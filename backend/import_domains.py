# backend/import_domains.py
import logging
import os
import sys
import re
# import argparse # Removed argparse
from urllib.parse import urlparse
from typing import Optional, List, Tuple, Type, Set

from dotenv import load_dotenv
from sqlalchemy import create_engine, select, func, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint
from sqlalchemy.sql.expression import literal_column
from datetime import datetime, timezone # Import datetime for timestamps

# --- Constants ---
# Removed EMAIL_REGEX as it's not used in the import logic
# Default chunk size for batch processing DB operations
DEFAULT_CHUNK_SIZE = 500 # Keep batch processing for efficiency

# --- File Paths (Cập nhật để đọc từ các tệp cố định) ---
# Các tệp .txt nằm trong cùng thư mục backend
URLS_FILE = "urls.txt"
URLS_ABP_FILE = "urls-ABP.txt"
CLDB_BLACKLIST_FILE = "CLDBllacklist.txt"
# Danh sách các tệp cần xử lý
FILES_TO_PROCESS = [URLS_FILE, URLS_ABP_FILE, CLDB_BLACKLIST_FILE]


# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout) # Ensure logs go to stdout
    ]
)
logger = logging.getLogger("import_script")

# --- Load Environment & DB Setup ---
# Determine the correct path to the .env file relative to this script
# Assumes .env is in the same directory as this script (backend/)
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    logger.info(f".env file loaded from {dotenv_path}")
else:
    logger.warning(f".env file not found at {dotenv_path}. Using system environment variables.")


# Lấy DATABASE_URL từ biến môi trường
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.critical("DATABASE_URL environment variable not set.")
    sys.exit(1)

# Tạo SQLAlchemy Engine
try:
    engine = create_engine(DATABASE_URL)
    # Test connection
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    logger.info("Database connection successful.")
except Exception as e:
    logger.critical(f"Failed to connect to database using DATABASE_URL: {e}")
    sys.exit(1)

# Tạo Session Local Class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Tạo Base cho các mô hình ORM
Base = declarative_base()

# --- Database Model (Cập nhật nếu tên bảng/cột của bạn khác) ---
# Giả định tên bảng là 'phishing_domains' và có cột 'domain'
# Thêm UniqueConstraint để đảm bảo tính duy nhất của domain
class PhishingDomain(Base):
    __tablename__ = 'phishing_domains' # Thay đổi nếu tên bảng của bạn khác

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    # Thêm các cột khác nếu có, ví dụ:
    added_at = Column(DateTime, default=datetime.now(timezone.utc))
    source = Column(String(50))

    # Thêm UniqueConstraint nếu cột 'domain' không đủ ràng buộc duy nhất
    __table_args__ = (UniqueConstraint('domain', name='_domain_uc'),)

    def __repr__(self):
        return f"<PhishingDomain(domain='{self.domain}')>"

# --- Hàm làm sạch domain (Cập nhật logic xử lý định dạng tệp) ---
def clean_domain(line: str) -> Optional[str]:
    """Làm sạch dòng để trích xuất domain từ các định dạng khác nhau."""
    line = line.strip() # Xóa khoảng trắng ở đầu và cuối

    # Xử lý dòng trống, dòng comment (bắt đầu bằng !), hoặc các quy tắc Adblock Plus phức tạp khác
    if not line or line.startswith('!') or '#' in line or '$' not in line and any(char in line for char in ['~', '|', '@', '*']):
         # Bỏ qua các dòng không phải là quy tắc cơ bản hoặc có vẻ là quy tắc phức tạp
        return None

    # Xử lý các định dạng phổ biến: ||domain.com^, ||domain.com$all, domain.com
    # Loại bỏ tiền tố '||'
    if line.startswith('||'):
        line = line[2:]

    # Loại bỏ hậu tố '^'
    if line.endswith('^'):
        line = line[:-1]

    # Loại bỏ hậu tố '$all' và các hậu tố $ khác (như $domain=...)
    if '$' in line:
        # Tìm vị trí của ký tự '$' đầu tiên và lấy phần trước đó
        line = line.split('$', 1)[0]

    # Xử lý trường hợp còn lại có thể là URL hoặc domain đơn giản
    # Cố gắng phân tích cú pháp như một URL để lấy hostname
    try:
        # Prefix with a scheme to help urlparse if missing (optional, but can help)
        if '://' not in line:
             # Add a dummy scheme if it looks like a domain/path
             if '/' in line or '.' in line:
                  line = 'http://' + line

        parsed = urlparse(line)
        # Lấy hostname, loại bỏ www. và chuyển thành chữ thường
        domain = parsed.hostname
        if domain:
            domain = domain.lower()
            if domain.startswith('www.'):
                 domain = domain[4:]
            return domain
        # Nếu không có hostname, có thể là domain đơn giản không có scheme/path
        # Hoặc một định dạng không chuẩn. Trả về None nếu không chắc chắn.
        # Hoặc bạn có thể thêm logic kiểm tra định dạng domain cơ bản ở đây.
        return line.lower() if '.' in line and '/' not in line else None # Kiểm tra cơ bản có dấu chấm và không có /

    except Exception as e:
        logger.warning(f"Could not parse domain from line '{line}': {e}")
        return None

# --- Hàm đọc và xử lý domain từ tệp ---
def process_domain_files(session: Session) -> int:
    """Đọc domain từ các tệp, làm sạch, kiểm tra trùng lặp và nhập vào DB."""
    all_domains_from_files: Set[str] = set()
    processed_lines_count = 0
    imported_count = 0

    logger.info("Bắt đầu đọc domain từ các tệp...")

    for filepath in FILES_TO_PROCESS:
        full_filepath = os.path.join(os.path.dirname(__file__), filepath)
        if not os.path.exists(full_filepath):
            logger.warning(f"Tệp không tồn tại: {full_filepath}. Bỏ qua.")
            continue

        logger.info(f"Đọc tệp: {full_filepath}")
        try:
            # Sử dụng 'r' và 'utf-8' encoding, xử lý lỗi bằng 'ignore' hoặc 'replace' nếu cần
            with open(full_filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    processed_lines_count += 1
                    cleaned_domain = clean_domain(line)
                    if cleaned_domain:
                        all_domains_from_files.add(cleaned_domain)

            logger.info(f"Đã xử lý {processed_lines_count} dòng từ tệp {filepath}.")
            processed_lines_count = 0 # Reset counter for next file

        except Exception as e:
            logger.error(f"Lỗi khi đọc hoặc xử lý tệp {full_filepath}: {e}")
            # Tiếp tục xử lý các tệp khác thay vì dừng lại

    logger.info(f"Tổng số domain duy nhất đọc được từ tất cả các tệp: {len(all_domains_from_files)}")

    if not all_domains_from_files:
        logger.info("Không tìm thấy domain hợp lệ nào để nhập.")
        return 0

    logger.info("Kiểm tra domain hiện có trong cơ sở dữ liệu...")
    existing_domains: Set[str] = set()
    try:
        # Đọc tất cả domain hiện có trong DB để kiểm tra trùng lặp hiệu quả
        # Sử dụng SELECT DISTINCT để tránh đọc trùng lặp từ DB nếu có
        stmt = select(PhishingDomain.domain)
        result = session.execute(stmt)
        existing_domains = set([row[0] for row in result])
        logger.info(f"Đã lấy {len(existing_domains)} domain hiện có từ cơ sở dữ liệu.")

    except SQLAlchemyError as e:
        logger.error(f"Lỗi khi lấy domain hiện có từ cơ sở dữ liệu: {e}")
        session.rollback() # Rollback nếu có lỗi
        return 0 # Dừng quá trình nhập

    # Xác định các domain mới cần thêm (không có trong DB)
    new_domains_to_import: List[PhishingDomain] = []
    for domain in all_domains_from_files:
        if domain not in existing_domains:
            new_domains_to_import.append(PhishingDomain(domain=domain))

    logger.info(f"Tìm thấy {len(new_domains_to_import)} domain mới cần nhập.")

    if not new_domains_to_import:
        logger.info("Không có domain mới nào cần nhập vào cơ sở dữ liệu.")
        return 0

    # Nhập các domain mới theo đợt
    logger.info(f"Bắt đầu nhập {len(new_domains_to_import)} domain mới vào cơ sở dữ liệu (batch size: {DEFAULT_CHUNK_SIZE}).")
    try:
        for i in range(0, len(new_domains_to_import), DEFAULT_CHUNK_SIZE):
            batch = new_domains_to_import[i:i + DEFAULT_CHUNK_SIZE]
            session.add_all(batch)
            session.commit() # Commit sau mỗi đợt
            imported_count += len(batch)
            logger.info(f"Đã nhập {imported_count}/{len(new_domains_to_import)} domain.")

        logger.info("Quá trình nhập hoàn tất.")
        return imported_count

    except IntegrityError as e:
        # Xử lý cụ thể lỗi vi phạm ràng buộc UNIQUE (domain trùng lặp)
        logger.warning(f"Lỗi vi phạm ràng buộc duy nhất khi nhập: {e}. Có thể có domain trùng lặp được thêm vào từ các luồng khác sau khi kiểm tra.")
        session.rollback() # Rollback đợt hiện tại nếu có lỗi
        # Lưu ý: Với cách kiểm tra trùng lặp bằng cách đọc toàn bộ DB trước, lỗi IntegrityError
        # ở đây ít khả năng xảy ra trừ khi có các tiến trình khác cũng đang ghi vào bảng này.
        # Nếu xảy ra, bạn có thể cần chiến lược xử lý trùng lặp phức tạp hơn (ví dụ: ON DUPLICATE KEY UPDATE).
        # Hiện tại, chúng ta chỉ rollback và thông báo.
        return imported_count # Trả về số lượng đã nhập thành công trước khi lỗi

    except SQLAlchemyError as e:
        logger.error(f"Lỗi cơ sở dữ liệu khi nhập domain: {e}")
        session.rollback() # Rollback nếu có lỗi
        return imported_count # Trả về số lượng đã nhập thành công trước khi lỗi

    except Exception as e:
        logger.critical(f"Lỗi không mong muốn trong quá trình nhập: {e}", exc_info=True)
        session.rollback()
        return imported_count # Trả về số lượng đã nhập thành công trước khi lỗi


# --- Hàm chính (Thực thi trực tiếp) ---
def main():
    """Điểm vào chính của script, thực hiện việc đọc tệp và nhập DB."""
    logger.info("Bắt đầu script nhập domain.")
    db_session: Optional[Session] = None
    exit_code = 0 # 0 for success, 1 for failure

    try:
        # Tạo một session cho lần chạy này
        db_session = SessionLocal()

        # Đảm bảo bảng tồn tại (có thể bỏ qua nếu bạn chắc chắn bảng đã có)
        Base.metadata.create_all(engine, tables=[PhishingDomain.__table__])
        logger.info(f"Đã kiểm tra/tạo bảng '{PhishingDomain.__tablename__}'.")


        # Thực hiện quá trình xử lý và nhập
        imported_count = process_domain_files(db_session)

        logger.info(f"Tổng số domain mới được nhập thành công: {imported_count}.")

    except Exception as e:
        logger.critical(f"Lỗi nghiêm trọng xảy ra trong quá trình chính: {e}", exc_info=True)
        exit_code = 1
        # Rollback transaction nếu session tồn tại và đang hoạt động
        if db_session and db_session.is_active:
            try:
                db_session.rollback()
                logger.warning("Đã rollback transaction do lỗi nghiêm trọng.")
            except Exception as rb_err:
                 logger.error(f"Lỗi khi rollback sau lỗi nghiêm trọng: {rb_err}")

    finally:
        # Đảm bảo session được đóng
        if db_session:
            try:
                db_session.close()
                logger.info("Database session đã đóng.")
            except Exception as close_err:
                logger.error(f"Lỗi khi đóng database session: {close_err}")
                if exit_code == 0: exit_code = 1 # Đảm bảo báo cáo lỗi nếu đóng session thất bại

    logger.info(f"Script kết thúc với mã thoát {exit_code}.")
    sys.exit(exit_code) # Thoát script với mã tương ứng

# --- Điểm bắt đầu thực thi của tập lệnh ---
if __name__ == "__main__":
    main()