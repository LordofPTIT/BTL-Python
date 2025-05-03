import os
import sys
import logging
import time
from typing import Set, Generator
from dotenv import load_dotenv
from sqlalchemy import create_engine, select, exists
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError


try:
    from app import db, BlockedDomain, normalize_domain, app as flask_app
except ImportError as e:
    print(f"Lỗi import từ app.py: {e}")
    print("Hãy đảm bảo script này được chạy từ thư mục chứa app.py hoặc cấu hình PYTHONPATH.")
    sys.exit(1)

# --- Cấu hình Logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


URLS_TXT_PATH = 'urls.txt'
URLS_ABP_PATH = 'urls-ABP.txt'

# --- Hàm xử lý file ---

def process_urls_txt(filepath: str) -> Generator[str, None, None]:
    """Đọc file urls.txt và trả về các domain đã chuẩn hóa."""
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    normalized = normalize_domain(domain)
                    if normalized:
                        yield normalized
                        count += 1
    except FileNotFoundError:
        logger.warning(f"File không tìm thấy: {filepath}")
    except Exception as e:
        logger.error(f"Lỗi khi đọc file {filepath}: {e}")
    logger.info(f"Đã xử lý {count} domain hợp lệ từ {filepath}")

def process_urls_abp(filepath: str) -> Generator[str, None, None]:
    """Đọc file urls-ABP.txt, trích xuất và chuẩn hóa domain."""
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                if line.startswith('||') and line.endswith('^'):

                    domain_part = line[2:-1]

                    domain_part = domain_part.split('$')[0]

                    domain_part = domain_part.split(':')[0]

                    if '/' in domain_part or '*' in domain_part:
                        continue
                    normalized = normalize_domain(domain_part)
                    if normalized:
                        yield normalized
                        count += 1
    except FileNotFoundError:
        logger.warning(f"File không tìm thấy: {filepath}")
    except Exception as e:
        logger.error(f"Lỗi khi đọc file {filepath}: {e}")
    logger.info(f"Đã xử lý {count} domain hợp lệ từ {filepath}")


def import_domains_to_db(domains: Set[str], source_tag: str):
    """Import danh sách các domain vào database, tránh trùng lặp."""
    inserted_count = 0
    skipped_count = 0
    error_count = 0
    batch_size = 1000  # Commit sau mỗi batch_size bản ghi
    domains_to_insert = []


    with flask_app.app_context():
        logger.info(f"Bắt đầu import {len(domains)} domain từ nguồn '{source_tag}'...")
        start_time = time.time()

        processed_count = 0
        for domain in domains:
            processed_count += 1
            if processed_count % 10000 == 0: # Log tiến trình
                 logger.info(f"Đã xử lý {processed_count}/{len(domains)} domain...")

            try:
                # Kiểm tra xem domain đã tồn tại chưa (cách check từng cái)
                exists_stmt = select(exists().where(BlockedDomain.domain_name == domain))
                domain_exists = db.session.execute(exists_stmt).scalar()

                # Hoặc kiểm tra với set đã lấy trước đó (nhanh hơn nếu set không quá lớn)
                # domain_exists = domain in existing_domains

                if not domain_exists:
                    # logger.debug(f"Chuẩn bị thêm domain: {domain}")
                    new_domain = BlockedDomain(
                        domain_name=domain,
                        source=source_tag, # Gán nguồn import
                        status='active',   # Mặc định là active
                        reason='Bulk imported' # Lý do chung
                    )
                    domains_to_insert.append(new_domain)
                    # existing_domains.add(domain) # Thêm vào set check nếu dùng cách check bằng set

                    if len(domains_to_insert) >= batch_size:
                        logger.info(f"Đang commit batch {batch_size} domain...")
                        db.session.add_all(domains_to_insert)
                        db.session.commit()
                        inserted_count += len(domains_to_insert)
                        domains_to_insert = [] # Reset batch
                else:
                    # logger.debug(f"Bỏ qua domain đã tồn tại: {domain}")
                    skipped_count += 1

            except SQLAlchemyError as e:
                logger.error(f"Lỗi DB khi xử lý domain '{domain}': {e}")
                db.session.rollback() # Quan trọng: rollback khi có lỗi
                error_count += 1
            except Exception as e:
                 logger.error(f"Lỗi không mong muốn khi xử lý domain '{domain}': {e}")
                 db.session.rollback()
                 error_count += 1

        # Commit các bản ghi còn lại trong batch cuối cùng
        if domains_to_insert:
            try:
                logger.info(f"Đang commit batch cuối cùng ({len(domains_to_insert)} domain)...")
                db.session.add_all(domains_to_insert)
                db.session.commit()
                inserted_count += len(domains_to_insert)
            except SQLAlchemyError as e:
                logger.error(f"Lỗi DB khi commit batch cuối: {e}")
                db.session.rollback()
                error_count += len(domains_to_insert) # Coi như lỗi nếu không commit được
            except Exception as e:
                 logger.error(f"Lỗi không mong muốn khi commit batch cuối: {e}")
                 db.session.rollback()
                 error_count += len(domains_to_insert)


        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Hoàn thành import cho nguồn '{source_tag}' trong {duration:.2f} giây.")
        logger.info(f"Kết quả: Đã thêm = {inserted_count}, Bỏ qua (trùng) = {skipped_count}, Lỗi = {error_count}")

# --- Hàm chính ---
def main():
    """Hàm chính điều phối việc đọc file và import vào DB."""
    logger.info("Bắt đầu script import domain...")

    # --- Đọc và xử lý các file ---
    all_domains: Set[str] = set() # Dùng set để tự loại bỏ trùng lặp từ các file

    logger.info(f"Đang xử lý file: {URLS_TXT_PATH}")
    for domain in process_urls_txt(URLS_TXT_PATH):
        all_domains.add(domain)

    logger.info(f"Đang xử lý file: {URLS_ABP_PATH}")
    for domain in process_urls_abp(URLS_ABP_PATH):
        all_domains.add(domain)

    logger.info(f"Tổng cộng tìm thấy {len(all_domains)} domain duy nhất cần import.")

    if not all_domains:
        logger.info("Không tìm thấy domain nào để import. Kết thúc.")
        return

    # --- Import vào database ---
    # Có thể gọi import_domains_to_db riêng cho từng file nếu muốn tag nguồn khác nhau
    # Hoặc gộp chung như hiện tại với một tag nguồn chung
    import_domains_to_db(all_domains, source_tag='BulkImportScript')

    logger.info("Script import domain đã hoàn tất.")


if __name__ == "__main__":
    # Đảm bảo biến môi trường DATABASE_URL đã được thiết lập (trong .env hoặc hệ thống)
    if not os.getenv('DATABASE_URL'):
         logger.critical("Lỗi: Biến môi trường DATABASE_URL chưa được thiết lập.")
         logger.critical("Hãy tạo file .env hoặc thiết lập biến môi trường hệ thống.")
         sys.exit(1)
    main()