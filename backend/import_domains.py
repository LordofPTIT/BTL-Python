import os
import sys
import logging
import time
from typing import Set, Generator
from dotenv import load_dotenv
from sqlalchemy import select, exists
from sqlalchemy.exc import SQLAlchemyError


try:
    from app import db, BlockedDomain, normalize_domain, app as flask_app, initialize_database
except ImportError as e:
    print(f"Lỗi import từ app.py: {e}")
    sys.exit(1)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)


URLS_TXT_PATH = 'urls.txt'
URLS_ABP_PATH = 'urls-ABP.txt'
CLDBLACKLIST_PATH = 'CLDBllacklist.txt'

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
                    domain_part = line[2:-1].split('$')[0]
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

def process_cld_blacklist(filepath: str) -> Generator[str, None, None]:
    """Đọc file CLDBllacklist.txt và trích xuất các domain từ các dòng chứa '||domain.com$all'."""
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Chỉ lấy các dòng bắt đầu với || và chứa $all
                if line.startswith('||') and '$all' in line:
                    domain_part = line[2:].split('$')[0]
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
    """Import danh sách domain vào database, tránh trùng lặp."""
    inserted_count = 0
    skipped_count = 0
    error_count = 0
    batch_size = 1000
    domains_to_insert = []

    with flask_app.app_context():
        logger.info(f"Bắt đầu import {len(domains)} domain từ nguồn '{source_tag}'...")
        start_time = time.time()
        processed_count = 0

        for domain in domains:
            processed_count += 1
            if processed_count % 10000 == 0:
                logger.info(f"Đã xử lý {processed_count}/{len(domains)} domain...")

            try:
                exists_stmt = select(exists().where(BlockedDomain.domain_name == domain))
                domain_exists = db.session.execute(exists_stmt).scalar()

                if not domain_exists:
                    new_domain = BlockedDomain(
                        domain_name=domain,
                        source=source_tag,
                        status='active',
                        reason='Bulk imported'
                    )
                    domains_to_insert.append(new_domain)
                    if len(domains_to_insert) >= batch_size:
                        logger.info(f"Đang commit batch {batch_size} domain...")
                        db.session.add_all(domains_to_insert)
                        db.session.commit()
                        inserted_count += len(domains_to_insert)
                        domains_to_insert = []
                else:
                    skipped_count += 1

            except SQLAlchemyError as e:
                logger.error(f"Lỗi DB khi xử lý domain '{domain}': {e}")
                db.session.rollback()
                error_count += 1
            except Exception as e:
                logger.error(f"Lỗi không mong muốn khi xử lý domain '{domain}': {e}")
                db.session.rollback()
                error_count += 1

        # Commit batch cuối cùng (nếu có)
        if domains_to_insert:
            try:
                logger.info(f"Đang commit batch cuối cùng ({len(domains_to_insert)} domain)...")
                db.session.add_all(domains_to_insert)
                db.session.commit()
                inserted_count += len(domains_to_insert)
            except SQLAlchemyError as e:
                logger.error(f"Lỗi DB khi commit batch cuối: {e}")
                db.session.rollback()
                error_count += len(domains_to_insert)
            except Exception as e:
                logger.error(f"Lỗi không mong muốn khi commit batch cuối: {e}")
                db.session.rollback()
                error_count += len(domains_to_insert)

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Hoàn thành import trong {duration:.2f} giây.")
        logger.info(f"Kết quả: Đã thêm = {inserted_count}, Bỏ qua = {skipped_count}, Lỗi = {error_count}")

def main():
    logger.info("Bắt đầu script import domain...")

    logger.info("Đang kiểm tra và khởi tạo cấu trúc database (nếu cần)...")
    with flask_app.app_context():
        initialize_database()
    logger.info("Kiểm tra/khởi tạo database hoàn tất.")

    # Đọc và xử lý các file
    all_domains: Set[str] = set()

    logger.info(f"Đang xử lý file: {URLS_TXT_PATH}")
    for domain in process_urls_txt(URLS_TXT_PATH):
        all_domains.add(domain)

    logger.info(f"Đang xử lý file: {URLS_ABP_PATH}")
    for domain in process_urls_abp(URLS_ABP_PATH):
        all_domains.add(domain)

    logger.info(f"Đang xử lý file: {CLDBLACKLIST_PATH}")
    for domain in process_cld_blacklist(CLDBLACKLIST_PATH):
        all_domains.add(domain)

    logger.info(f"Tổng cộng tìm thấy {len(all_domains)} domain duy nhất cần import.")

    if not all_domains:
        logger.info("Không tìm thấy domain nào để import. Kết thúc.")
        return

    # Import vào database
    import_domains_to_db(all_domains, source_tag='BulkImportScript')
    logger.info("Script import domain đã hoàn tất.")

if __name__ == "__main__":
    if not os.getenv('DATABASE_URL'):
        logger.critical("Lỗi: Biến môi trường DATABASE_URL chưa được thiết lập.")
        sys.exit(1)
    main()
