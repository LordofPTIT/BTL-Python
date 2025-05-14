import logging
import os
import sys
import re
from urllib.parse import urlparse
from dotenv import load_dotenv
from sqlalchemy import create_engine, select, exists, func, inspect, delete
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import Column, Integer, String, DateTime, Text
import time
from datetime import datetime

load_dotenv()

EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
ALLOWED_ITEM_TYPES_IMPORT = {'domain', 'email'}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger("import_script")

BASE_DIR_IMPORT = os.path.abspath(os.path.dirname(__file__))
DEFAULT_DATABASE_FILE_IMPORT = 'local_phishing_guard.db'
DATABASE_URL_ENV_IMPORT = os.getenv('DATABASE_URL')

SQLALCHEMY_DATABASE_URI_IMPORT = DATABASE_URL_ENV_IMPORT if DATABASE_URL_ENV_IMPORT else f'sqlite:///{os.path.join(BASE_DIR_IMPORT, DEFAULT_DATABASE_FILE_IMPORT)}'
if SQLALCHEMY_DATABASE_URI_IMPORT.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URI_IMPORT = SQLALCHEMY_DATABASE_URI_IMPORT.replace("postgres://", "postgresql://", 1)

try:
    engine_import = create_engine(SQLALCHEMY_DATABASE_URI_IMPORT, pool_pre_ping=True, pool_recycle=300)
    SessionLocalImport = sessionmaker(autocommit=False, autoflush=False, bind=engine_import)
    logger.info(f"Import script DB engine created for {SQLALCHEMY_DATABASE_URI_IMPORT}.")
except Exception as e:
    logger.critical(f"Failed to create import script DB engine: {e}")
    sys.exit(1)

BaseImport = declarative_base()

class BlocklistImport(BaseImport):
    __tablename__ = 'blocklist'
    id = Column(Integer, primary_key=True)
    item_type = Column(String(10), nullable=False, index=True)
    value = Column(String(255), nullable=False, unique=True, index=True)
    reason = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)
    added_on = Column(DateTime, server_default=func.now())
    status = Column(String(50), default='active', nullable=False, index=True)

class WhitelistImport(BaseImport):
    __tablename__ = 'whitelist'
    id = Column(Integer, primary_key=True)
    item_type = Column(String(10), nullable=False, index=True)
    value = Column(String(255), nullable=False, unique=True, index=True)
    reason = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)
    added_on = Column(DateTime, server_default=func.now())

class DataVersionImport(BaseImport):
    __tablename__ = 'data_version'
    id = Column(Integer, primary_key=True)
    data_type = Column(String(50), unique=True, nullable=False)
    version = Column(String(100), nullable=False, default=lambda: str(time.time()))
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

BaseImport.metadata.create_all(bind=engine_import)
logger.info("Import script: Tables checked/created if they didn't exist.")

def normalize_domain_import(domain: str) -> str | None:
    if not domain or not isinstance(domain, str): return None
    try:
        domain = domain.strip().lower()
        if not domain: return None
        if re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) or ':' in domain: return None
        parsed = urlparse(domain if '://' in domain else 'http://' + domain)
        hostname = parsed.hostname
        if not hostname: return None
        hostname = hostname.strip('.')
        if hostname.startswith('www.'): hostname = hostname[4:]
        if not hostname: return None
        if not re.fullmatch(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$", hostname):
            return None
        return hostname
    except Exception:
        return None

def is_valid_email_import(email: str) -> bool:
    if not email or not isinstance(email, str): return False
    return re.fullmatch(EMAIL_REGEX, email) is not None

def update_data_version_import(session, data_type):
    try:
        version_entry = session.execute(select(DataVersionImport).filter_by(data_type=data_type)).scalar_one_or_none()
        new_version = str(time.time())
        if version_entry:
            version_entry.version = new_version
            version_entry.last_updated = datetime.utcnow()
        else:
            version_entry = DataVersionImport(data_type=data_type, version=new_version)
            session.add(version_entry)
        session.commit()
        logger.info(f"Updated data version for {data_type} to {new_version}")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Error updating data version for {data_type}: {e}")

def import_file_to_list(session, ModelClass, item_type, filepath):
    count = 0; added = 0; skipped_exists_db = 0; skipped_invalid = 0; skipped_dup_file = 0; errors = 0
    processed_values_in_file = set()
    filename = os.path.basename(filepath)
    logger.info(f"Starting import for {item_type} from {filename} into {ModelClass.__tablename__}")

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_content in f:
                count += 1
                value = line_content.strip()
                if not value or value.startswith('#') or value.startswith('!'): continue

                original_value_for_log = value
                normalized_value = None

                if item_type == 'domain':
                    if value.startswith('||'): value = value[2:]
                    value = value.split('$')[0].split('^')[0].split('#')[0].strip().rstrip('/')
                    if value.startswith('*.'): value = value[2:]
                    elif value.startswith('.'): value = value[1:]

                    normalized_value = normalize_domain_import(value)
                    if not normalized_value: skipped_invalid += 1; continue
                elif item_type == 'email':
                    normalized_value = value.lower()
                    if not is_valid_email_import(normalized_value): skipped_invalid += 1; continue
                else: logger.error(f"Unsupported item type '{item_type}'"); return 0, count, 0

                if normalized_value in processed_values_in_file: skipped_dup_file += 1; continue
                processed_values_in_file.add(normalized_value)

        unique_values_to_check = list(processed_values_in_file)
        if not unique_values_to_check: logger.info(f"No valid items from {filename}."); return 0, skipped_invalid + skipped_dup_file, 0

        items_to_insert_mappings = []
        existing_in_db = set()
        value_col = ModelClass.value

        chunk_size = 1000
        for i in range(0, len(unique_values_to_check), chunk_size):
            chunk = unique_values_to_check[i:i+chunk_size]
            try:
                results = session.execute(select(value_col).where(ModelClass.item_type == item_type).where(value_col.in_(chunk))).scalars().all()
                existing_in_db.update(results)
            except SQLAlchemyError as e: logger.error(f"DB error existence check chunk {i//chunk_size}: {e}"); errors += len(chunk); continue

        import_source_tag = f"import_{filename}"
        for norm_val in unique_values_to_check:
             if norm_val in existing_in_db: skipped_exists_db += 1; continue
             item_map = {'item_type': item_type, 'value': norm_val, 'source': import_source_tag}
             if hasattr(ModelClass, 'status'): item_map['status'] = 'active'
             items_to_insert_mappings.append(item_map)

        if items_to_insert_mappings:
            try:
                 session.bulk_insert_mappings(ModelClass, items_to_insert_mappings)
                 session.commit(); added = len(items_to_insert_mappings)
                 # Cập nhật version sau khi import thành công
                 update_data_version_import(session, f"blocklist_{item_type}s")
            except IntegrityError:
                 session.rollback(); logger.warning(f"Integrity error bulk insert {filename}, trying individual."); added_ind = 0
                 for item_map_ind in items_to_insert_mappings:
                     try:
                         if not session.execute(select(exists().where(ModelClass.item_type == item_map_ind['item_type']).where(value_col == item_map_ind['value']))).scalar():
                             session.add(ModelClass(**item_map_ind)); session.commit(); added_ind +=1
                         else: skipped_exists_db += 1
                     except IntegrityError: session.rollback(); skipped_exists_db +=1
                     except SQLAlchemyError as e_ind: session.rollback(); logger.error(f"Indiv insert error {item_map_ind['value']}: {e_ind}"); errors += 1
                 added = added_ind
                 if added > 0:
                     # Cập nhật version sau khi import thành công
                     update_data_version_import(session, f"blocklist_{item_type}s")
            except SQLAlchemyError as e_bulk: session.rollback(); logger.error(f"Bulk insert error {filename}: {e_bulk}"); errors += len(items_to_insert_mappings); added = 0
        else: logger.info(f"No new items from {filename} to add.")

    except FileNotFoundError: logger.error(f"File not found: {filepath}"); errors = count or 1
    except Exception as e_file: logger.error(f"Unexpected error processing {filepath}: {e_file}", exc_info=True); errors = count or 1; added=0; skipped_exists_db=0; skipped_invalid=0; skipped_dup_file=0;
    finally:
        if session.is_active:
            session.rollback()

    total_skipped = skipped_exists_db + skipped_invalid + skipped_dup_file
    logger.info(f"Imported {filename}: Added={added}, Skipped={total_skipped} (DB:{skipped_exists_db}, Invalid:{skipped_invalid}, FileDup:{skipped_dup_file}), Errors={errors}, Lines={count}")
    return added, total_skipped, errors

def remove_duplicates_from_table(session, ModelClass, item_type_filter):
    logger.info(f"Deduplicating {item_type_filter} in {ModelClass.__tablename__}...")
    value_col = ModelClass.value; pk_col = ModelClass.id
    ids_to_keep_query = select(func.min(pk_col)).where(ModelClass.item_type == item_type_filter).group_by(value_col)
    ids_to_keep = session.execute(ids_to_keep_query).scalars().all()
    if not ids_to_keep: logger.info(f"No groups found for {item_type_filter}, deduplication not needed."); return 0

    stmt_delete = delete(ModelClass).where(ModelClass.item_type == item_type_filter).where(pk_col.not_in(ids_to_keep))
    try:
        result = session.execute(stmt_delete); session.commit(); deleted_count = result.rowcount
        logger.info(f"Deduplication {item_type_filter}: Deleted {deleted_count} rows.")
        return deleted_count
    except SQLAlchemyError as e: session.rollback(); logger.error(f"Deduplication error {item_type_filter}: {e}"); return -1

if __name__ == "__main__":
    db_session_import = SessionLocalImport()
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    files_to_process = [
        {"path": os.path.join(current_script_dir, "urls.txt"), "type": "domain"},
        {"path": os.path.join(current_script_dir, "urls-ABP.txt"), "type": "domain"},
        {"path": os.path.join(current_script_dir, "CLDBllacklist.txt"), "type": "domain"}
    ]
    overall_added, overall_skipped, overall_errors = 0, 0, 0

    try:
        logger.info("--- Starting List Import ---")
        for file_info in files_to_process:
            file_p = file_info["path"]
            item_t = file_info["type"]
            TargetModel = BlocklistImport
            if not os.path.exists(file_p): logger.error(f"File not found: {file_p}. Skipping."); overall_errors += 1; continue
            added_f, skipped_f, errors_f = import_file_to_list(db_session_import, TargetModel, item_t, file_p)
            overall_added += added_f; overall_skipped += skipped_f; overall_errors += errors_f

        logger.info(f"Overall Import Summary: Added={overall_added}, Skipped={overall_skipped}, Errors={overall_errors}")

        logger.info("--- Starting Database Deduplication ---")
        remove_duplicates_from_table(db_session_import, BlocklistImport, "domain")
        remove_duplicates_from_table(db_session_import, BlocklistImport, "email")
        remove_duplicates_from_table(db_session_import, WhitelistImport, "domain")
        remove_duplicates_from_table(db_session_import, WhitelistImport, "email")

        # Cập nhật version cho tất cả các loại dữ liệu sau khi hoàn thành
        for item_type in ['domain', 'email']:
            update_data_version_import(db_session_import, f"blocklist_{item_type}s")
            update_data_version_import(db_session_import, f"whitelist_{item_type}s")

    except Exception as main_e: logger.critical(f"Critical error in main import: {main_e}", exc_info=True)
    finally: db_session_import.close(); logger.info("Import script DB session closed.")