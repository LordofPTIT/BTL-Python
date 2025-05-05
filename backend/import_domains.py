# backend/import_domains.py
import logging
import os
import sys
import re
from urllib.parse import urlparse
from dotenv import load_dotenv
from sqlalchemy import create_engine, select, exists, func, inspect
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint

# --- Constants ---
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger("import_script")

# --- Load Environment & DB Setup ---
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    logger.info("Loaded environment variables from .env file.")
else:
    logger.warning(".env file not found, relying on system environment variables.")

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    logger.critical("CRITICAL: Biến môi trường DATABASE_URL chưa được thiết lập.")
    sys.exit(1)

# Adjust for Render/Heroku convention
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    logger.info("Updated DATABASE_URL prefix to postgresql://")

# Create engine and session *independent* of Flask app context
try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("Database engine created for MySQL.")
except Exception as e:
    logger.critical(f"Failed to create database engine: {e}")
    sys.exit(1)

# --- Define Models (match app.py structure) ---
# Using a base here allows the script to define models independently if needed,
# but ideally, import them from a shared models file used by app.py too.
Base = declarative_base()

class BlockedDomain(Base):
    __tablename__ = 'blocked_domains'
    id = Column(Integer, primary_key=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = Column(String(50), default='active', nullable=False, index=True)

class BlockedEmail(Base):
    __tablename__ = 'blocked_emails'
    id = Column(Integer, primary_key=True)
    email_address = Column(String(255), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = Column(String(50), default='active', nullable=False, index=True)

# You might need other models like WhitelistedItem if the script interacts with them

# --- Helper Functions (Copied/adapted from app.py) ---
def normalize_domain(domain: str) -> str | None:
    if not domain or not isinstance(domain, str): return None
    try:
        domain = domain.strip().lower()
        if not domain: return None
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) or ':' in domain: return None
        if '://' not in domain: domain = 'http://' + domain
        parsed = urlparse(domain)
        hostname = parsed.hostname
        if not hostname: return None
        hostname = hostname.strip('.')
        if hostname.startswith('www.'): hostname = hostname[4:]
        if not hostname: return None
        if re.search(r"[^a-z0-9\-\.]", hostname): return None  # Basic check for valid chars
        return hostname
    except Exception as e:
        logger.error(f"Error normalizing domain '{domain}': {e}")
        return None

def is_valid_email(email: str) -> bool:
    return re.match(EMAIL_REGEX, email) is not None

# --- Import List Function ---
def import_list(session, ModelClass, item_type, filename):
    """Imports items from a file, handling duplicates and normalization."""
    count = 0
    added = 0
    skipped_exists_db = 0
    skipped_invalid = 0
    skipped_dup_file = 0
    errors = 0

    processed_values_in_file = set()  # Use a set for file deduplication

    logger.info(f"Starting import for {item_type} from {filename}")

    try:
        # --- Step 1: Read file and collect unique, normalized values ---
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                count += 1
                original_value_for_log = line.strip()
                value = line.strip()
                if not value or value.startswith('#') or value.startswith('!'):  # Skip empty/comment lines
                    continue

                # Normalize based on type
                if item_type == 'domain':
                    normalized_value = normalize_domain(value)
                    if not normalized_value:
                        logger.debug(f"Line {count}: Skipping invalid domain format: '{original_value_for_log}'")
                        skipped_invalid += 1
                        continue
                elif item_type == 'email':
                    normalized_value = value.lower()  # Normalize email to lowercase
                    if not is_valid_email(normalized_value):
                        logger.debug(f"Line {count}: Skipping invalid email format: '{original_value_for_log}'")
                        skipped_invalid += 1
                        continue
                else:
                    logger.error("Invalid item_type specified for import.")
                    return 0, count, 0  # added, skipped, errors

                # Check duplicates in file
                if normalized_value in processed_values_in_file:
                    skipped_dup_file += 1
                    continue

                processed_values_in_file.add(normalized_value)

                # --- Step 2: Check existence in DB ---
                existing = session.query(ModelClass).filter(
                    (ModelClass.domain_name == normalized_value) if item_type == 'domain' else (ModelClass.email_address == normalized_value)
                ).first()
                if existing:
                    skipped_exists_db += 1
                    continue

                # Prepare for bulk insert
                processed_values_in_file  # ensure normalization
                # We'll bulk insert this mapping
        # --- Step 3: Bulk Insert (using session.bulk_insert_mappings) ---
        unique_values_to_check = list(processed_values_in_file)
        import_source_tag = f"import_{os.path.basename(filename)}"
        items_to_insert_mappings = []
        if unique_values_to_check:
            for norm_val in unique_values_to_check:
                item_data = {'source': import_source_tag, 'status': 'active'}
                if item_type == 'domain':
                    item_data['domain_name'] = norm_val
                else:  # email
                    item_data['email_address'] = norm_val
                items_to_insert_mappings.append(item_data)

            try:
                session.bulk_insert_mappings(ModelClass, items_to_insert_mappings)
                session.commit()
                added = len(items_to_insert_mappings)
                logger.info(f"Successfully added {added} new items.")
            except IntegrityError as e:
                logger.warning(f"Database Integrity Error during bulk insert: {e}. Rolling back.")
                session.rollback()
                errors += len(items_to_insert_mappings)
                added = 0
            except SQLAlchemyError as e:
                logger.error(f"Database error during bulk insert: {e}")
                session.rollback()
                errors += len(items_to_insert_mappings)
                added = 0
        else:
            logger.info("No new items to add to the database.")

    except FileNotFoundError:
        logger.error(f"Error: File not found at {filename}")
        errors = count if count > 0 else 1
    except Exception as e:
        logger.error(f"An unexpected error occurred during import of {filename}: {e}", exc_info=True)
        try:
            session.rollback()
        except Exception as rb_e:
            logger.error(f"Error during rollback attempt: {rb_e}")
        errors = count
        added = 0
        skipped_exists_db = 0
        skipped_invalid = 0
        skipped_dup_file = 0

    total_skipped = skipped_exists_db + skipped_invalid + skipped_dup_file
    logger.info(f"Import complete for {filename}:")
    logger.info(f"  Lines Processed: {count}")
    logger.info(f"  Items Added: {added}")
    logger.info(f"  Skipped (Total): {total_skipped}")
    logger.info(f"    - Existed in DB: {skipped_exists_db}")
    logger.info(f"    - Invalid/Duplicate in File: {skipped_invalid + skipped_dup_file}")
    logger.info(f"  Errors: {errors}")

    return added, total_skipped, errors

# --- Database Deduplication Function ---
def remove_database_duplicates(session, ModelClass, item_type):
    """Finds and removes duplicate entries in the specified table."""
    logger.info(f"Starting database deduplication for {item_type} in table {ModelClass.__tablename__}...")
    value_column_name = 'domain_name' if item_type == 'domain' else 'email_address'
    value_column = getattr(ModelClass, value_column_name)
    pk_column = inspect(ModelClass).primary_key[0]  # Get primary key column (usually 'id')
    logger.info(f"Identifying duplicates based on column '{value_column_name}', keeping lowest '{pk_column.name}'.")

    try:
        # Find all values that are duplicated
        duplicate_values_query = (
            select(value_column)
            .group_by(value_column)
            .having(func.count(pk_column) > 1)
        )
        duplicate_values = session.execute(duplicate_values_query).scalars().all()

        if not duplicate_values:
            logger.info("No duplicate values found in the database.")
            return 0  # Return 0 deleted

        logger.info(f"Found {len(duplicate_values)} values with duplicates. Processing deletion.")
        total_deleted = 0

        # Process duplicates in chunks to avoid locking/memory issues
        chunk_size = 100
        for i in range(0, len(duplicate_values), chunk_size):
            chunk_values = duplicate_values[i:i+chunk_size]
            logger.debug(f"Processing duplicate values chunk {i//chunk_size + 1}.")

            # Subquery to find the minimum primary key (ID) for each duplicate value
            subquery = (
                select(func.min(pk_column))
                .where(value_column.in_(chunk_values))
                .group_by(value_column)
                .scalar_subquery()
            )

            # Delete rows where the value is in the duplicate chunk AND the primary key is NOT the minimum one
            delete_statement = (
                ModelClass.__table__.delete()
                .where(value_column.in_(chunk_values))
                .where(pk_column.not_in(subquery))
            )

            result = session.execute(delete_statement)
            deleted_count = result.rowcount
            total_deleted += deleted_count
            logger.debug(f"Deleted {deleted_count} rows in this chunk.")

            # Commit periodically
            try:
                session.commit()
                logger.debug("Committed deletions for chunk.")
            except SQLAlchemyError as e:
                logger.error(f"Error committing deletions for chunk: {e}. Rolling back chunk.")
                session.rollback()
                logger.critical("Aborting deduplication due to commit error.")
                return -1  # Indicate error

        logger.info(f"Database deduplication complete. Total rows deleted: {total_deleted}")
        return total_deleted
    except SQLAlchemyError as e:
        logger.error(f"Database error during deduplication query/execution: {e}")
        session.rollback()
        return -1

# --- Main Execution Logic ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_domains.py <domain|email> <file1> [file2 ...]")
        print("       python import_domains.py --deduplicate <domain|email>")
        sys.exit(1)
    command = sys.argv[1]
    db_session = SessionLocal()  # Create a session
    try:
        if command == '--deduplicate':
            if len(sys.argv) != 3:
                print("Usage for deduplication: python import_domains.py --deduplicate <domain|email>")
                sys.exit(1)
            item_type = sys.argv[2].lower()
            if item_type == 'domain':
                Model = BlockedDomain
            elif item_type == 'email':
                Model = BlockedEmail
            else:
                print("Error: item_type must be 'domain' or 'email' for deduplication")
                sys.exit(1)
            # Run deduplication
            deleted_count = remove_database_duplicates(db_session, Model, item_type)
            if deleted_count >= 0:
                logger.info(f"Deduplication finished. Deleted {deleted_count} rows.")
            else:
                logger.error("Deduplication failed.")
        else:
            item_type = command.lower()
            if item_type not in ['domain', 'email']:
                print("Error: item_type must be 'domain' or 'email'")
                sys.exit(1)
            if len(sys.argv) < 3:
                print("Usage: python import_domains.py <domain|email> <file1> [file2 ...]")
                sys.exit(1)
            Model = BlockedDomain if item_type == 'domain' else BlockedEmail
            total_added = 0
            total_skipped = 0
            total_errors = 0

            files_to_import = sys.argv[2:]
            for file_path in files_to_import:
                if not os.path.exists(file_path):
                    logger.error(f"File not found: {file_path}. Skipping.")
                    total_errors += 1  # Count file not found as an error
                    continue

                if os.path.basename(file_path).lower() == 'cldbllacklist.txt':
                    logger.info(f"Detected CLDB blacklist format, extracting domains from: {file_path}")
                    temp_file = os.path.join(os.path.dirname(file_path), os.path.basename(file_path) + ".tmp")
                    count = 0
                    with open(file_path, 'r', encoding='utf-8') as src, open(temp_file, 'w', encoding='utf-8') as dest:
                        for line in src:
                            line = line.strip()
                            if not line or line.startswith('!'):
                                continue
                            if not line.startswith('||'):
                                continue
                            domain_part = line[2:]
                            domain_part = domain_part.split('$')[0]
                            domain_part = domain_part.split(':')[0]
                            domain_part = domain_part.replace('^', '')
                            if '/' in domain_part or '*' in domain_part:
                                continue
                            domain_part = domain_part.strip()
                            if not domain_part:
                                continue
                            dest.write(domain_part + "\n")
                            count += 1
                    if count > 0:
                        added, skipped, errors = import_list(db_session, Model, item_type, temp_file)
                    else:
                        added = skipped = errors = 0
                    total_added += added
                    total_skipped += skipped
                    total_errors += errors
                    try:
                        os.remove(temp_file)
                    except OSError:
                        pass
                    logger.info(f"--- Finished file: {file_path} ---")
                else:
                    logger.info(f"--- Processing file: {file_path} ---")
                    added, skipped, errors = import_list(db_session, Model, item_type, file_path)
                    total_added += added
                    total_skipped += skipped
                    total_errors += errors
                    logger.info(f"--- Finished file: {file_path} ---")

            logger.info("="*20 + " Overall Import Summary " + "="*20)
            logger.info(f"Total Items Added: {total_added}")
            logger.info(f"Total Items Skipped: {total_skipped}")
            logger.info(f"Total Errors (including file not found): {total_errors}")
    finally:
        db_session.close()  # Ensure session is closed
        logger.info("Database session closed.")
