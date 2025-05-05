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
    logger.info("Database engine created for PostgreSQL.")
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
        if re.search(r"[^a-z0-9\-\.]", hostname): return None # Basic check for valid chars
        return hostname
    except Exception as e:
        logger.warning(f"Error normalizing domain '{domain}': {e}")
        return None

def is_valid_email(email: str) -> bool:
    if not email or not isinstance(email, str): return False
    return re.match(EMAIL_REGEX, email) is not None

# --- Import Function ---
def import_list(session, ModelClass, item_type, filename):
    """Imports items from a file, handling duplicates and normalization."""
    count = 0
    added = 0
    skipped_exists_db = 0
    skipped_invalid = 0
    skipped_dup_file = 0
    errors = 0

    processed_values_in_file = set() # Use a set for file deduplication

    logger.info(f"Starting import for {item_type} from {filename}")

    try:
        # --- Step 1: Read file and collect unique, normalized values ---
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                count += 1
                value = line.strip()
                if not value or value.startswith('#') or value.startswith('!'): # Skip empty/comment lines
                    continue

                original_value_for_log = value # Keep original for logging if needed
                normalized_value = None

                if item_type == 'domain':
                    # Handle common list formats before normalization
                    if value.startswith('||') and value.endswith('^'): value = value[2:-1]
                    elif value.startswith('||'): value = value[2:]
                    elif value.startswith('.'): value = value[1:] # Handle leading dot wildcards sometimes used
                    value = value.split('$')[0] # Remove options like $all
                    value = value.split('#')[0] # Remove comments on the same line
                    value = value.split('^')[0] # Remove anchors/separators
                    value = value.strip() # Clean up whitespace

                    normalized_value = normalize_domain(value)
                    if not normalized_value:
                        logger.debug(f"Line {count}: Skipping invalid domain format: '{original_value_for_log}' -> normalized to None")
                        skipped_invalid += 1
                        continue
                elif item_type == 'email':
                    normalized_value = value.lower() # Normalize email to lowercase
                    if not is_valid_email(normalized_value):
                         logger.debug(f"Line {count}: Skipping invalid email format: '{original_value_for_log}'")
                         skipped_invalid += 1
                         continue
                else:
                    logger.error("Invalid item_type specified for import.")
                    return 0, count, 0 # added, skipped, errors

                # --- File Deduplication Check ---
                if normalized_value in processed_values_in_file:
                    # logger.debug(f"Line {count}: Skipping duplicate from file: '{normalized_value}'")
                    skipped_dup_file += 1
                    continue
                processed_values_in_file.add(normalized_value)

        # --- Step 2: Check against DB and prepare for insertion ---
        unique_values_to_check = list(processed_values_in_file)
        logger.info(f"Read {count} lines, found {len(unique_values_to_check)} unique, valid items in file.")

        if not unique_values_to_check:
            logger.info("No valid items to process from file.")
            return 0, skipped_invalid + skipped_dup_file, 0

        items_to_insert_mappings = []
        existing_in_db = set()
        value_column = ModelClass.domain_name if item_type == 'domain' else ModelClass.email_address

        # Check existence in chunks for potentially large lists
        chunk_size = 500 # Process 500 items at a time
        for i in range(0, len(unique_values_to_check), chunk_size):
            chunk = unique_values_to_check[i:i+chunk_size]
            try:
                existing_query = select(value_column).where(value_column.in_(chunk))
                results = session.execute(existing_query).scalars().all()
                existing_in_db.update(results)
            except SQLAlchemyError as e:
                 logger.error(f"Database error during bulk existence check (chunk {i//chunk_size}): {e}")
                 errors += len(chunk) # Assume error for the whole chunk
                 # Consider aborting or trying individually if critical

        logger.info(f"Checked {len(unique_values_to_check)} items against DB, found {len(existing_in_db)} existing.")

        # Prepare items for bulk insertion
        import_source_tag = f"import_{os.path.basename(filename)}"
        for norm_val in unique_values_to_check:
             if norm_val in existing_in_db:
                  skipped_exists_db += 1
                  continue

             item_data = {'source': import_source_tag, 'status': 'active'} # Default fields
             if item_type == 'domain':
                  item_data['domain_name'] = norm_val
             else: # email
                  item_data['email_address'] = norm_val
             items_to_insert_mappings.append(item_data)

        # --- Step 3: Bulk Insert ---
        if items_to_insert_mappings:
            try:
                 session.bulk_insert_mappings(ModelClass, items_to_insert_mappings)
                 session.commit()
                 added = len(items_to_insert_mappings)
                 logger.info(f"Successfully added {added} new items.")
            except IntegrityError as e:
                 logger.warning(f"Database Integrity Error during bulk insert (likely concurrent additions or items missed in check): {e}. Rolling back.")
                 session.rollback()
                 errors += len(items_to_insert_mappings)
                 added = 0
                 # Could attempt individual inserts here as a fallback
            except SQLAlchemyError as e:
                 logger.error(f"Database error during bulk insert: {e}")
                 session.rollback()
                 errors += len(items_to_insert_mappings)
                 added = 0
        else:
             logger.info("No new items to add to the database.")

    except FileNotFoundError:
        logger.error(f"Error: File not found at {filename}")
        errors = count if count > 0 else 1 # Count error if file not found
    except Exception as e:
        logger.error(f"An unexpected error occurred during import of {filename}: {e}", exc_info=True)
        try:
            session.rollback() # Attempt rollback on general errors
        except Exception as rb_e:
            logger.error(f"Error during rollback attempt: {rb_e}")
        errors = count # Assume failure for all lines on unexpected error
        added = 0
        # Reset skipped counts as the process was interrupted
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
     pk_column = inspect(ModelClass).primary_key[0] # Get primary key column (usually 'id')
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
               return 0 # Return 0 deleted

          logger.info(f"Found {len(duplicate_values)} values with duplicates. Processing deletion...")

          total_deleted = 0
          # Process duplicates in chunks to avoid locking/memory issues if many duplicates exist
          chunk_size = 100
          for i in range(0, len(duplicate_values), chunk_size):
              chunk_values = duplicate_values[i:i+chunk_size]
              logger.debug(f"Processing duplicate values chunk {i//chunk_size + 1}...")

              # Subquery to find the minimum primary key (ID) for each duplicate value in the chunk
              subquery = (
                  select(func.min(pk_column))
                  .where(value_column.in_(chunk_values))
                  .group_by(value_column)
                  .scalar_subquery()
              )

              # Delete statement: Delete rows where the value is in the duplicate chunk
              # AND the primary key is NOT the minimum one found for that value.
              delete_statement = (
                  ModelClass.__table__.delete()
                  .where(value_column.in_(chunk_values))
                  .where(pk_column.not_in(subquery))
              )

              result = session.execute(delete_statement)
              deleted_count = result.rowcount
              total_deleted += deleted_count
              logger.debug(f"Deleted {deleted_count} rows in this chunk.")

              # Commit periodically for large operations
              try:
                    session.commit()
                    logger.debug("Committed deletions for chunk.")
              except SQLAlchemyError as e:
                    logger.error(f"Error committing deletions for chunk: {e}. Rolling back chunk.")
                    session.rollback()
                    # Decide how to handle: stop, log and continue? Stopping for safety.
                    logger.critical("Aborting deduplication due to commit error.")
                    return -1 # Indicate error


          logger.info(f"Database deduplication complete. Total rows deleted: {total_deleted}")
          return total_deleted

     except SQLAlchemyError as e:
          logger.error(f"Database error during deduplication query/execution: {e}")
          session.rollback()
          return -1 # Indicate error
     except Exception as e:
          logger.error(f"Unexpected error during deduplication: {e}", exc_info=True)
          session.rollback()
          return -1 # Indicate error


# --- Main Execution Logic ---
if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] == '--deduplicate':
        # Handling import and deduplication commands
        pass # Allow proceeding to command check
    elif len(sys.argv) < 3:
         print("Usage for import: python import_domains.py <domain|email> <file1.txt> [file2.txt ...]")
         print("Usage for deduplication: python import_domains.py --deduplicate <domain|email>")
         sys.exit(1)


    command = sys.argv[1]

    db_session = SessionLocal() # Create a session

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
                print("Error: item_type for deduplication must be 'domain' or 'email'")
                sys.exit(1)

            # Run deduplication
            deleted_count = remove_database_duplicates(db_session, Model, item_type)
            if deleted_count >= 0:
                 logger.info(f"Deduplication finished. Deleted {deleted_count} rows.")
            else:
                 logger.error("Deduplication failed.")

        else: # Assuming import command
            item_type = command.lower()
            files_to_import = sys.argv[2:]

            if item_type not in ['domain', 'email']:
                print("Error: item_type for import must be 'domain' or 'email'")
                print("Usage: python import_domains.py <domain|email> <file1.txt> [file2.txt ...]")
                sys.exit(1)

            Model = BlockedDomain if item_type == 'domain' else BlockedEmail

            total_added = 0
            total_skipped = 0
            total_errors = 0

            for file_path in files_to_import:
                if not os.path.exists(file_path):
                    logger.error(f"File not found: {file_path}. Skipping.")
                    total_errors += 1 # Count file not found as an error
                    continue

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
        db_session.close() # Ensure session is closed
        logger.info("Database session closed.")