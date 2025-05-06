# backend/import_domains.py
import logging
import os
import sys
import re
import argparse # Import argparse for better CLI argument handling
from urllib.parse import urlparse
from typing import Optional, List, Tuple, Type, Set

from dotenv import load_dotenv
from sqlalchemy import create_engine, select, func, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint
from sqlalchemy.sql.expression import literal_column

# --- Constants ---
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
# Default chunk size for batch processing DB operations
DEFAULT_CHUNK_SIZE = 500

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
    logger.info(f"Loaded environment variables from: {dotenv_path}")
else:
    logger.warning(f".env file not found at {dotenv_path}, relying on system environment variables.")

DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    logger.critical("CRITICAL: Biến môi trường DATABASE_URL chưa được thiết lập trong .env hoặc hệ thống.")
    sys.exit(1)

# Log the database type being used based on the URL prefix
db_type = DATABASE_URL.split(':')[0].split('+')[0] if ':' in DATABASE_URL else 'unknown'
logger.info(f"Attempting to connect to {db_type.upper()} database using DATABASE_URL.")
# Example: mysql+mysqlconnector://lethinh:PASSWORD@localhost:3306/btl_python

# Create engine and session *independent* of Flask/FastAPI app context
try:
    # Ensure you have the correct DB driver installed based on DATABASE_URL prefix
    # For 'mysql+mysqlconnector', ensure 'mysql-connector-python' is installed.
    # For 'mysql+pymysql', ensure 'PyMySQL' is installed.
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True, # Checks connection vitality before use
        pool_recycle=300,   # Recycles connections after 300 seconds (helps with timeouts)
        echo=False          # Set to True ONLY for debugging SQL statements (can be very verbose)
    )
    # Test connection early to catch configuration errors
    with engine.connect() as connection:
        logger.info("Successfully established initial database connection.")

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("Database session factory created.")

except ImportError as e:
     logger.critical(f"CRITICAL: DB driver not found or import failed. Based on DATABASE_URL prefix '{db_type}', ensure the correct driver library (e.g., mysql-connector-python) is installed. Error: {e}")
     sys.exit(1)
except SQLAlchemyError as e:
    # This catches DB connection errors, authentication errors, etc.
    logger.critical(f"CRITICAL: Failed to create database engine or connect. Check DATABASE_URL (user, password, host, port, db name) and DB server status. Error: {e}")
    sys.exit(1)
except Exception as e:
    logger.critical(f"CRITICAL: An unexpected error occurred during database setup: {e}", exc_info=True)
    sys.exit(1)


# --- Define Models ---
# TODO: Ideally, import Base and models from a shared models.py used by app.py
#       to ensure consistency and avoid redefining them here.
#       Example: from your_app.models import Base, BlockedDomain, BlockedEmail
Base = declarative_base()

class BlockedDomain(Base):
    __tablename__ = 'blocked_domains'
    # Define table columns matching your database schema
    id = Column(Integer, primary_key=True)
    domain_name = Column(String(255), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=True) # Optional reason for blocking
    source = Column(String(100), nullable=True) # Where the domain came from (e.g., import file)
    # Ensure timezone=True for consistent timestamp handling across DBs
    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = Column(String(50), default='active', nullable=False, index=True) # e.g., 'active', 'inactive'

    # Explicit unique constraint name can help with managing constraints
    __table_args__ = (UniqueConstraint('domain_name', name='uq_domain_name'),)

    def __repr__(self):
        # Useful representation for logging or debugging
        return f"<BlockedDomain(domain_name='{self.domain_name}', source='{self.source}')>"

class BlockedEmail(Base):
    __tablename__ = 'blocked_emails'
    # Define table columns matching your database schema
    id = Column(Integer, primary_key=True)
    email_address = Column(String(255), unique=True, nullable=False, index=True)
    reason = Column(String(255), nullable=True)
    source = Column(String(100), nullable=True)
    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = Column(String(50), default='active', nullable=False, index=True)

    # Explicit unique constraint name
    __table_args__ = (UniqueConstraint('email_address', name='uq_email_address'),)

    def __repr__(self):
        return f"<BlockedEmail(email_address='{self.email_address}', source='{self.source}')>"

# IMPORTANT: Before running the import for the first time,
# ensure these tables (`blocked_domains`, `blocked_emails`) exist in your MySQL database (`btl_python`).
# You might need to create them manually using SQL commands or use a migration tool like Alembic
# if you are managing your schema alongside a web application (like Flask/FastAPI).
# Example SQL (adapt types if needed for your MySQL version):
# CREATE TABLE blocked_domains (
#     id INTEGER NOT NULL AUTO_INCREMENT,
#     domain_name VARCHAR(255) NOT NULL,
#     reason VARCHAR(255) NULL,
#     source VARCHAR(100) NULL,
#     added_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
#     status VARCHAR(50) DEFAULT 'active' NOT NULL,
#     PRIMARY KEY (id),
#     UNIQUE KEY uq_domain_name (domain_name)
# );
# CREATE INDEX ix_blocked_domains_domain_name ON blocked_domains (domain_name);
# CREATE INDEX ix_blocked_domains_status ON blocked_domains (status);
# (Similar table structure for blocked_emails)

# --- Helper Functions ---
# TODO: Ideally, import these helpers from a shared utils.py used by app.py.
#       Example: from your_app.utils import normalize_domain, is_valid_email

def normalize_domain(domain: str) -> Optional[str]:
    """
    Normalizes a domain name or URL string to a standard format.
    Removes schema, www., trailing dots, converts to lowercase.
    Returns None if input is invalid or not a domain-like string.
    """
    if not domain or not isinstance(domain, str):
        return None
    try:
        domain = domain.strip().lower()
        if not domain: return None

        # Basic check: Skip things that look like IP addresses or invalid structures early
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain): # Match IPv4 with optional port
             logger.debug(f"Skipping IP address-like input: '{domain}'")
             return None
        if ':' in domain and not re.search(r":\d+$", domain): # Allow domain:port, but reject others with colons (like IPv6 for now)
             if '[' not in domain: # Don't reject valid IPv6 in brackets if needed later
                 logger.debug(f"Skipping potentially invalid format (colon without port): '{domain}'")
                 return None

        # Add scheme if missing for urlparse (handles domains and full URLs)
        scheme_present = '://' in domain
        if not scheme_present:
            # Handle cases like '.domain.com' or 'domain.' before adding scheme
             domain = domain.strip('.')
             if not domain: return None # If only dots were present
             domain = 'http://' + domain
        elif domain.startswith('//'): # Handle protocol-relative URLs
             domain = 'http:' + domain


        parsed = urlparse(domain)
        # Use hostname, which handles IDNs better if libraries support it
        # For standard ASCII domains, this works fine.
        hostname = parsed.hostname

        if not hostname:
            # Try simple splitting if urlparse fails on odd inputs but it looks like a domain
            if not scheme_present and '.' in domain and not ' ' in domain:
                 hostname = domain.split(':')[0] # Get part before port if present
            else:
                 logger.debug(f"Could not parse hostname from: '{domain}'")
                 return None

        # Remove www. prefix if present
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        # Remove trailing dot (often signifies FQDN root) and any remaining leading dots
        hostname = hostname.strip('.')

        # Final checks for validity
        if not hostname: return None

        # Check for invalid characters (basic ASCII check).
        # More complex validation (like IDNA compliance) could be added if needed.
        if re.search(r"[^a-z0-9\-\.]", hostname):
             # Allow underscores as they sometimes appear, though technically not standard for hostnames
             if re.search(r"[^a-z0-9\-\._]", hostname):
                  logger.debug(f"Invalid characters found in hostname: '{hostname}' from '{domain}'")
                  return None

        # Avoid returning TLDs only like "com" or invalid structures like "-domain-.com"
        if '.' not in hostname or hostname.startswith('.') or hostname.endswith('.') or \
           hostname.startswith('-') or hostname.endswith('-'):
             logger.debug(f"Invalid domain structure: '{hostname}' from '{domain}'")
             return None

        return hostname
    except ValueError:
        # urlparse can raise ValueError on very weird inputs like 'http://[::1]:namedport'
        logger.warning(f"ValueError during parsing, likely invalid URL/domain format: '{domain}'")
        return None
    except Exception as e:
        # Catch-all for other unexpected normalization errors
        logger.warning(f"Error normalizing domain '{domain}': {e}", exc_info=False) # Keep log clean unless debugging
        return None


def is_valid_email(email: str) -> bool:
    """Checks if a string matches a basic email format using regex."""
    if not email or not isinstance(email, str): return False
    # Use the pre-compiled regex for efficiency
    return re.match(EMAIL_REGEX, email) is not None

# --- Import Function ---
def import_list(session: Session, ModelClass: Type[Base], item_type: str, filename: str) -> Tuple[int, int, int]:
    """
    Imports items (domains or emails) from a file into the database.

    Handles:
    - Reading the file line by line.
    - Skipping comments (#, !) and empty lines.
    - Normalizing domains (handling various list formats like Adblock Plus) or emails (lowercase).
    - Skipping invalid formats based on normalization/validation functions.
    - **Deduplicating items within the current file being processed.** (Uses `processed_values_in_file` set)
    - **Checking for existence in the database before insertion.** (Uses `existing_in_db` set built via chunked queries)
    - Bulk inserting only new items for performance.
    - Logging detailed statistics for the processed file.

    Args:
        session: The SQLAlchemy session object.
        ModelClass: The SQLAlchemy model class (BlockedDomain or BlockedEmail).
        item_type: 'domain' or 'email'.
        filename: Path to the input file.

    Returns:
        A tuple: (items_added, items_skipped, errors).
    """
    line_count = 0
    added = 0
    skipped_exists_db = 0
    skipped_invalid = 0
    skipped_dup_file = 0
    errors = 0

    # Set for efficient deduplication *within this file* during processing.
    processed_values_in_file: Set[str] = set()
    # List to hold valid, normalized items from this file, ready for DB check.
    valid_items_to_check: List[str] = []

    logger.info(f"Starting import for '{item_type}' from file: {filename}")

    try:
        # --- Step 1: Read file, normalize, validate, and collect unique values from THIS FILE ---
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f: # Add errors='ignore' for potentially problematic files
            for line_num, line in enumerate(f, 1):
                line_count += 1
                value = line.strip()

                # Skip empty lines and common comment prefixes
                if not value or value.startswith('#') or value.startswith('!'):
                    continue

                original_value_for_log = value # Keep original for logging if needed
                normalized_value: Optional[str] = None

                if item_type == 'domain':
                    # --- Pre-normalization for common blocklist/input formats ---
                    # Remove Adblock Plus options and anchors first
                    value = value.split('$')[0]
                    value = value.split('^')[0]
                    # Remove comments on the same line
                    value = value.split('#')[0]
                    # Handle specific prefixes/formats
                    if value.startswith('||'): value = value[2:]      # Adblock Plus format ||domain.com
                    elif value.startswith('0.0.0.0 ') or value.startswith('127.0.0.1 '): # Hosts file format
                         value = value.split()[-1]
                    # Handle leading/trailing dots that might interfere with normalization
                    value = value.strip('. ') # Remove leading/trailing dots and spaces

                    if not value: continue # Skip if preprocessing left nothing

                    # --- Actual Normalization ---
                    normalized_value = normalize_domain(value)
                    if not normalized_value:
                        # Log if normalization explicitly returned None (invalid format)
                        if value: # Avoid logging noise from lines that became empty
                             logger.debug(f"Line {line_num}: Skipping invalid domain format: '{original_value_for_log}' (raw='{value}')")
                        skipped_invalid += 1
                        continue
                elif item_type == 'email':
                    # Basic email normalization: lowercase
                    normalized_value = value.lower()
                    if not is_valid_email(normalized_value):
                         logger.debug(f"Line {line_num}: Skipping invalid email format: '{original_value_for_log}'")
                         skipped_invalid += 1
                         continue
                else:
                    # Should be caught by argparse, but defensively handle
                    logger.error("Invalid item_type specified for import function.")
                    return 0, line_count, 1 # added, skipped, errors

                # --- File-level Deduplication Check ---
                # Check if this *normalized* value has already been processed *from this file*.
                if normalized_value in processed_values_in_file:
                    # logger.debug(f"Line {line_num}: Skipping duplicate from file: '{normalized_value}'")
                    skipped_dup_file += 1
                    continue

                # If it's new for this file, add it to the set and the list for DB checks
                processed_values_in_file.add(normalized_value)
                valid_items_to_check.append(normalized_value)

        logger.info(f"Read {line_count} lines. Found {len(valid_items_to_check)} unique, valid, normalized items in file '{os.path.basename(filename)}'.")

        if not valid_items_to_check:
            logger.info(f"No new valid items found in file {filename} to process further.")
            total_skipped_file_stage = skipped_invalid + skipped_dup_file
            return 0, total_skipped_file_stage, 0

        # --- Step 2: Check which of these items already exist in the Database (in chunks) ---
        existing_in_db: Set[str] = set()
        value_column = ModelClass.domain_name if item_type == 'domain' else ModelClass.email_address

        logger.info(f"Checking {len(valid_items_to_check)} items against database table '{ModelClass.__tablename__}'...")
        try:
            for i in range(0, len(valid_items_to_check), DEFAULT_CHUNK_SIZE):
                chunk = valid_items_to_check[i : i + DEFAULT_CHUNK_SIZE]
                if not chunk: continue

                # logger.debug(f"Checking DB existence for chunk {i // DEFAULT_CHUNK_SIZE + 1}/{ (len(valid_items_to_check) + DEFAULT_CHUNK_SIZE - 1) // DEFAULT_CHUNK_SIZE } ({len(chunk)} items)")
                # Query the database for items in the current chunk that exist
                existing_query = select(value_column).where(value_column.in_(chunk))
                results = session.execute(existing_query).scalars().all()
                # Update the set of items found in the DB
                existing_in_db.update(results)

            # Count how many items from the file were found in the DB
            skipped_exists_db = len(existing_in_db)
            logger.info(f"Found {skipped_exists_db} items from '{os.path.basename(filename)}' already present in the database.")

        except SQLAlchemyError as e:
             logger.error(f"Database error during bulk existence check for file {filename}: {e}. Aborting import for this file.")
             session.rollback() # Rollback any potential transaction state change
             # Mark all items intended for checking as errors for this file's summary
             errors = len(valid_items_to_check)
             return 0, skipped_invalid + skipped_dup_file, errors


        # --- Step 3: Prepare list of items that are NEW (not in file duplicates, not in DB) ---
        items_to_insert_mappings = []
        import_source_tag = f"import_{os.path.basename(filename)}" # Tag source based on filename

        for norm_val in valid_items_to_check:
             # Skip if it was found during the database check phase
             if norm_val in existing_in_db:
                  continue # Already counted in skipped_exists_db

             # Prepare data dictionary for insertion map
             item_data = {'source': import_source_tag, 'status': 'active'} # Default fields
             if item_type == 'domain':
                  item_data['domain_name'] = norm_val
             else: # email
                  item_data['email_address'] = norm_val
             items_to_insert_mappings.append(item_data)

        # --- Step 4: Perform Bulk Insert (if any new items) ---
        if items_to_insert_mappings:
            num_to_insert = len(items_to_insert_mappings)
            logger.info(f"Attempting to bulk insert {num_to_insert} new items from {filename}...")
            try:
                 # Use bulk_insert_mappings for better performance than individual inserts
                 session.bulk_insert_mappings(ModelClass, items_to_insert_mappings)
                 session.commit() # Commit the transaction for this file's batch
                 added = num_to_insert
                 logger.info(f"Successfully added {added} new items from {filename}.")
            except IntegrityError as e:
                 # This usually happens if an item was added by another process between the check and insert,
                 # or if the existence check somehow missed an item. Also catches constraint violations.
                 logger.warning(f"Database Integrity Error during bulk insert for {filename} (likely concurrent additions or constraint violation): {e}. Rolling back this batch.")
                 session.rollback() # Rollback the failed transaction
                 logger.warning(f"Failed to insert {num_to_insert} items due to IntegrityError. These items were skipped.")
                 errors += num_to_insert # Count these as errors for this file import
                 added = 0 # Reset added count for this failed attempt
            except SQLAlchemyError as e:
                 logger.error(f"Database error during bulk insert for {filename}: {e}. Rolling back this batch.")
                 session.rollback()
                 logger.warning(f"Failed to insert {num_to_insert} items due to SQLAlchemyError. These items were skipped.")
                 errors += num_to_insert # Count as errors
                 added = 0
        else:
             # This is expected if all items in the file were duplicates or already in DB
             logger.info(f"No new items required insertion from {filename}.")

    except FileNotFoundError:
        logger.error(f"Error: File not found at {filename}")
        errors = 1 # Count file not found as one distinct error for summary
        added, skipped_exists_db, skipped_invalid, skipped_dup_file = 0, 0, 0, 0 # Reset counts
    except IOError as e:
        logger.error(f"Error reading file {filename}: {e}")
        errors = 1 # Count file reading error
        added, skipped_exists_db, skipped_invalid, skipped_dup_file = 0, 0, 0, 0
    except Exception as e:
        logger.error(f"An unexpected error occurred during import of {filename}: {e}", exc_info=True) # Log traceback
        try:
            session.rollback() # Attempt rollback on general errors
            logger.warning("Rolled back transaction due to unexpected error during file processing.")
        except Exception as rb_e:
            logger.error(f"Error during rollback attempt after unexpected error: {rb_e}")
        # Assume failure for all lines read so far if unexpected error occurs mid-file
        errors = line_count if line_count > 0 else 1
        added, skipped_exists_db, skipped_invalid, skipped_dup_file = 0, 0, 0, 0 # Reset counts

    # Calculate total skipped for this file (DB + File duplicates/invalid)
    total_skipped = skipped_exists_db + skipped_invalid + skipped_dup_file
    logger.info(f"Import finished for {filename}: Added={added}, Skipped={total_skipped} [DB={skipped_exists_db}, FileInvalid/Dup={skipped_invalid + skipped_dup_file}], Errors={errors}")

    return added, total_skipped, errors


# --- Database Deduplication Function ---
# (No changes needed for this function based on the request)
def remove_database_duplicates(session: Session, ModelClass: Type[Base], item_type: str) -> int:
     """
     Finds and removes duplicate entries in the specified database table based on the value column.
     Keeps the entry with the lowest primary key (ID) for each duplicate value.

     Args:
         session: The SQLAlchemy session object.
         ModelClass: The SQLAlchemy model class (BlockedDomain or BlockedEmail).
         item_type: 'domain' or 'email'.

     Returns:
         The number of rows deleted, or -1 if an error occurred.
     """
     logger.info(f"Starting database deduplication for '{item_type}' in table '{ModelClass.__tablename__}'...")
     value_column_name = 'domain_name' if item_type == 'domain' else 'email_address'
     value_column = getattr(ModelClass, value_column_name)

     try:
          # Dynamically get the primary key column (usually 'id') from the model's inspection
          pk_column = inspect(ModelClass).primary_key[0]
          logger.info(f"Identifying duplicates based on column '{value_column_name}', keeping row with lowest '{pk_column.name}'.")

          # --- Step 1: Find values that have duplicates ---
          # Select the value and count occurrences, filter for counts > 1
          duplicate_values_query = (
              select(value_column, func.count(pk_column).label('count')) # Select value and count
              .group_by(value_column)      # Group by the value to count duplicates
              .having(func.count(pk_column) > 1) # Filter for groups with more than one entry
          )
          # Execute and fetch only the values that are duplicated
          duplicate_values = session.execute(duplicate_values_query).scalars().all()

          if not duplicate_values:
               logger.info("No duplicate values found in the database table.")
               return 0 # Return 0 deleted

          logger.info(f"Found {len(duplicate_values)} distinct values with duplicates.")

          # --- Step 2: Delete duplicates, keeping the one with the MIN ID ---
          total_deleted = 0
          # Process in chunks to avoid very large IN clauses or potential locking issues
          logger.info(f"Processing deletions in chunks of up to {DEFAULT_CHUNK_SIZE} duplicate values...")
          for i in range(0, len(duplicate_values), DEFAULT_CHUNK_SIZE):
              chunk_values = duplicate_values[i : i + DEFAULT_CHUNK_SIZE]
              if not chunk_values: continue

              logger.debug(f"Processing duplicate values chunk {i // DEFAULT_CHUNK_SIZE + 1} ({len(chunk_values)} values)...")

              # Subquery to find the minimum primary key (ID) for each duplicate value *in this chunk*.
              # This identifies the single row we want to KEEP for each duplicated value.
              min_pk_subquery = (
                  select(func.min(pk_column)) # Find the minimum primary key...
                  .where(value_column.in_(chunk_values)) # ...for the values in this chunk...
                  .group_by(value_column)      # ...grouped by the value...
                  .scalar_subquery() # ...used as a subquery for the NOT IN clause below.
              )

              # Construct the DELETE statement using SQLAlchemy Core API for efficiency
              # Delete rows from the target table WHERE:
              # 1. The value column is one of the duplicated values in the current chunk.
              # 2. The primary key (ID) of the row is NOT the minimum ID found for that value
              #    (i.e., delete all rows for a value EXCEPT the one with the minimum ID).
              delete_statement = (
                  ModelClass.__table__.delete() # Target the table directly
                  .where(value_column.in_(chunk_values)) # Filter by duplicated values in the chunk
                  .where(pk_column.not_in(min_pk_subquery)) # Exclude the row with the minimum PK for each value
              )

              # Execute the delete statement for the current chunk
              try:
                  result = session.execute(delete_statement)
                  deleted_count_chunk = result.rowcount # Get the number of rows affected (deleted)
                  session.commit() # Commit deletions for this chunk IMPORTANT: Commit frequently for large deletes
                  total_deleted += deleted_count_chunk
                  if deleted_count_chunk > 0:
                       logger.debug(f"Deleted {deleted_count_chunk} duplicate rows in this chunk. Committed transaction.")
                  else:
                       logger.debug("No rows deleted in this chunk (might be expected if duplicates resolved concurrently).")
              except SQLAlchemyError as e:
                  logger.error(f"Database error during delete execution or commit for chunk {i // DEFAULT_CHUNK_SIZE + 1}: {e}. Rolling back chunk.")
                  session.rollback()
                  logger.critical("Aborting deduplication process due to commit error.")
                  return -1 # Indicate error

          logger.info(f"Database deduplication complete for {ModelClass.__tablename__}. Total duplicate rows deleted: {total_deleted}")
          return total_deleted

     except SQLAlchemyError as e:
          logger.error(f"Database error during deduplication query setup or execution: {e}")
          session.rollback() # Ensure rollback on error
          return -1 # Indicate error
     except Exception as e:
          # Catch unexpected errors during the process
          logger.error(f"Unexpected error during deduplication: {e}", exc_info=True)
          session.rollback()
          return -1 # Indicate error


# --- Main Execution Logic ---
if __name__ == "__main__":
    # Setup argparse for clear command-line interface
    parser = argparse.ArgumentParser(
        description="Import domains or emails into the blocklist database or remove duplicates from the DB.",
        formatter_class=argparse.RawTextHelpFormatter # Preserve formatting in help text
        )

    # Use subparsers to handle different actions: 'import' and 'deduplicate'
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # --- Define 'import' command arguments ---
    parser_import = subparsers.add_parser('import', help='Import items (domains/emails) from one or more text files.')
    parser_import.add_argument(
        'item_type',
        choices=['domain', 'email'],
        help='Specify whether to import "domain" or "email". Determines normalization and target table.'
        )
    parser_import.add_argument(
        'files',
        nargs='+', # '+' means 1 or more files are required
        metavar='FILE',
        help='Path(s) to the text file(s) containing items to import (one item per line).'
        )

    # --- Define 'deduplicate' command arguments ---
    parser_deduplicate = subparsers.add_parser(
        'deduplicate',
        help='Remove duplicate entries (based on domain_name or email_address) from the database table, keeping the oldest entry (lowest ID).'
        )
    parser_deduplicate.add_argument(
        'item_type',
        choices=['domain', 'email'],
        help='Specify the type ("domain" or "email") to deduplicate, which determines the target table.'
        )

    # Parse the command-line arguments provided when running the script
    try:
        args = parser.parse_args()
    except SystemExit:
         # argparse handles showing help/errors and exiting if args are invalid.
         sys.exit(1) # Exit gracefully if argparse found an issue

    # --- Execute the requested command ---
    db_session: Optional[Session] = None # Initialize session variable, will be created in try block
    exit_code = 0 # Default exit code is 0 (success)

    try:
        # Create a new database session for this script execution run
        db_session = SessionLocal()
        logger.info("Database session opened for script execution.")

        # --- Handle 'import' command ---
        if args.command == 'import':
            item_type = args.item_type
            files_to_import = args.files
            # Select the correct SQLAlchemy Model based on item_type
            Model = BlockedDomain if item_type == 'domain' else BlockedEmail

            logger.info(f"Starting import process for type '{item_type}' into table '{Model.__tablename__}'.")

            # Initialize overall counters for the import session
            overall_added = 0
            overall_skipped = 0
            overall_errors = 0

            # Iterate through each file provided in the command line
            for file_path in files_to_import:
                # Basic check if file exists before attempting to open
                if not os.path.isfile(file_path): # Use isfile for better check
                    logger.error(f"File not found or is not a regular file: {file_path}. Skipping.")
                    overall_errors += 1 # Count file not found as a distinct error
                    continue # Move to the next file

                logger.info(f"--- Processing file: {file_path} ---")
                try:
                    # Call the import_list function for the current file
                    # Pass the active session, model, type, and path
                    added, skipped, errors = import_list(db_session, Model, item_type, file_path)
                    # Accumulate results from this file to the overall totals
                    overall_added += added
                    overall_skipped += skipped
                    overall_errors += errors
                except Exception as e:
                     # Catch any unexpected errors specifically during a single file's import process
                     logger.error(f"Unexpected critical error processing file {file_path}: {e}", exc_info=True)
                     overall_errors += 1 # Count this as a file processing error
                     # Attempt to rollback just in case the error left the session in a weird state
                     try:
                         db_session.rollback()
                         logger.warning(f"Rolled back session state after error in file {file_path}")
                     except Exception as rb_err:
                         logger.error(f"Error during rollback attempt after file processing error: {rb_err}")

                logger.info(f"--- Finished processing file: {file_path} ---")


            # Log the summary for the entire import operation across all files
            logger.info("="*20 + " Overall Import Summary " + "="*20)
            logger.info(f"Files processed: {len(files_to_import)}")
            logger.info(f"Total Items Added: {overall_added}")
            logger.info(f"Total Items Skipped (DB dups + File dups/invalid): {overall_skipped}")
            logger.info(f"Total Errors (File not found / Read errors / DB errors): {overall_errors}")
            if overall_errors > 0:
                exit_code = 1 # Indicate partial or full failure if any errors occurred

        # --- Handle 'deduplicate' command ---
        elif args.command == 'deduplicate':
            item_type = args.item_type
            # Select the correct SQLAlchemy Model based on item_type
            Model = BlockedDomain if item_type == 'domain' else BlockedEmail

            logger.info(f"Starting deduplication process for type '{item_type}' in table '{Model.__tablename__}'.")
            # Run the deduplication function using the active session
            deleted_count = remove_database_duplicates(db_session, Model, item_type)

            if deleted_count >= 0:
                 # Log success even if 0 rows were deleted (meaning no duplicates found)
                 logger.info(f"Deduplication finished successfully. Deleted {deleted_count} duplicate rows.")
            else:
                 # deleted_count returns -1 on error
                 logger.error("Deduplication process failed due to database errors.")
                 exit_code = 1 # Indicate failure

    except Exception as e:
        # Catch-all for unexpected errors during the main script execution
        # (e.g., errors during session creation before command handling starts)
        logger.critical(f"An unexpected critical error occurred during script execution: {e}", exc_info=True)
        exit_code = 1 # Indicate failure
        # Attempt rollback if session exists and is active (might not exist if error was early)
        if db_session and db_session.is_active:
            try:
                db_session.rollback()
                logger.warning("Rolled back transaction due to critical script error.")
            except Exception as rb_err:
                 logger.error(f"Error during rollback attempt after critical error: {rb_err}")

    finally:
        # Crucial: Ensure the database session is always closed properly,
        # releasing the connection back to the pool, even if errors occurred.
        if db_session:
            try:
                db_session.close()
                logger.info("Database session closed.")
            except Exception as close_err:
                logger.error(f"Error closing the database session: {close_err}")
                if exit_code == 0: exit_code = 1 # Ensure error is reported if closing failed

    logger.info(f"Script finished with exit code {exit_code}.")
    sys.exit(exit_code) # Exit script with 0 for success, non-zero for errors