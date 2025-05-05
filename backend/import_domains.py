import os
import sys
import time
from datetime import datetime
from sqlalchemy import create_engine, select, exists
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

# CHANGE: Import models and helpers from app.py
from app import db, Blocklist, Whitelist, ALLOWED_ITEM_TYPES, normalize_domain_backend, normalize_email_backend, update_data_version, DATABASE_URI, logger

# --- Configuration ---
# CHANGE: Use DATABASE_URI from app.py
SQLALCHEMY_DATABASE_URI = DATABASE_URI
ENGINE = create_engine(SQLALCHEMY_DATABASE_URI) # Use echo=True for debugging SQL
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ENGINE)

# Files containing domains/emails to import (adjust paths as needed)
BLOCKLIST_FILES = {
    'domain': ['urls.txt', 'urls-ABP.txt', 'CLDBllacklist.txt'],
    'email': [] # Add filenames for email blocklists if you have them
}
WHITELIST_FILES = {
    'domain': [], # Add filenames for domain whitelists
    'email': [] # Add filenames for email whitelists
}

# --- Helper Functions ---

def import_list(session, list_model, item_type, file_path):
    """Imports items from a file into the specified list model."""
    count = 0
    added_count = 0
    skipped_count = 0
    error_count = 0
    start_time = time.time()

    logger.info(f"Starting import for {list_model.__name__} ({item_type}) from '{file_path}'...")

    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}. Skipping.")
        return 0, 0, 0, 1 # Indicate file not found error

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                count += 1
                value = line.strip()
                if not value or value.startswith('#') or value.startswith('//'): # Skip empty lines and comments
                    skipped_count += 1
                    continue

                # Normalize based on type
                normalized_value = None
                if item_type == 'domain':
                    normalized_value = normalize_domain_backend(value)
                elif item_type == 'email':
                    normalized_value = normalize_email_backend(value)
                else:
                     logger.warning(f"Unsupported item type '{item_type}' during import. Skipping line {count}.")
                     skipped_count += 1
                     continue

                if not normalized_value:
                    # logger.warning(f"Invalid format or skipped value '{value}' (line {count}).")
                    skipped_count += 1
                    continue

                try:
                    # Check existence efficiently before adding
                    exists_query = select(exists().where(list_model.value == normalized_value))
                    item_exists = session.execute(exists_query).scalar()

                    if item_exists:
                        # logger.debug(f"'{normalized_value}' already exists. Skipping.")
                        skipped_count += 1
                        continue

                    # Add new item
                    new_item = list_model(item_type=item_type, value=normalized_value, added_on=datetime.utcnow())
                    session.add(new_item)
                    added_count += 1

                    # Commit periodically to manage memory and transaction size
                    if added_count % 1000 == 0:
                        session.commit()
                        logger.info(f"Processed {count} lines, Added {added_count}, Skipped {skipped_count}...")

                except IntegrityError: # Handle rare race conditions or duplicates if check fails
                    session.rollback()
                    logger.warning(f"Integrity error adding '{normalized_value}' (line {count}). Likely duplicate.")
                    skipped_count += 1
                except SQLAlchemyError as e:
                    session.rollback()
                    logger.error(f"Database error on line {count} ('{value}'): {e}")
                    error_count += 1
                    # Optionally stop import on error or continue
                    # continue

            # Final commit for any remaining items
            session.commit()

    except Exception as e:
        logger.error(f"Error reading file '{file_path}': {e}")
        error_count += 1
    finally:
         # CHANGE: Update the data version AFTER the import is complete
         if added_count > 0:
              data_type_key = f"{list_model.__name__.lower()}_{item_type}s"
              update_data_version(data_type_key) # Use the function from app.py
              logger.info(f"Updated data version for {data_type_key} after import.")


    end_time = time.time()
    logger.info(f"Import finished for '{file_path}'.")
    logger.info(f"Total lines processed: {count}")
    logger.info(f"Items added: {added_count}")
    logger.info(f"Items skipped (duplicates/invalid/comments): {skipped_count}")
    logger.info(f"Errors encountered: {error_count}")
    logger.info(f"Time taken: {end_time - start_time:.2f} seconds")

    return added_count, skipped_count, error_count

# --- Main Import Logic ---
if __name__ == "__main__":
    logger.info("Database Import Script Started.")
    db_session = SessionLocal()

    total_added = 0
    total_skipped = 0
    total_errors = 0

    try:
        # Import Blocklists
        logger.info("\n--- Importing Blocklists ---")
        for item_type, files in BLOCKLIST_FILES.items():
            if item_type not in ALLOWED_ITEM_TYPES: continue
            for file in files:
                added, skipped, errors = import_list(db_session, Blocklist, item_type, file)
                total_added += added
                total_skipped += skipped
                total_errors += errors

        # Import Whitelists
        logger.info("\n--- Importing Whitelists ---")
        for item_type, files in WHITELIST_FILES.items():
             if item_type not in ALLOWED_ITEM_TYPES: continue
             for file in files:
                added, skipped, errors = import_list(db_session, Whitelist, item_type, file)
                total_added += added
                total_skipped += skipped
                total_errors += errors

        logger.info("\n--- Import Summary ---")
        logger.info(f"Total items added across all files: {total_added}")
        logger.info(f"Total items skipped: {total_skipped}")
        logger.info(f"Total errors encountered: {total_errors}")

    except Exception as e:
        logger.critical(f"An unexpected error occurred during the import process: {e}", exc_info=True)
        total_errors += 1
    finally:
        db_session.close()
        logger.info("Database session closed.")

    if total_errors > 0:
        logger.warning("Import completed with errors.")
        sys.exit(1)
    else:
        logger.info("Import completed successfully.")
        sys.exit(0)