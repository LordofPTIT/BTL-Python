# backend/import_domains.py
import logging
import os
import sys
import re
from urllib.parse import urlparse
from typing import Optional, List, Set

from dotenv import load_dotenv
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint
from datetime import datetime, timezone

DEFAULT_CHUNK_SIZE = 500

URLS_FILE = "urls.txt"
URLS_ABP_FILE = "urls-ABP.txt"
CLDB_BLACKLIST_FILE = "CLDBllacklist.txt"
FILES_TO_PROCESS = [URLS_FILE, URLS_ABP_FILE, CLDB_BLACKLIST_FILE]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("import_script")

dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    logger.warning(".env file not found. Using system environment variables.")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.critical("DATABASE_URL environment variable not set.")
    sys.exit(1)

try:
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    logger.info("Database connection successful.")
except Exception as e:
    logger.critical(f"Failed to connect to database using DATABASE_URL: {e}")
    sys.exit(1)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class PhishingDomain(Base):
    __tablename__ = 'phishing_domains'

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    added_at = Column(DateTime, default=datetime.now(timezone.utc))
    source = Column(String(50), nullable=True)

    __table_args__ = (UniqueConstraint('domain', name='_domain_uc'),)

    def __repr__(self):
        return f"<PhishingDomain(domain='{self.domain}')>"

def clean_domain(line: str) -> Optional[str]:
    line = line.strip()

    if not line or line.startswith('!') or '#' in line or '$' not in line and any(char in line for char in ['~', '|', '@', '*']):
        return None

    if line.startswith('||'):
        line = line[2:]

    if line.endswith('^'):
        line = line[:-1]

    if '$' in line:
        line = line.split('$', 1)[0]

    try:
        if '://' not in line:
             if '/' in line or '.' in line:
                  line = 'http://' + line

        parsed = urlparse(line)
        domain = parsed.hostname
        if domain:
            domain = domain.lower()
            if domain.startswith('www.'):
                 domain = domain[4:]
            return domain
        return line.lower() if '.' in line and '/' not in line else None

    except Exception as e:
        logger.warning(f"Could not parse domain from line '{line}': {e}")
        return None

def read_domains_from_file(filepath: str) -> List[str]:
    domains = set()
    processed_lines_count = 0
    full_filepath = os.path.join(os.path.dirname(__file__), filepath)

    if not os.path.exists(full_filepath):
        logger.warning(f"File not found: {full_filepath}. Skipping.")
        return []

    logger.info(f"Reading file: {full_filepath}")
    try:
        with open(full_filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                processed_lines_count += 1
                cleaned_domain = clean_domain(line)
                if cleaned_domain:
                    domains.add(cleaned_domain)

        logger.info(f"Processed {processed_lines_count} lines from file {filepath}.")
        return list(domains)

    except Exception as e:
        logger.error(f"Error reading or processing file {full_filepath}: {e}")
        return []

def get_existing_domains(session: Session) -> Set[str]:
    domains = set()
    logger.info("Checking for existing domains in the database...")
    try:
        stmt = select(PhishingDomain.domain)
        result = session.execute(stmt)
        existing_domains = set([row[0] for row in result])
        logger.info(f"Retrieved {len(existing_domains)} existing domains from the database.")
        return existing_domains
    except SQLAlchemyError as e:
        logger.error(f"Error retrieving existing domains: {e}")
        raise # Re-raise to indicate failure
    except Exception as e:
        logger.critical(f"Unexpected error retrieving existing domains: {e}", exc_info=True)
        raise

def import_new_domains(session: Session, new_domains: List[str]) -> int:
    if not new_domains:
        logger.info("No new domains to import.")
        return 0

    sql = text(f"""
        INSERT IGNORE INTO {PhishingDomain.__tablename__} (domain, added_at, source)
        VALUES (:domain, :added_at, :source)
    """)

    data_to_insert = [
        {
            "domain": domain,
            "added_at": datetime.now(timezone.utc),
            "source": None
        }
        for domain in new_domains
    ]

    total_to_import = len(data_to_insert)
    logger.info(f"Starting import of {total_to_import} new potential domains (batch size: {DEFAULT_CHUNK_SIZE}).")
    processed_count = 0

    try:
        for i in range(0, total_to_import, DEFAULT_CHUNK_SIZE):
            batch_data = data_to_insert[i:i + DEFAULT_CHUNK_SIZE]
            try:
                session.execute(sql, batch_data)
                session.commit()
                processed_count += len(batch_data)
                logger.info(f"Processed batch {i//DEFAULT_CHUNK_SIZE + 1}. Attempted import: {processed_count}/{total_to_import}.")
            except SQLAlchemyError as e:
                logger.error(f"Database error during batch import (batch starting at index {i}): {e}")
                session.rollback() # Rollback the failed batch
            except Exception as e:
                logger.critical(f"Unexpected error during batch import (batch starting at index {i}): {e}", exc_info=True)
                session.rollback() # Rollback the failed batch
                # Decide if you want to stop or continue after a critical error
                # For now, let's stop.
                raise # Re-raise the critical error

        logger.info("Import process finished (duplicates ignored).")

    except Exception as e:
         # This catches the re-raised critical error from the batch loop
         logger.critical(f"Import process interrupted due to a critical batch error: {e}", exc_info=True)
         raise # Re-raise to be caught by main's exception handler


    # Note: Returning total_to_import doesn't mean all were inserted,
    # it's the number of items we *tried* to insert after filtering.
    # To get the exact number of *new* inserts, additional logic is needed.
    # Returning processed_count reflects how many we *attempted* to process in batches.
    return processed_count


def process_domain_files(session: Session) -> int:
    all_domains_from_files: Set[str] = set()

    logger.info("Starting to read domains from files...")

    for filepath in FILES_TO_PROCESS:
        domains_from_file = read_domains_from_file(filepath)
        all_domains_from_files.update(domains_from_file)

    logger.info(f"Total unique domains read from all files: {len(all_domains_from_files)}")

    if not all_domains_from_files:
        logger.info("No valid domains found to import.")
        return 0

    try:
        existing_domains = get_existing_domains(session)
    except Exception:
        logger.error("Failed to retrieve existing domains. Cannot proceed with import.")
        return 0

    new_domains_to_import: List[str] = list(all_domains_from_files - existing_domains)

    logger.info(f"Found {len(new_domains_to_import)} potential new domains to import.")

    if not new_domains_to_import:
        logger.info("No new domains need to be imported into the database.")
        return 0

    imported_count = import_new_domains(session, new_domains_to_import)

    return imported_count

def main():
    logger.info("Starting domain import script.")
    db_session: Optional[Session] = None
    exit_code = 0

    try:
        db_session = SessionLocal()

        Base.metadata.create_all(engine, tables=[PhishingDomain.__table__])
        logger.info(f"Checked/created table '{PhishingDomain.__tablename__}'.")

        processed_items_count = process_domain_files(db_session)

        logger.info(f"Import process completed. Attempted to process {processed_items_count} potential new domains (duplicates ignored).")

    except Exception as e:
        logger.critical(f"A critical error occurred during the main process: {e}", exc_info=True)
        exit_code = 1
        if db_session and db_session.is_active:
            try:
                db_session.rollback()
                logger.warning("Rolled back transaction due to critical error.")
            except Exception as rb_err:
                 logger.error(f"Error during rollback attempt after critical error: {rb_err}")

    finally:
        if db_session:
            try:
                db_session.close()
                logger.info("Database session closed.")
            except Exception as close_err:
                logger.error(f"Error closing the database session: {close_err}")
                if exit_code == 0: exit_code = 1

    logger.info(f"Script finished with exit code {exit_code}.")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()