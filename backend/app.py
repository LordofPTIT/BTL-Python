import os
import re
import logging
import sys
import time # <<< Import time for timestamps
from datetime import datetime, timezone # <<< Use timezone-aware datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, exists, func, Index, inspect
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from urllib.parse import urlparse
from dotenv import load_dotenv

# --- Constants ---
ALLOWED_ITEM_TYPES = {'domain', 'email'}
# Basic regex for email validation (consider using a library like email-validator for robustness)
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
DEFAULT_PAGE = 1
DEFAULT_PER_PAGE = 100 # Default items per page for pagination

# --- Load Environment Variables ---
# Load .env file only if it exists (useful for local development)
if os.path.exists(".env"):
    load_dotenv()
    print("Loaded environment variables from .env file.")
else:
    print(".env file not found, relying on system environment variables.")

# --- Logging Configuration ---
# Configure logging to output to stdout, suitable for Render/containerized environments
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- Flask App Initialization ---
app = Flask(__name__)

# --- CORS Configuration ---
# Get allowed origins from environment variable, default to allow all for development
# For production, set ALLOWED_ORIGINS="chrome-extension://YOUR_EXTENSION_ID"
allowed_origins = os.getenv('ALLOWED_ORIGINS', '*')
if allowed_origins != '*':
    allowed_origins_list = [origin.strip() for origin in allowed_origins.split(',')]
    logger.info(f"Configuring CORS for specific origins: {allowed_origins_list}")
    CORS(app, origins=allowed_origins_list, supports_credentials=True)
else:
    logger.warning("Configuring CORS to allow all origins (DEVELOPMENT ONLY)")
    CORS(app) # Allow all origins by default

# --- Database Configuration ---
db_url = os.getenv('DATABASE_URL')
if not db_url:
    logger.critical("CRITICAL: Biến môi trường DATABASE_URL chưa được thiết lập.")
    raise ValueError("DATABASE_URL environment variable not set.")

# Ensure URL uses 'postgresql://' prefix required by SQLAlchemy for psycopg2
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
    logger.info("Updated DATABASE_URL prefix to postgresql://")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
# Disable modification tracking as it's deprecated and consumes extra memory
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Optional: Add configurations for pool size, timeout, etc. if needed
# app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_size': 10, 'pool_recycle': 280}

db = SQLAlchemy(app)

# --- Database Models ---

class BlockedDomain(db.Model):
    """Model for storing blocked domain names."""
    __tablename__ = 'blocked_domains'
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    # Use timezone-aware datetime, default to current UTC time on insert
    added_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = db.Column(db.String(50), default='active', nullable=False, index=True) # e.g., 'active', 'inactive'

    def __repr__(self):
        return f'<BlockedDomain {self.domain_name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'domain_name': self.domain_name,
            'reason': self.reason,
            'source': self.source,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'status': self.status
        }

class BlockedEmail(db.Model):
    """Model for storing blocked email addresses."""
    __tablename__ = 'blocked_emails'
    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.String(255), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    added_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = db.Column(db.String(50), default='active', nullable=False, index=True)

    def __repr__(self):
        return f'<BlockedEmail {self.email_address}>'

    def to_dict(self):
        return {
            'id': self.id,
            'email_address': self.email_address,
            'reason': self.reason,
            'source': self.source,
            'added_at': self.added_at.isoformat() if self.added_at else None,
            'status': self.status
        }

class ReportedItem(db.Model):
    """Model for items reported by users."""
    __tablename__ = 'reported_items'
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(50), nullable=False, index=True) # 'domain' or 'email'
    value = db.Column(db.String(255), nullable=False, index=True) # The domain name or email address
    reason = db.Column(db.String(500), nullable=True) # Optional reason from user
    source = db.Column(db.String(100), nullable=True) # e.g., 'chrome_extension_user'
    reported_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = db.Column(db.String(50), default='pending', nullable=False, index=True) # 'pending', 'reviewed', 'rejected'

    def __repr__(self):
        return f'<ReportedItem {self.item_type}:{self.value}>'

    def to_dict(self):
        return {
            'id': self.id,
            'item_type': self.item_type,
            'value': self.value,
            'reason': self.reason,
            'source': self.source,
            'reported_at': self.reported_at.isoformat() if self.reported_at else None,
            'status': self.status
        }

class WhitelistedItem(db.Model):
    """Model for whitelisted domains or emails."""
    __tablename__ = 'whitelisted_items'
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(50), nullable=False, index=True) # 'domain' or 'email'
    value = db.Column(db.String(255), nullable=False, index=True) # The domain name or email address
    reason = db.Column(db.String(255), nullable=True)
    added_by = db.Column(db.String(100), nullable=True) # Identifier of who added it
    added_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Add a unique constraint for item_type and value
    __table_args__ = (db.UniqueConstraint('item_type', 'value', name='_item_type_value_uc'),)


    def __repr__(self):
        return f'<WhitelistedItem {self.item_type}:{self.value}>'

    def to_dict(self):
        return {
            'id': self.id,
            'item_type': self.item_type,
            'value': self.value,
            'reason': self.reason,
            'added_by': self.added_by,
            'added_at': self.added_at.isoformat() if self.added_at else None
        }

# --- Helper Functions ---

def normalize_domain(domain: str) -> str | None:
    """
    Normalizes a domain name to a standard format (lowercase, strip www).
    Returns None if input is invalid.
    """
    if not domain or not isinstance(domain, str):
        return None
    try:
        # Prepend http:// if no scheme exists for urlparse
        if '://' not in domain:
            domain = 'http://' + domain
        parsed = urlparse(domain)
        # Use netloc which contains the domain/subdomain
        hostname = parsed.hostname
        if not hostname:
            return None
        # Convert to lowercase
        hostname = hostname.lower()
        # Remove leading 'www.' if present
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        return hostname
    except Exception as e:
        logger.warning(f"Error normalizing domain '{domain}': {e}")
        return None

def is_valid_email(email: str) -> bool:
    """Validates email format using regex."""
    if not email or not isinstance(email, str):
        return False
    # Consider using email-validator library for more robust checks (incl. DNS)
    return re.match(EMAIL_REGEX, email) is not None

# --- Error Handling ---
@app.errorhandler(400)
def bad_request_error(error):
    logger.warning(f"Bad Request: {error.description}")
    return jsonify(error=str(error.description)), 400

@app.errorhandler(404)
def not_found_error(error):
    logger.info(f"Not Found: {request.path}")
    return jsonify(error="Resource not found"), 404

@app.errorhandler(500)
def internal_error(error):
    # Log the actual error cause if available
    original_exception = getattr(error, "original_exception", error)
    logger.error(f"Internal Server Error: {original_exception}", exc_info=True)
    db.session.rollback() # Rollback session in case of DB error during request
    return jsonify(error="Internal server error"), 500

@app.errorhandler(SQLAlchemyError)
def handle_db_error(error):
    logger.error(f"Database Error: {error}", exc_info=True)
    db.session.rollback()
    return jsonify(error="Database operation failed"), 500

@app.errorhandler(IntegrityError)
def handle_integrity_error(error):
    logger.warning(f"Database Integrity Error: {error.orig}") # Log original DB error
    db.session.rollback()
    # Provide a more user-friendly message for common integrity issues like duplicates
    if "duplicate key value violates unique constraint" in str(error.orig).lower():
         return jsonify(error="Item already exists or conflicts with existing data."), 409 # Conflict
    return jsonify(error="Data conflict or constraint violation."), 400

# --- API Endpoints ---

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    # Optional: Add database connection check
    # try:
    #     db.session.execute(select(1))
    #     db_status = "ok"
    # except Exception as e:
    #     logger.error(f"Health check DB connection failed: {e}")
    #     db_status = "error"
    # return jsonify(status="ok", database=db_status), 200
    return jsonify(status="ok"), 200


@app.route('/api/check', methods=['GET'])
def check_item():
    """
    Checks if a given domain or email is blocked or whitelisted.
    Query Parameters:
        type (str): 'domain' or 'email'. Required.
        value (str): The domain name or email address. Required.
    Returns:
        JSON: {'status': 'blocked'|'whitelisted'|'safe', 'details': {}}
    """
    # --- Start timer (FIXED: using time.time()) ---
    request_start_time = time.time()
    logger.info(f"Received /api/check request: {request.args}")

    item_type = request.args.get('type')
    value = request.args.get('value')

    # --- Input Validation ---
    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/check: Invalid or missing 'type' parameter: {item_type}")
        return jsonify(error=f"Invalid or missing 'type' parameter. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    if not value:
        logger.warning("/api/check: Missing 'value' parameter.")
        return jsonify(error="Missing 'value' parameter."), 400

    normalized_value = None
    if item_type == 'domain':
        normalized_value = normalize_domain(value)
        if not normalized_value:
            logger.warning(f"/api/check: Invalid domain format: {value}")
            return jsonify(error=f"Invalid domain format: {value}"), 400
    elif item_type == 'email':
        if not is_valid_email(value):
            logger.warning(f"/api/check: Invalid email format: {value}")
            return jsonify(error=f"Invalid email format: {value}"), 400
        normalized_value = value.lower() # Store emails lowercase

    logger.info(f"/api/check: Processing type='{item_type}', normalized_value='{normalized_value}'")

    try:
        # 1. Check Whitelist first
        whitelist_stmt = select(WhitelistedItem).where(
            WhitelistedItem.item_type == item_type,
            func.lower(WhitelistedItem.value) == normalized_value # Case-insensitive check
        )
        whitelisted_entry = db.session.execute(whitelist_stmt).scalar_one_or_none()

        if whitelisted_entry:
            logger.info(f"/api/check: Item '{normalized_value}' is whitelisted.")
            processing_time = time.time() - request_start_time
            return jsonify(status="whitelisted", details=whitelisted_entry.to_dict(), processing_time_ms=processing_time * 1000), 200

        # 2. Check Blocklist if not whitelisted
        blocked_entry = None
        if item_type == 'domain':
            block_stmt = select(BlockedDomain).where(
                BlockedDomain.domain_name == normalized_value,
                BlockedDomain.status == 'active'
            )
            blocked_entry = db.session.execute(block_stmt).scalar_one_or_none()
        elif item_type == 'email':
            block_stmt = select(BlockedEmail).where(
                BlockedEmail.email_address == normalized_value,
                BlockedEmail.status == 'active'
            )
            blocked_entry = db.session.execute(block_stmt).scalar_one_or_none()

        processing_time = time.time() - request_start_time
        if blocked_entry:
            logger.info(f"/api/check: Item '{normalized_value}' is blocked.")
            return jsonify(status="blocked", details=blocked_entry.to_dict(), processing_time_ms=processing_time * 1000), 200
        else:
            logger.info(f"/api/check: Item '{normalized_value}' is safe.")
            return jsonify(status="safe", details={}, processing_time_ms=processing_time * 1000), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error during /api/check for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Database query failed"), 500
    except Exception as e:
        logger.error(f"Unexpected error during /api/check for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Internal server error"), 500


@app.route('/api/report', methods=['POST'])
def report_item():
    """
    Reports a suspicious domain or email.
    JSON Body:
        {
            "type": "domain" | "email",
            "value": "...",
            "reason": "Optional reason from user",
            "source": "Optional source (e.g., 'chrome_extension')"
        }
    Returns:
        JSON: {'message': 'Report submitted successfully.', 'report': {...}} or error.
    """
     # --- Start timer (FIXED: using time.time()) ---
    request_start_time = time.time()
    logger.info(f"Received /api/report request: {request.json}")

    if not request.is_json:
        logger.warning("/api/report: Request content type is not JSON.")
        return jsonify(error="Request must be JSON"), 415

    data = request.json
    item_type = data.get('type')
    value = data.get('value')
    reason = data.get('reason', None) # Optional
    source = data.get('source', 'unknown') # Optional

    # --- Input Validation ---
    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/report: Invalid or missing 'type': {item_type}")
        return jsonify(error=f"Invalid or missing 'type'. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    if not value:
        logger.warning("/api/report: Missing 'value'.")
        return jsonify(error="Missing 'value' parameter."), 400

    normalized_value = None
    if item_type == 'domain':
        normalized_value = normalize_domain(value)
        if not normalized_value:
            logger.warning(f"/api/report: Invalid domain format: {value}")
            return jsonify(error=f"Invalid domain format: {value}"), 400
    elif item_type == 'email':
        if not is_valid_email(value):
            logger.warning(f"/api/report: Invalid email format: {value}")
            return jsonify(error=f"Invalid email format: {value}"), 400
        normalized_value = value.lower()

    logger.info(f"/api/report: Processing report for type='{item_type}', normalized_value='{normalized_value}'")

    try:
        # Optional: Check if already whitelisted - prevent reporting?
        whitelist_exists = db.session.query(
            exists().where(WhitelistedItem.item_type == item_type, func.lower(WhitelistedItem.value) == normalized_value)
        ).scalar()
        if whitelist_exists:
             logger.info(f"/api/report: Item '{normalized_value}' is whitelisted, report ignored.")
             processing_time = time.time() - request_start_time
             # Return success but indicate it was ignored due to whitelist
             return jsonify(message="Item is whitelisted and cannot be reported.", status="ignored_whitelisted", processing_time_ms=processing_time * 1000), 200 # 200 OK seems appropriate here

        # Check if already blocked - maybe update the reason/source or just ignore?
        # For now, let's just add the report regardless.

        # Check if already reported recently with status 'pending' (to avoid duplicates)
        report_exists = db.session.query(
            exists().where(
                ReportedItem.item_type == item_type,
                ReportedItem.value == normalized_value,
                ReportedItem.status == 'pending' # Only check pending reports
            )
        ).scalar()

        if report_exists:
            logger.info(f"/api/report: Item '{normalized_value}' already has a pending report.")
            processing_time = time.time() - request_start_time
            return jsonify(message="Report already exists and is pending review.", status="already_reported", processing_time_ms=processing_time * 1000), 200 # 200 OK or 208 Already Reported

        # Create new report
        new_report = ReportedItem(
            item_type=item_type,
            value=normalized_value,
            reason=reason,
            source=source,
            status='pending' # Default status
        )
        db.session.add(new_report)
        db.session.commit()
        logger.info(f"Successfully created report ID {new_report.id} for '{normalized_value}'.")
        processing_time = time.time() - request_start_time
        return jsonify(
            message="Report submitted successfully.",
            report=new_report.to_dict(),
            processing_time_ms=processing_time * 1000
            ), 201 # 201 Created

    except IntegrityError as e:
         # This might happen if there's a race condition despite the check above
         logger.warning(f"Database integrity error during /api/report for '{normalized_value}': {e.orig}")
         db.session.rollback()
         return jsonify(error="Report conflict, possibly already exists."), 409
    except SQLAlchemyError as e:
        logger.error(f"Database error during /api/report for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Database operation failed"), 500
    except Exception as e:
        logger.error(f"Unexpected error during /api/report for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Internal server error"), 500


@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """
    Retrieves the blocklist (domains or emails) added since a specific time.
    Query Parameters:
        type (str): 'domain' or 'email'. Required.
        since (float/int): Timestamp (seconds since epoch). Defaults to 0 (all items). Optional.
        page (int): Page number for pagination. Defaults to 1. Optional.
        per_page (int): Items per page. Defaults to 100. Optional.
    Returns:
        JSON: {'items': [...], 'total': N, 'page': N, 'per_page': N}
    """
     # --- Start timer (FIXED: using time.time()) ---
    request_start_time = time.time()
    logger.info(f"Received /api/blocklist request: {request.args}")

    item_type = request.args.get('type')
    since_str = request.args.get('since', '0')
    page = request.args.get('page', DEFAULT_PAGE, type=int)
    per_page = request.args.get('per_page', DEFAULT_PER_PAGE, type=int)

    # Limit max per_page
    per_page = min(per_page, 1000) # Set a reasonable upper limit

    # --- Input Validation ---
    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/blocklist: Invalid or missing 'type': {item_type}")
        return jsonify(error=f"Invalid or missing 'type'. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    try:
        since_timestamp = float(since_str)
        # Convert timestamp to timezone-aware datetime object
        since_dt = datetime.fromtimestamp(since_timestamp, timezone.utc)
    except ValueError:
        logger.warning(f"/api/blocklist: Invalid 'since' timestamp format: {since_str}")
        return jsonify(error="Invalid 'since' timestamp format. Must be seconds since epoch."), 400

    logger.info(f"/api/blocklist: Processing type='{item_type}', since='{since_dt}', page={page}, per_page={per_page}")

    try:
        query = None
        if item_type == 'domain':
            query = select(BlockedDomain).where(
                BlockedDomain.added_at > since_dt,
                BlockedDomain.status == 'active' # Only return active entries
            ).order_by(BlockedDomain.added_at.asc()) # Order for consistent pagination
        elif item_type == 'email':
             query = select(BlockedEmail).where(
                BlockedEmail.added_at > since_dt,
                BlockedEmail.status == 'active'
            ).order_by(BlockedEmail.added_at.asc())

        # Apply pagination
        paginated_query = query.limit(per_page).offset((page - 1) * per_page)
        items = db.session.execute(paginated_query).scalars().all()

        # Get total count for pagination info (can be slow on large tables without 'since')
        # If performance is critical, consider alternative ways or omit total count for 'since=0'
        total_count_query = select(func.count()).select_from(query.order_by(None).subquery()) # Count from the filtered query
        total_items = db.session.execute(total_count_query).scalar_one()


        result_items = [item.to_dict() for item in items]
        processing_time = time.time() - request_start_time
        logger.info(f"/api/blocklist: Found {len(result_items)} items (Total: {total_items}) for type='{item_type}' since {since_dt}.")

        return jsonify(
            items=result_items,
            total=total_items,
            page=page,
            per_page=per_page,
            processing_time_ms=processing_time * 1000
        ), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error during /api/blocklist for type='{item_type}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Database query failed"), 500
    except Exception as e:
        logger.error(f"Unexpected error during /api/blocklist for type='{item_type}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Internal server error"), 500

@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    """
    Retrieves the whitelist (domains or emails) added since a specific time.
    Query Parameters:
        type (str): 'domain' or 'email'. Required.
        since (float/int): Timestamp (seconds since epoch). Defaults to 0 (all items). Optional.
        page (int): Page number for pagination. Defaults to 1. Optional.
        per_page (int): Items per page. Defaults to 100. Optional.
    Returns:
        JSON: {'items': [...], 'total': N, 'page': N, 'per_page': N}
    """
    request_start_time = time.time()
    logger.info(f"Received /api/whitelist request: {request.args}")

    item_type = request.args.get('type')
    since_str = request.args.get('since', '0')
    page = request.args.get('page', DEFAULT_PAGE, type=int)
    per_page = request.args.get('per_page', DEFAULT_PER_PAGE, type=int)

    per_page = min(per_page, 1000) # Limit per_page

    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/whitelist: Invalid or missing 'type': {item_type}")
        return jsonify(error=f"Invalid or missing 'type'. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    try:
        since_timestamp = float(since_str)
        since_dt = datetime.fromtimestamp(since_timestamp, timezone.utc)
    except ValueError:
         logger.warning(f"/api/whitelist: Invalid 'since' timestamp format: {since_str}")
         return jsonify(error="Invalid 'since' timestamp format. Must be seconds since epoch."), 400

    logger.info(f"/api/whitelist: Processing type='{item_type}', since='{since_dt}', page={page}, per_page={per_page}")

    try:
        # Query whitelisted items based on type and time added
        query = select(WhitelistedItem).where(
            WhitelistedItem.item_type == item_type,
            WhitelistedItem.added_at > since_dt
        ).order_by(WhitelistedItem.added_at.asc())

        # Apply pagination
        paginated_query = query.limit(per_page).offset((page - 1) * per_page)
        items = db.session.execute(paginated_query).scalars().all()

        # Get total count
        total_count_query = select(func.count()).select_from(query.order_by(None).subquery())
        total_items = db.session.execute(total_count_query).scalar_one()

        result_items = [item.to_dict() for item in items]
        processing_time = time.time() - request_start_time
        logger.info(f"/api/whitelist: Found {len(result_items)} items (Total: {total_items}) for type='{item_type}' since {since_dt}.")

        return jsonify(
            items=result_items,
            total=total_items,
            page=page,
            per_page=per_page,
            processing_time_ms=processing_time * 1000
        ), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error during /api/whitelist for type='{item_type}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Database query failed"), 500
    except Exception as e:
        logger.error(f"Unexpected error during /api/whitelist for type='{item_type}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Internal server error"), 500


# --- Database Initialization ---
def initialize_database():
    """Checks if tables exist and creates them if they don't."""
    logger.info("Initializing database...")
    try:
        # Reflect existing tables
        inspector = inspect(db.engine)
        existing_tables = inspector.get_table_names()
        logger.info(f"Existing tables: {existing_tables}")

        # Check if our models' tables exist
        required_tables = [
            BlockedDomain.__tablename__,
            BlockedEmail.__tablename__,
            ReportedItem.__tablename__,
            WhitelistedItem.__tablename__
        ]

        missing_tables = [tbl for tbl in required_tables if tbl not in existing_tables]

        if missing_tables:
            logger.info(f"Creating missing tables: {missing_tables}")
            # Create only the missing tables (or use db.create_all() if sure)
            # Using metadata associated with the models ensures only defined tables are created
            db.metadata.create_all(bind=db.engine, tables=[
                db.metadata.tables[tbl] for tbl in missing_tables
            ])
            logger.info("Database tables created successfully.")
            # Optional: Seed database after creation if needed
            # seed_database()
        else:
            logger.info("All required database tables already exist.")

    except SQLAlchemyError as e:
        logger.critical(f"CRITICAL: Database initialization failed: {e}", exc_info=True)
        # Depending on the error, you might want to exit or retry
    except Exception as e:
        logger.critical(f"CRITICAL: Unexpected error during database initialization: {e}", exc_info=True)


# --- Seed Database (Optional, for initial data) ---
# def seed_database():
#     """Adds initial sample data to the database if empty."""
#     logger.info("Attempting to seed database...")
#     try:
#         # Check if seeding is needed (e.g., count records)
#         domain_count = db.session.query(func.count(BlockedDomain.id)).scalar()
#         email_count = db.session.query(func.count(BlockedEmail.id)).scalar()

#         if domain_count == 0 and email_count == 0:
#             logger.info("Seeding database with initial data...")
#             # Thêm domain mẫu
#             domains = [
#                 BlockedDomain(domain_name='malicious-example.com', reason='Known Phishing Site', source='SeedData', status='active'),
#                 BlockedDomain(domain_name='fake-bank-login.net', reason='Phishing', source='SeedData', status='active'),
#             ]
#             db.session.add_all(domains)

#             # Thêm email mẫu
#             emails = [
#                 BlockedEmail(email_address='support@fake-paypal-service.com', reason='Known PayPal Phishing', source='SeedData', status='active'),
#                 BlockedEmail(email_address='admin@suspicious-login.net', reason='Reported Spear Phishing', source='SeedData', status='active'),
#             ]
#             db.session.add_all(emails)

#              # Thêm whitelist mẫu
#             whitelists = [
#                  WhitelistedItem(item_type='domain', value='my-internal-tool.corp', reason='Internal Tool', added_by='SeedData'),
#                  WhitelistedItem(item_type='email', value='safe.sender@trusted.com', reason='Trusted Partner', added_by='SeedData'),
#              ]
#             db.session.add_all(whitelists)

#             db.session.commit()
#             logger.info("Database seeded successfully.")
#         else:
#             logger.info("Database already contains data, skipping seed.")

#     except IntegrityError as e:
#          logger.warning(f"Integrity error during seeding (likely duplicate data): {e.orig}")
#          db.session.rollback()
#     except SQLAlchemyError as e:
#          db.session.rollback()
#          logger.error(f"Error seeding database: {e}", exc_info=True)
#     except Exception as e:
#          db.session.rollback()
#          logger.error(f"Unexpected error seeding database: {e}", exc_info=True)


# --- Main Execution Guard ---
if __name__ == '__main__':
    # Database initialization should ideally be handled by migrations (e.g., Flask-Migrate)
    # or a separate setup script, not typically run every time the dev server starts.
    # However, for simple cases or first run, this can be useful.
    with app.app_context(): # Create application context for DB operations
        initialize_database()

    # Get port from environment variable, default to 5001 for local dev if not set
    port = int(os.environ.get("PORT", 5001))

    # Run Flask development server (DO NOT USE IN PRODUCTION)
    # Use a production-grade WSGI server like Gunicorn or uWSGI instead.
    # Example Render Start Command: gunicorn --bind 0.0.0.0:$PORT --workers 3 --log-level info app:app
    logger.info(f"Starting Flask development server on http://0.0.0.0:{port}")
    # debug=True enables auto-reloading and debugger, disable in production
    app.run(host='0.0.0.0', port=port, debug=False) # Set debug=False for production-like behavior