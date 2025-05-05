import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, exists, func, inspect, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

# --- Constants ---
ALLOWED_ITEM_TYPES = {'domain', 'email'}
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
DEFAULT_PAGE = 1
DEFAULT_PER_PAGE = 100 # Default items per page for lists

# --- Environment & Logging Setup ---
if os.path.exists(".env"):
    load_dotenv()
    print("Loaded environment variables from .env file.")
else:
    print(".env file not found, relying on system environment variables.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- Flask App Initialization ---
app = Flask(__name__)

# --- CORS Configuration ---
# Allows configuration via environment variable for production flexibility.
allowed_origins = os.getenv('ALLOWED_ORIGINS', '*')
if allowed_origins != '*':
    allowed_origins_list = [origin.strip() for origin in allowed_origins.split(',')]
    logger.info(f"Configuring CORS for specific origins: {allowed_origins_list}")
    CORS(app, origins=allowed_origins_list, supports_credentials=True, methods=["GET", "POST", "OPTIONS"])
else:
    # This is acceptable for development or controlled environments,
    # but for production, it's recommended to set specific ALLOWED_ORIGINS.
    logger.warning("Configuring CORS to allow all origins (DEVELOPMENT ONLY - Restrict in Production via ALLOWED_ORIGINS env var)")
    CORS(app, origins="*", supports_credentials=True, methods=["GET", "POST", "OPTIONS"])


# --- Database Configuration ---
db_url = os.getenv('DATABASE_URL')
if not db_url:
    logger.critical("CRITICAL: Biến môi trường DATABASE_URL chưa được thiết lập.")
    raise ValueError("DATABASE_URL environment variable not set.")
# Adjust for Heroku/Render convention
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
    logger.info("Updated DATABASE_URL prefix to postgresql://")

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,
    "pool_recycle": 300, # Recycle connections every 5 minutes
}
db = SQLAlchemy(app)

# --- Database Models ---
class BlockedDomain(db.Model):
    """Model for storing blocked domain names."""
    __tablename__ = 'blocked_domains'
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(255), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    added_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = db.Column(db.String(50), default='active', nullable=False, index=True) # e.g., active, inactive

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
    status = db.Column(db.String(50), default='active', nullable=False, index=True) # e.g., active, inactive

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
    value = db.Column(db.String(255), nullable=False, index=True) # normalized domain or email
    reason = db.Column(db.String(500), nullable=True)
    source = db.Column(db.String(100), nullable=True) # e.g., 'chrome_extension_v1.2'
    reported_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = db.Column(db.String(50), default='pending', nullable=False, index=True) # pending, approved, rejected, false_positive

    def __repr__(self):
        return f'<ReportedItem {self.item_type}:{self.value} ({self.status})>'

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
    value = db.Column(db.String(255), nullable=False, index=True) # normalized domain or email
    reason = db.Column(db.String(255), nullable=True)
    added_by = db.Column(db.String(100), nullable=True) # e.g., 'admin', 'user_report_override'
    added_at = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Ensure unique combination of type and value
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
    Normalizes a domain name to a standard format (lowercase, strip www, strip trailing dot).
    Returns None if input is invalid or represents an IP address.
    """
    if not domain or not isinstance(domain, str):
        return None
    try:
        domain = domain.strip().lower()
        if not domain:
            return None

        # Basic IP address check (v4 and v6) - we don't block IPs this way usually
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) or ':' in domain:
             # logger.debug(f"Ignoring potential IP address: {domain}")
             return None

        # Add scheme if missing for urlparse
        if '://' not in domain:
            domain = 'http://' + domain

        parsed = urlparse(domain)
        hostname = parsed.hostname
        if not hostname:
            return None

        # Strip leading/trailing dots and www.
        hostname = hostname.strip('.')
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        # Reject empty hostnames after stripping
        if not hostname:
            return None

        # Basic check for invalid characters (though urlparse usually handles this)
        if re.search(r"[^a-z0-9\-\.]", hostname):
             logger.warning(f"Potential invalid characters in hostname: {hostname} (from: {domain})")
             return None

        return hostname
    except Exception as e:
        logger.warning(f"Error normalizing domain '{domain}': {e}")
        return None

def is_valid_email(email: str) -> bool:
    """Validates email format using regex."""
    if not email or not isinstance(email, str):
        return False
    return re.match(EMAIL_REGEX, email) is not None

# --- Error Handling ---
@app.errorhandler(400)
def bad_request_error(error):
    description = getattr(error, 'description', 'Bad request')
    logger.warning(f"Bad Request: {description}")
    # Ensure consistent JSON error response
    return jsonify(error=str(description)), 400

@app.errorhandler(404)
def not_found_error(error):
    logger.info(f"Not Found: {request.path}")
    return jsonify(error="Resource not found"), 404

@app.errorhandler(415)
def unsupported_media_type_error(error):
    logger.warning(f"Unsupported Media Type: {request.content_type}")
    return jsonify(error="Unsupported Media Type. Request must be JSON."), 415

@app.errorhandler(500)
def internal_error(error):
    original_exception = getattr(error, "original_exception", error)
    logger.error(f"Internal Server Error: {original_exception}", exc_info=True)
    # Rollback session in case of DB issues during the error
    try:
        db.session.rollback()
    except Exception as rollback_err:
        logger.error(f"Error during rollback after internal error: {rollback_err}")
    return jsonify(error="Internal server error"), 500

@app.errorhandler(SQLAlchemyError)
def handle_db_error(error):
    logger.error(f"Database Error: {error}", exc_info=True)
    db.session.rollback()
    return jsonify(error="Database operation failed"), 500

@app.errorhandler(IntegrityError)
def handle_integrity_error(error):
    """Handles unique constraint violations etc."""
    error_msg = str(getattr(error, 'orig', error))
    logger.warning(f"Database Integrity Error: {error_msg}")
    db.session.rollback()
    if "duplicate key value violates unique constraint" in error_msg.lower():
         # More specific message for duplicates
         return jsonify(error="Item already exists or conflicts with existing data."), 409 # 409 Conflict
    # General integrity error
    return jsonify(error="Data conflict or constraint violation."), 400

# --- API Endpoints ---
@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    # Could add a basic DB check here if needed
    # try:
    #     db.session.execute(select(1))
    #     db_status = "ok"
    # except Exception:
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
        JSON: {'status': 'blocked'|'whitelisted'|'safe', 'details': {...}}
              or {'error': '...'} on failure.
    """
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

    # --- Normalization ---
    normalized_value = None
    if item_type == 'domain':
        normalized_value = normalize_domain(value)
        if not normalized_value:
            # Even if normalization fails, it's 'safe' from our list perspective
            logger.info(f"/api/check: Invalid or non-normalizable domain format: {value}. Treating as safe.")
            processing_time = time.time() - request_start_time
            return jsonify(status="safe", details={"reason": "Invalid format"}, processing_time_ms=processing_time * 1000), 200
    elif item_type == 'email':
        if not is_valid_email(value):
            logger.warning(f"/api/check: Invalid email format: {value}")
            # Return error for clearly invalid email format
            return jsonify(error=f"Invalid email format: {value}"), 400
        normalized_value = value.lower() # Normalize email to lowercase

    logger.info(f"/api/check: Processing type='{item_type}', normalized_value='{normalized_value}'")

    try:
        # --- Whitelist Check ---
        whitelist_stmt = select(WhitelistedItem).where(
            WhitelistedItem.item_type == item_type,
            func.lower(WhitelistedItem.value) == normalized_value # Case-insensitive check
        )
        whitelisted_entry = db.session.execute(whitelist_stmt).scalar_one_or_none()
        if whitelisted_entry:
            logger.info(f"/api/check: Item '{normalized_value}' is whitelisted.")
            processing_time = time.time() - request_start_time
            return jsonify(status="whitelisted", details=whitelisted_entry.to_dict(), processing_time_ms=processing_time * 1000), 200

        # --- Blocklist Check ---
        blocked_entry = None
        Model = BlockedDomain if item_type == 'domain' else BlockedEmail
        value_column = BlockedDomain.domain_name if item_type == 'domain' else BlockedEmail.email_address

        block_stmt = select(Model).where(
            value_column == normalized_value,
            Model.status == 'active' # Only check active blocks
        )
        blocked_entry = db.session.execute(block_stmt).scalar_one_or_none()

        processing_time = time.time() - request_start_time
        if blocked_entry:
            logger.info(f"/api/check: Item '{normalized_value}' is blocked.")
            return jsonify(status="blocked", details=blocked_entry.to_dict(), processing_time_ms=processing_time * 1000), 200
        else:
            logger.info(f"/api/check: Item '{normalized_value}' is safe (not blocked or whitelisted).")
            return jsonify(status="safe", details={}, processing_time_ms=processing_time * 1000), 200

    except SQLAlchemyError as e:
        # Log specific DB errors but return generic message
        logger.error(f"Database error during /api/check for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Database query failed"), 500
    except Exception as e:
        # Catch any other unexpected errors
        logger.error(f"Unexpected error during /api/check for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback() # Attempt rollback on any error
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
    request_start_time = time.time()
    logger.info(f"Received /api/report request") # Avoid logging full body initially for privacy

    if not request.is_json:
        logger.warning("/api/report: Request content type is not JSON.")
        return jsonify(error="Request must be JSON"), 415

    data = request.json
    item_type = data.get('type')
    value = data.get('value')
    reason = data.get('reason') # Optional
    source = data.get('source', 'unknown') # Optional with default

    # --- Input Validation ---
    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/report: Invalid or missing 'type': {item_type}")
        return jsonify(error=f"Invalid or missing 'type'. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    if not value:
        logger.warning("/api/report: Missing 'value'.")
        return jsonify(error="Missing 'value' parameter."), 400

    # --- Normalization ---
    normalized_value = None
    if item_type == 'domain':
        normalized_value = normalize_domain(value)
        if not normalized_value:
            logger.warning(f"/api/report: Invalid domain format for report: {value}")
            return jsonify(error=f"Invalid domain format for report: {value}"), 400
    elif item_type == 'email':
        if not is_valid_email(value):
            logger.warning(f"/api/report: Invalid email format for report: {value}")
            return jsonify(error=f"Invalid email format for report: {value}"), 400
        normalized_value = value.lower()

    # Log processed info
    logger.info(f"/api/report: Processing report for type='{item_type}', normalized_value='{normalized_value}', source='{source}'")


    try:
        # --- Check if Whitelisted ---
        whitelist_exists = db.session.query(
            exists().where(WhitelistedItem.item_type == item_type, func.lower(WhitelistedItem.value) == normalized_value)
        ).scalar()

        if whitelist_exists:
             logger.info(f"/api/report: Item '{normalized_value}' is whitelisted, report ignored.")
             processing_time = time.time() - request_start_time
             # Use 200 OK but indicate the reason it wasn't created
             return jsonify(message="Item is whitelisted and cannot be reported.", status="ignored_whitelisted", processing_time_ms=processing_time * 1000), 200

        # --- Check if Already Blocked ---
        Model = BlockedDomain if item_type == 'domain' else BlockedEmail
        value_column = BlockedDomain.domain_name if item_type == 'domain' else BlockedEmail.email_address
        block_exists = db.session.query(
             exists().where(value_column == normalized_value, Model.status == 'active')
        ).scalar()

        if block_exists:
             logger.info(f"/api/report: Item '{normalized_value}' is already actively blocked, report ignored.")
             processing_time = time.time() - request_start_time
             return jsonify(message="Item is already blocked.", status="ignored_already_blocked", processing_time_ms=processing_time * 1000), 200


        # --- Check if Pending Report Exists ---
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
            # 200 OK or 208 Already Reported might be suitable
            return jsonify(message="Report already exists and is pending review.", status="already_reported", processing_time_ms=processing_time * 1000), 200

        # --- Create New Report ---
        new_report = ReportedItem(
            item_type=item_type,
            value=normalized_value,
            reason=reason,
            source=source,
            status='pending' # Default status for new reports
        )
        db.session.add(new_report)
        db.session.commit() # Commit to get the ID and save

        logger.info(f"Successfully created report ID {new_report.id} for '{normalized_value}'.")
        processing_time = time.time() - request_start_time
        # Return 201 Created status
        return jsonify(
            message="Report submitted successfully.",
            report=new_report.to_dict(),
            processing_time_ms=processing_time * 1000
            ), 201

    except IntegrityError as e:
         # This might happen if a report is submitted concurrently after checks pass
         logger.warning(f"Database integrity error during /api/report for '{normalized_value}': {e.orig}")
         db.session.rollback()
         return jsonify(error="Report conflict, possibly submitted concurrently or already exists."), 409
    except SQLAlchemyError as e:
        logger.error(f"Database error during /api/report for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Database operation failed"), 500
    except Exception as e:
        logger.error(f"Unexpected error during /api/report for '{normalized_value}': {e}", exc_info=True)
        db.session.rollback()
        return jsonify(error="Internal server error"), 500

# Helper to get the latest timestamp for versioning
def get_latest_timestamp(model_class):
    latest_item = db.session.query(model_class).order_by(desc(model_class.added_at)).first()
    if latest_item and latest_item.added_at:
        # Return Unix timestamp (seconds since epoch)
        return latest_item.added_at.timestamp()
    return time.time() # Fallback to current time if no items or no timestamp

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """
    Retrieves the blocklist (domains or emails). Returns only the values.
    Query Parameters:
        type (str): 'domain' or 'email'. Required.
    Returns:
        JSON: {'items': [...], 'version': timestamp} or error.
    """
    request_start_time = time.time()
    logger.info(f"Received /api/blocklist request: {request.args}")
    item_type = request.args.get('type')

    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/blocklist: Invalid or missing 'type': {item_type}")
        return jsonify(error=f"Invalid or missing 'type'. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    logger.info(f"/api/blocklist: Processing type='{item_type}'")

    try:
        items = []
        version = time.time() # Default version to current time

        if item_type == 'domain':
            query = select(BlockedDomain.domain_name).where(BlockedDomain.status == 'active')
            items = db.session.execute(query).scalars().all()
            version = get_latest_timestamp(BlockedDomain)
        elif item_type == 'email':
            query = select(BlockedEmail.email_address).where(BlockedEmail.status == 'active')
            items = db.session.execute(query).scalars().all()
            version = get_latest_timestamp(BlockedEmail)

        processing_time = time.time() - request_start_time
        logger.info(f"/api/blocklist: Found {len(items)} active items for type='{item_type}'. Version: {version}")

        # Return structure expected by background.js cache update
        return jsonify(
            items=items,
            version=version, # Use latest timestamp as version
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
    Retrieves the whitelist (domains or emails). Returns only the values.
    Query Parameters:
        type (str): 'domain' or 'email'. Required.
    Returns:
        JSON: {'items': [...], 'version': timestamp} or error.
    """
    request_start_time = time.time()
    logger.info(f"Received /api/whitelist request: {request.args}")
    item_type = request.args.get('type')

    if not item_type or item_type not in ALLOWED_ITEM_TYPES:
        logger.warning(f"/api/whitelist: Invalid or missing 'type': {item_type}")
        return jsonify(error=f"Invalid or missing 'type'. Must be one of {ALLOWED_ITEM_TYPES}."), 400

    logger.info(f"/api/whitelist: Processing type='{item_type}'")

    try:
        # Use func.lower to ensure case-insensitive retrieval if needed,
        # but storing normalized values is generally better.
        query = select(WhitelistedItem.value).where(
            WhitelistedItem.item_type == item_type
        ) # No 'active' status for whitelist in this model

        items = db.session.execute(query).scalars().all()
        version = get_latest_timestamp(WhitelistedItem) # Version based on latest whitelist addition

        processing_time = time.time() - request_start_time
        logger.info(f"/api/whitelist: Found {len(items)} items for type='{item_type}'. Version: {version}")

        # Return structure expected by background.js cache update
        return jsonify(
            items=items,
            version=version,
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
    logger.info("Initializing database connection and checking tables...")
    max_retries = 5
    retry_delay = 5 # seconds
    for attempt in range(max_retries):
        try:
            # Test connection implicitly by getting inspector
            inspector = inspect(db.engine)
            existing_tables = inspector.get_table_names()
            logger.info(f"Database connection successful. Existing tables: {existing_tables}")

            required_tables = [
                BlockedDomain.__tablename__,
                BlockedEmail.__tablename__,
                ReportedItem.__tablename__,
                WhitelistedItem.__tablename__
            ]
            missing_tables = [tbl for tbl in required_tables if tbl not in existing_tables]

            if missing_tables:
                logger.info(f"Creating missing tables: {missing_tables}")
                # Create only the missing tables
                db.metadata.create_all(bind=db.engine, tables=[
                    db.metadata.tables[tbl] for tbl in missing_tables
                ])
                logger.info("Database tables created successfully.")
            else:
                logger.info("All required database tables already exist.")
            return # Success
        except SQLAlchemyError as e:
            logger.error(f"Database connection/initialization error (Attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.critical("CRITICAL: Database initialization failed after multiple retries.")
                # sys.exit(1) # Exit if DB connection fails critically after retries
                raise # Re-raise the last exception
        except Exception as e:
            logger.critical(f"CRITICAL: Unexpected error during database initialization: {e}", exc_info=True)
            # sys.exit(1) # Exit on unexpected critical error
            raise

# --- Main Execution ---
if __name__ == '__main__':
    # Initialize DB within app context AFTER app is created but BEFORE running
    with app.app_context():
        initialize_database()

    # Use PORT environment variable provided by Render/Heroku, default to 5001 for local dev
    port = int(os.environ.get("PORT", 5001))
    # Use debug=False for production/Render deployment
    # Use debug=True only for local development (enables auto-reload)
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    logger.info(f"Starting Flask server on http://0.0.0.0:{port} (Debug: {debug_mode})")
    # Use waitress or gunicorn for production deployments instead of app.run()
    # For Render, Procfile usually handles this (e.g., using gunicorn)
    app.run(host='0.0.0.0', port=port, debug=debug_mode)