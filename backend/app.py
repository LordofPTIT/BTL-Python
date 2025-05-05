import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, unquote # Added unquote

import logger
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, exists, func, inspect, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
# Optional: For database migrations
# from flask_migrate import Migrate

# --- Constants ---
ALLOWED_ITEM_TYPES = {'domain', 'email'}
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
DEFAULT_PAGE = 1
DEFAULT_PER_PAGE = 1000 # Increase default per page for local cache fetching

# --- Configuration ---
# CHANGE: Use SQLite for local database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_FILE = 'local_phishing_guard.db'
DATABASE_URI = f'sqlite:///{os.path.join(BASE_DIR, DATABASE_FILE)}'

app = Flask(__name__)
# CHANGE: Configure Flask app for SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False # Set to True for debugging SQL queries

# CHANGE: Enable CORS for local extension access (adjust origin if needed)
CORS(app, resources={r"/api/*": {"origins": "chrome-extension://*"}}) # Be more specific if you know your extension ID

db = SQLAlchemy(app)
# Optional: Initialize Flask-Migrate
# migrate = Migrate(app, db)

# --- Create Tables ---
# Thêm đoạn này: Đảm bảo các bảng được tạo trong context của ứng dụng
with app.app_context():
    db.create_all()
    logger.info("Database tables checked/created.")

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Database Models ---
# Simple version tracking table (can be expanded)
class DataVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_type = db.Column(db.String(50), unique=True, nullable=False) # e.g., 'phishing_domains', 'whitelist_emails'
    version = db.Column(db.String(100), nullable=False, default=lambda: str(time.time())) # Use timestamp as simple version
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Blocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(10), nullable=False, index=True) # 'domain' or 'email'
    value = db.Column(db.String(255), nullable=False, unique=True, index=True)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)
    # Add version tracking? Could get complex. Simplest is to update DataVersion table on change.

    def __repr__(self):
        return f'<Blocklist {self.item_type}:{self.value}>'

class Whitelist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(10), nullable=False, index=True) # 'domain' or 'email'
    value = db.Column(db.String(255), nullable=False, unique=True, index=True)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Whitelist {self.item_type}:{self.value}>'

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(50), nullable=False) # Allow 'false_positive_domain' etc.
    value = db.Column(db.String(255), nullable=False, index=True)
    reason = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(100), nullable=True) # e.g., 'chrome_extension'
    reported_on = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='received') # e.g., 'received', 'investigating', 'confirmed_phishing', 'rejected'

    def __repr__(self):
        return f'<Report {self.item_type}:{self.value} ({self.status})>'

# --- Helper Functions ---

def get_data_version(data_type):
    """Gets the current version string for a given data type."""
    version_entry = db.session.execute(select(DataVersion).filter_by(data_type=data_type)).scalar_one_or_none()
    if version_entry:
        return version_entry.version
    return "0" # Default initial version if not found

def update_data_version(data_type):
    """Updates the version string for a given data type to the current timestamp."""
    try:
        version_entry = db.session.execute(select(DataVersion).filter_by(data_type=data_type)).scalar_one_or_none()
        new_version = str(time.time())
        if version_entry:
            version_entry.version = new_version
            version_entry.last_updated = datetime.utcnow()
            logger.info(f"Updating version for {data_type} to {new_version}")
        else:
            version_entry = DataVersion(data_type=data_type, version=new_version)
            db.session.add(version_entry)
            logger.info(f"Creating initial version for {data_type}: {new_version}")
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error updating data version for {data_type}: {e}")

def normalize_domain_backend(url_or_domain):
    """Normalizes a URL or domain name for database storage/lookup."""
    if not url_or_domain or not isinstance(url_or_domain, str):
        return None
    try:
        # Handle potential full URLs first
        if '://' in url_or_domain:
            parsed = urlparse(url_or_domain)
            hostname = parsed.hostname
        else:
            hostname = url_or_domain # Assume it's already a domain/hostname

        if not hostname: return None

        # Basic cleanup
        hostname = hostname.lower().strip()
        # Remove www. prefix
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        # Remove trailing dot
        if hostname.endswith('.'):
            hostname = hostname[:-1]

        # Basic IP address check (optional, adjust if needed)
        if re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
            return None # Don't treat IPs as domains for typical phishing lists

        # Add more sophisticated checks if needed (e.g., Punycode, valid TLDs)
        if '.' not in hostname: # Basic check for a TLD separator
             return None

        return hostname
    except Exception as e:
        logger.warning(f"Could not normalize domain '{url_or_domain}': {e}")
        return None

def normalize_email_backend(email):
    """Validates and normalizes an email address."""
    if not email or not isinstance(email, str):
        return None
    email = email.lower().strip()
    if re.fullmatch(EMAIL_REGEX, email):
        return email
    logger.warning(f"Invalid email format: {email}")
    return None

def add_to_list(list_model, item_type, value, skip_normalization=False):
    """Adds an item to the specified list (Blocklist or Whitelist)."""
    if item_type not in ALLOWED_ITEM_TYPES:
        return False, "Invalid item type"

    normalized_value = value # Assume pre-normalized if skip_normalization is True
    if not skip_normalization:
        if item_type == 'domain':
            normalized_value = normalize_domain_backend(value)
        elif item_type == 'email':
            normalized_value = normalize_email_backend(value)

    if not normalized_value:
        return False, f"Invalid {item_type} value: {value}"

    try:
        # Check if exists
        exists_query = select(exists().where(list_model.value == normalized_value))
        item_exists = db.session.execute(exists_query).scalar()

        if item_exists:
            logger.info(f"{normalized_value} already exists in {list_model.__name__}.")
            return True, f"Item already exists in {list_model.__name__}"

        # Add new item
        new_item = list_model(item_type=item_type, value=normalized_value)
        db.session.add(new_item)
        db.session.commit()
        logger.info(f"Added '{normalized_value}' to {list_model.__name__}.")

        # CHANGE: Update the version after successful addition
        data_type_key = f"{list_model.__name__.lower()}_{item_type}s" # e.g., blocklist_domains
        update_data_version(data_type_key)

        return True, f"Successfully added to {list_model.__name__}"
    except IntegrityError: # Catch potential race conditions if unique constraint fails
        db.session.rollback()
        logger.warning(f"Integrity error (likely race condition) adding '{normalized_value}' to {list_model.__name__}.")
        return True, f"Item likely already exists (IntegrityError)" # Treat as success if it exists
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error adding '{normalized_value}' to {list_model.__name__}: {e}")
        return False, "Database error"

# --- API Endpoints ---

@app.route('/api/status', methods=['GET'])
def api_status():
    """Simple endpoint to check if the API is running."""
    logger.info("API status check requested.")
    # Check DB connection
    db_status = "disconnected"
    try:
        # Try a simple query
        db.session.execute(select(1))
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")

    return jsonify({
        "status": "ok",
        "message": "Phishing Guard Local API is running.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database_status": db_status
    }), 200

# --- Blocklist Endpoints ---

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """Returns the blocklist items (domains or emails)."""
    item_type = request.args.get('type', 'domain').lower() # Default to domain
    if item_type not in ALLOWED_ITEM_TYPES:
        return jsonify({"error": "Invalid type parameter. Use 'domain' or 'email'."}), 400

    page = request.args.get('page', DEFAULT_PAGE, type=int)
    per_page = request.args.get('per_page', DEFAULT_PER_PAGE, type=int)

    try:
        # Query items
        paginated_query = db.session.execute(
            select(Blocklist.value)
            .filter_by(item_type=item_type)
            .order_by(Blocklist.id) # Or value?
            .limit(per_page)
            .offset((page - 1) * per_page)
        )
        items = [row[0] for row in paginated_query]

        # Get total count for pagination info (optional)
        # total_count = db.session.execute(select(func.count(Blocklist.id)).filter_by(item_type=item_type)).scalar_one()

        # Get current version for this list type
        data_type_key = f"blocklist_{item_type}s"
        current_version = get_data_version(data_type_key)

        logger.info(f"Returning {len(items)} blocklisted {item_type}s (Version: {current_version})")
        return jsonify({
            "items": items,
            "version": current_version,
            "type": item_type,
            # "page": page,
            # "per_page": per_page,
            # "total_items": total_count
        }), 200
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching blocklist ({item_type}): {e}")
        return jsonify({"error": "Database error fetching blocklist."}), 500

@app.route('/api/blocklist/add', methods=['POST'])
def add_blocklist_item():
    """Adds a new item to the blocklist."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload."}), 400

    item_type = data.get('type', '').lower()
    value = data.get('value', '')

    if not item_type or not value:
        return jsonify({"error": "Missing 'type' or 'value' in payload."}), 400

    success, message = add_to_list(Blocklist, item_type, value)

    if success:
        return jsonify({"message": message}), 201 # 201 Created or 200 OK if already exists
    else:
        return jsonify({"error": message}), 400 # Or 500 for database errors

# --- Whitelist Endpoints ---

@app.route('/api/whitelist', methods=['GET'])
def get_whitelist():
    """Returns the whitelist items (domains or emails)."""
    item_type = request.args.get('type', 'domain').lower()
    if item_type not in ALLOWED_ITEM_TYPES:
        return jsonify({"error": "Invalid type parameter. Use 'domain' or 'email'."}), 400

    page = request.args.get('page', DEFAULT_PAGE, type=int)
    per_page = request.args.get('per_page', DEFAULT_PER_PAGE, type=int)

    try:
        paginated_query = db.session.execute(
            select(Whitelist.value)
            .filter_by(item_type=item_type)
            .order_by(Whitelist.id)
            .limit(per_page)
            .offset((page - 1) * per_page)
        )
        items = [row[0] for row in paginated_query]

        # Get current version
        data_type_key = f"whitelist_{item_type}s"
        current_version = get_data_version(data_type_key)

        logger.info(f"Returning {len(items)} whitelisted {item_type}s (Version: {current_version})")
        return jsonify({
            "items": items,
            "version": current_version,
            "type": item_type,
            # "page": page,
            # "per_page": per_page,
        }), 200
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching whitelist ({item_type}): {e}")
        return jsonify({"error": "Database error fetching whitelist."}), 500

@app.route('/api/whitelist/add', methods=['POST'])
def add_whitelist_item():
    """Adds a new item to the whitelist."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload."}), 400

    item_type = data.get('type', '').lower()
    value = data.get('value', '')

    if not item_type or not value:
        return jsonify({"error": "Missing 'type' or 'value' in payload."}), 400

    success, message = add_to_list(Whitelist, item_type, value)

    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400

# --- Check Endpoint ---

@app.route('/api/check', methods=['GET'])
def check_item():
    """Checks if a domain or email is blocklisted, whitelisted, or safe."""
    item_type = request.args.get('type', '').lower()
    value = request.args.get('value', '')

    # FIX: Decode URL-encoded values from query parameters
    value = unquote(value)

    if item_type not in ALLOWED_ITEM_TYPES:
        return jsonify({"status": "error", "error": "Invalid type parameter."}), 400
    if not value:
        return jsonify({"status": "error", "error": "Missing value parameter."}), 400

    normalized_value = None
    if item_type == 'domain':
        normalized_value = normalize_domain_backend(value)
    elif item_type == 'email':
        normalized_value = normalize_email_backend(value)

    if not normalized_value:
        logger.warning(f"Check request for invalid {item_type}: '{value}'")
        return jsonify({"status": "error", "error": f"Invalid {item_type} format."}), 400

    logger.info(f"Checking {item_type}: '{normalized_value}' (Original: '{value}')")

    try:
        # 1. Check Whitelist first
        is_whitelisted = db.session.execute(
            select(exists().where(Whitelist.item_type == item_type, Whitelist.value == normalized_value))
        ).scalar()

        if is_whitelisted:
            logger.info(f"'{normalized_value}' is whitelisted.")
            return jsonify({"status": "whitelisted", "value": normalized_value, "type": item_type}), 200

        # 2. Check Blocklist
        is_blocklisted = db.session.execute(
            select(exists().where(Blocklist.item_type == item_type, Blocklist.value == normalized_value))
        ).scalar()

        if is_blocklisted:
            logger.info(f"'{normalized_value}' is blocklisted.")
            # Optionally add details about why it's blocked if available
            return jsonify({"status": "blocked", "value": normalized_value, "type": item_type}), 200

        # 3. If not in either list, it's considered safe by the lists
        logger.info(f"'{normalized_value}' is not in blocklist or whitelist.")
        return jsonify({"status": "safe", "value": normalized_value, "type": item_type}), 200

    except SQLAlchemyError as e:
        logger.error(f"Database error checking {item_type} '{normalized_value}': {e}")
        # Fallback: return 'safe' on DB error? Or a specific error status?
        # Returning 'error' is safer to indicate the check couldn't be completed reliably.
        return jsonify({"status": "error", "error": "Database check failed."}), 500


# --- Report Endpoint ---

@app.route('/api/report', methods=['POST'])
def report_item():
    """Receives reports from the extension."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload."}), 400

    report_type = data.get('type', '').lower() # e.g., 'domain', 'email', 'false_positive_domain'
    value = data.get('value', '')
    reason = data.get('reason', '')
    source = data.get('source', 'unknown')

    # Basic validation
    original_type = report_type.replace('false_positive_', '') # Get base type
    if original_type not in ALLOWED_ITEM_TYPES and report_type != 'content_keyword': # Allow a new type for keyword reports
        return jsonify({"error": f"Invalid report type: {report_type}"}), 400
    if not value:
        return jsonify({"error": "Missing 'value' in report payload."}), 400

    # Normalize value based on original type for consistency in reports table (optional)
    normalized_value = value
    if original_type == 'domain':
        normalized_value = normalize_domain_backend(value) or value # Keep original if normalization fails
    elif original_type == 'email':
        normalized_value = normalize_email_backend(value) or value # Keep original if normalization fails

    logger.info(f"Received report: Type='{report_type}', Value='{normalized_value}', Reason='{reason}', Source='{source}'")

    try:
        new_report = Report(
            item_type=report_type,
            value=normalized_value, # Store normalized value
            reason=reason,
            source=source,
            status='received' # Initial status
        )
        db.session.add(new_report)
        db.session.commit()

        logger.info(f"Report ID {new_report.id} created successfully.")
        return jsonify({
            "message": "Report received successfully.",
            "status": "received",
            "report": { # Return some details of the created report
                "id": new_report.id,
                "type": new_report.item_type,
                "value": new_report.value,
                "status": new_report.status
            }
        }), 201 # 201 Created

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Database error saving report for '{normalized_value}': {e}")
        return jsonify({"error": "Failed to save report due to database error."}), 500


# --- Database Initialization ---
def init_db():
    """Initializes the database and creates tables if they don't exist."""
    with app.app_context():
        logger.info("Checking database tables...")
        inspector = inspect(db.engine)
        required_tables = [Blocklist.__tablename__, Whitelist.__tablename__, Report.__tablename__, DataVersion.__tablename__]

        existing_tables = inspector.get_table_names()
        tables_to_create = [table for table in required_tables if table not in existing_tables]

        if tables_to_create:
            logger.info(f"Creating missing tables: {', '.join(tables_to_create)}")
            # db.create_all() # This might try to create existing ones too depending on context
            # Create only the missing tables
            db.metadata.create_all(bind=db.engine, tables=[db.metadata.tables[name] for name in tables_to_create])
            logger.info("Database tables created/verified.")
        else:
            logger.info("All required database tables already exist.")

        # Optional: Seed initial data or versions if needed
        # Example: Ensure version records exist
        for list_type in ['blocklist', 'whitelist']:
            for item_type in ALLOWED_ITEM_TYPES:
                 data_type_key = f"{list_type}_{item_type}s"
                 if get_data_version(data_type_key) == "0": # If version doesn't exist
                      update_data_version(data_type_key) # Create initial version


# --- Main Execution ---
if __name__ == '__main__':
    init_db() # Initialize DB before starting the server
    logger.info(f"Starting Flask server for Phishing Guard Local API on port 5001...")
    # CHANGE: Run on 0.0.0.0 to be accessible from the extension (even locally)
    # Use port 5001 as specified in the original background script default URL
    app.run(host='0.0.0.0', port=5001, debug=True) # Enable debug for development