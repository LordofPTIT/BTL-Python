import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, exists, func, inspect, desc
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from dotenv import load_dotenv

load_dotenv()

ALLOWED_ITEM_TYPES = {'domain', 'email'}
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
DEFAULT_PAGE = 1
DEFAULT_PER_PAGE = 10000

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DEFAULT_DATABASE_FILE = 'local_phishing_guard.db'
DATABASE_URL_ENV = os.getenv('DATABASE_URL')

SQLALCHEMY_DATABASE_URI = DATABASE_URL_ENV if DATABASE_URL_ENV else f'sqlite:///{os.path.join(BASE_DIR, DEFAULT_DATABASE_FILE)}'
if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace("postgres://", "postgresql://", 1)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False

CORS(app, resources={r"/api/*": {"origins": "*"}})

db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_type = db.Column(db.String(50), unique=True, nullable=False)
    version = db.Column(db.String(100), nullable=False, default=lambda: str(time.time()))
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Blocklist(db.Model):
    __tablename__ = 'blocklist'
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(10), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False, unique=True, index=True)
    reason = db.Column(db.String(255), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='active', nullable=False, index=True)

class Whitelist(db.Model):
    __tablename__ = 'whitelist'
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(10), nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False, unique=True, index=True)
    reason = db.Column(db.String(255), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    item_type = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(255), nullable=False, index=True)
    reason = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(100), nullable=True)
    reported_on = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='received')

def get_data_version(data_type):
    version_entry = db.session.execute(select(DataVersion).filter_by(data_type=data_type)).scalar_one_or_none()
    return version_entry.version if version_entry else "0"

def update_data_version(data_type):
    try:
        version_entry = db.session.execute(select(DataVersion).filter_by(data_type=data_type)).scalar_one_or_none()
        new_version = str(time.time())
        if version_entry:
            version_entry.version = new_version
            version_entry.last_updated = datetime.utcnow()
        else:
            version_entry = DataVersion(data_type=data_type, version=new_version)
            db.session.add(version_entry)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error updating data version for {data_type}: {e}")

def normalize_domain_backend(url_or_domain):
    if not url_or_domain or not isinstance(url_or_domain, str): return None
    try:
        hostname = url_or_domain.lower().strip()
        if '://' in hostname: parsed = urlparse(hostname); hostname = parsed.hostname or ""
        if hostname.startswith('www.'): hostname = hostname[4:]
        if hostname.endswith('.'): hostname = hostname[:-1]
        if not hostname or re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) or ':' in hostname: return None
        if not re.fullmatch(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$", hostname): return None
        return hostname
    except Exception: return None

def normalize_email_backend(email):
    if not email or not isinstance(email, str): return None
    email_normalized = email.lower().strip()
    return email_normalized if re.fullmatch(EMAIL_REGEX, email_normalized) else None

def add_item_to_blocklist_from_report(item_type_to_add, value_to_add, report_source="user_report"):
    if item_type_to_add not in ALLOWED_ITEM_TYPES: return False, "Invalid item type"
    normalized_value = normalize_domain_backend(value_to_add) if item_type_to_add == 'domain' else normalize_email_backend(value_to_add)
    if not normalized_value: return False, f"Invalid {item_type_to_add} value: {value_to_add}"
    try:
        if db.session.execute(select(exists().where(Whitelist.item_type == item_type_to_add, Whitelist.value == normalized_value))).scalar():
            return False, f"Item '{normalized_value}' is whitelisted."
        existing_item = db.session.execute(select(Blocklist).where(Blocklist.item_type == item_type_to_add, Blocklist.value == normalized_value)).scalar_one_or_none()
        if existing_item:
            if existing_item.status != 'active': existing_item.status = 'active'
            if report_source not in (existing_item.source or ""): existing_item.source = f"{existing_item.source or ''};{report_source}".strip(';')
            db.session.commit(); update_data_version(f"blocklist_{item_type_to_add}s")
            return True, f"Item '{normalized_value}' already in blocklist, updated."
        new_item = Blocklist(item_type=item_type_to_add, value=normalized_value, source=report_source, status='active')
        db.session.add(new_item); db.session.commit(); update_data_version(f"blocklist_{item_type_to_add}s")
        return True, f"Successfully added '{normalized_value}' to blocklist."
    except IntegrityError: db.session.rollback(); return True, f"Item '{normalized_value}' likely already exists (IntegrityError)"
    except SQLAlchemyError as e: db.session.rollback(); logger.error(f"DB error adding '{normalized_value}' to blocklist: {e}"); return False, "DB error adding to blocklist"

@app.route('/api/status', methods=['GET'])
def api_status():
    db_status = "disconnected"; db_uri_used = SQLALCHEMY_DATABASE_URI
    try: db.session.execute(select(1)); db_status = "connected"
    except Exception as e: logger.error(f"DB connection check failed: {e}")
    return jsonify({"status": "ok", "message": "API is running.", "database_status": db_status, "database_uri_used": db_uri_used}), 200

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist_items():
    item_type = request.args.get('type', 'domain').lower()
    if item_type not in ALLOWED_ITEM_TYPES: return jsonify({"error": "Invalid type."}), 400
    try:
        items = db.session.execute(select(Blocklist.value).filter_by(item_type=item_type, status='active').limit(DEFAULT_PER_PAGE)).scalars().all()
        return jsonify({"items": items, "version": get_data_version(f"blocklist_{item_type}s"), "type": item_type}), 200
    except SQLAlchemyError as e: logger.error(f"DB error blocklist ({item_type}): {e}"); return jsonify({"error": "DB error."}), 500

@app.route('/api/whitelist', methods=['GET'])
def get_whitelist_items():
    item_type = request.args.get('type', 'domain').lower()
    if item_type not in ALLOWED_ITEM_TYPES: return jsonify({"error": "Invalid type."}), 400
    try:
        items = db.session.execute(select(Whitelist.value).filter_by(item_type=item_type).limit(DEFAULT_PER_PAGE)).scalars().all()
        return jsonify({"items": items, "version": get_data_version(f"whitelist_{item_type}s"), "type": item_type}), 200
    except SQLAlchemyError as e: logger.error(f"DB error whitelist ({item_type}): {e}"); return jsonify({"error": "DB error."}), 500

@app.route('/api/check', methods=['GET'])
def check_item_status():
    item_type = request.args.get('type', '').lower()
    value = unquote(request.args.get('value', ''))
    if item_type not in ALLOWED_ITEM_TYPES or not value: return jsonify({"status": "error", "error": "Invalid params."}), 400
    normalized_value = normalize_domain_backend(value) if item_type == 'domain' else normalize_email_backend(value)
    if not normalized_value: return jsonify({"status": "safe", "reason": "Invalid format.", "type": item_type}), 200
    try:
        if db.session.execute(select(exists().where(Whitelist.item_type == item_type, Whitelist.value == normalized_value))).scalar():
            return jsonify({"status": "whitelisted", "value": normalized_value, "type": item_type}), 200
        block_query = select(Blocklist.reason, Blocklist.source).where(Blocklist.item_type == item_type, Blocklist.value == normalized_value, Blocklist.status == 'active')
        block_details = db.session.execute(block_query).first()
        if block_details:
            return jsonify({"status": "blocked", "value": normalized_value, "type": item_type, "details": dict(block_details._mapping) if block_details else {}}), 200
        return jsonify({"status": "safe", "value": normalized_value, "type": item_type}), 200
    except SQLAlchemyError as e: logger.error(f"DB error check {item_type} '{normalized_value}': {e}"); return jsonify({"status": "error", "error": "DB check failed."}), 500

@app.route('/api/report', methods=['POST'])
def report_item_api():
    data = request.get_json();
    if not data: return jsonify({"error": "Missing JSON."}), 400
    report_type_original = data.get('type', '').lower()
    value_original = data.get('value', '')
    reason = data.get('reason', '')
    source = data.get('source', 'chrome_extension')
    if report_type_original.startswith('false_positive_'):
        base_type_for_action = report_type_original.replace('false_positive_', '')
        if base_type_for_action not in ALLOWED_ITEM_TYPES:
            return jsonify({"error": f"Invalid report type: {report_type_original}"}), 400
        normalized_value = normalize_domain_backend(value_original) if base_type_for_action == 'domain' else normalize_email_backend(value_original)
        if not normalized_value:
            return jsonify({"error": f"Invalid {base_type_for_action} value: {value_original}"}), 400
        try:
            db.session.execute(db.delete(Blocklist).where(Blocklist.item_type == base_type_for_action, Blocklist.value == normalized_value))
            db.session.commit()
            update_data_version(f"blocklist_{base_type_for_action}s")
            return jsonify({"message": f"Đã xóa {base_type_for_action} {normalized_value} khỏi danh sách chặn."}), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"DB error removing {base_type_for_action} '{normalized_value}' from blocklist: {e}")
            return jsonify({"error": "Failed to remove from blocklist."}), 500
    if report_type_original in ALLOWED_ITEM_TYPES:
        normalized_value = normalize_domain_backend(value_original) if report_type_original == 'domain' else normalize_email_backend(value_original)
        if not normalized_value:
            return jsonify({"error": f"Invalid {report_type_original} value: {value_original}"}), 400
        try:
            exists_item = db.session.execute(select(Blocklist).where(Blocklist.item_type == report_type_original, Blocklist.value == normalized_value)).scalar_one_or_none()
            if not exists_item:
                db.session.add(Blocklist(item_type=report_type_original, value=normalized_value, status='active', source=source, reason=reason))
                db.session.commit()
                update_data_version(f"blocklist_{report_type_original}s")
                return jsonify({"message": f"Đã thêm {report_type_original} {normalized_value} vào danh sách chặn."}), 201
            else:
                return jsonify({"message": f"{report_type_original.capitalize()} {normalized_value} đã có trong danh sách chặn."}), 200
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"DB error adding {report_type_original} '{normalized_value}' to blocklist: {e}")
            return jsonify({"error": "Failed to add to blocklist."}), 500
    base_type_for_action = report_type_original.replace('false_positive_', '')
    if base_type_for_action not in ALLOWED_ITEM_TYPES and report_type_original != 'content_keyword':
        return jsonify({"error": f"Invalid report type: {report_type_original}"}), 400
    if not value_original: return jsonify({"error": "Missing 'value' in report."}), 400
    normalized_value = normalize_domain_backend(value_original) if base_type_for_action == 'domain' else normalize_email_backend(value_original) or value_original
    try:
        new_report = Report(item_type=report_type_original, value=normalized_value, reason=reason, source=source, status='received'); db.session.add(new_report); db.session.commit(); report_saved = True
        logger.info(f"Report ID {new_report.id} for '{normalized_value}' saved.")
    except SQLAlchemyError as e_report: db.session.rollback(); logger.error(f"DB error saving report for '{normalized_value}': {e_report}"); return jsonify({"error": "Failed to save report."}), 500
    blocklist_add_success = False; blocklist_add_message = ""
    if base_type_for_action in ALLOWED_ITEM_TYPES:
        try:
            if not db.session.execute(select(Blocklist).where(Blocklist.item_type == base_type_for_action, Blocklist.value == normalized_value)).scalar_one_or_none():
                db.session.add(Blocklist(item_type=base_type_for_action, value=normalized_value, status='active', source=source))
                db.session.commit()
                update_data_version(f"blocklist_{base_type_for_action}s")
                blocklist_add_success = True
                blocklist_add_message = f"Added '{normalized_value}' to blocklist."
            else:
                blocklist_add_success = True
                blocklist_add_message = f"'{normalized_value}' already in blocklist."
        except SQLAlchemyError as e:
            db.session.rollback(); blocklist_add_message = f"Error adding to blocklist: {e}"
    final_msg = "Report received." + (f" {blocklist_add_message}" if blocklist_add_message else "")
    return jsonify({"message": final_msg, "report_status": "saved", "blocklist_status": blocklist_add_message}), 201

@app.cli.command("init-db")
def init_db_command():
    db.create_all();
    with app.app_context():
        for list_t in ['blocklist', 'whitelist']:
            for item_t in ALLOWED_ITEM_TYPES:
                dt_k = f"{list_t}_{item_t}s";
                if get_data_version(dt_k) == "0": update_data_version(dt_k)
    logger.info("Initialized DB.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all(); logger.info(f"DB tables checked/created at {SQLALCHEMY_DATABASE_URI}")
        for list_type_n in ['blocklist', 'whitelist']:
            for item_type_n in ALLOWED_ITEM_TYPES:
                dt_k_n = f"{list_type_n}_{item_type_n}s";
                if not db.session.execute(select(DataVersion).filter_by(data_type=dt_k_n)).scalar_one_or_none(): update_data_version(dt_k_n)
        logger.info("DataVersion table checked/populated.")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=(os.getenv('FLASK_ENV') == 'development'))