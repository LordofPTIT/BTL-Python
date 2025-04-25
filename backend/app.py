import os
import re # Thư viện regex để kiểm tra email chặt chẽ hơn
import logging # Thêm logging chi tiết
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy
from urllib.parse import urlparse # Để chuẩn hóa domain/URL
from dotenv import load_dotenv

# --- Cấu hình Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Tải biến môi trường ---
load_dotenv()
logging.info("Đang tải biến môi trường...")

app = Flask(__name__)

# --- Cấu hình CORS ---
# Trong production, nên giới hạn origin cụ thể của extension
# Ví dụ: CORS(app, origins=["chrome-extension://your_extension_id_here"])
CORS(app)
logging.info("CORS được kích hoạt cho mọi nguồn (chỉ dành cho dev).")

# --- Cấu hình SQLAlchemy ---
db_url = os.getenv('DATABASE_URL')
if not db_url:
    logging.error("Biến môi trường DATABASE_URL chưa được thiết lập.")
    raise ValueError("DATABASE_URL environment variable not set.")

# Đảm bảo URL dùng driver psycopg2
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True, # Kiểm tra kết nối trước mỗi query
    "pool_recycle": 300,   # Tái sử dụng connection sau 5 phút
}

db = SQLAlchemy(app)
logging.info(f"Đã kết nối SQLAlchemy tới database (host: ***).") # Che host/port

# --- Định nghĩa Models (Ánh xạ tới bảng DB) ---
# (Giữ nguyên models từ phản hồi trước: BlockedDomain, BlockedEmail, UserReport, WhitelistedItem)
# ... (Thêm lại các class Model ở đây nếu cần thiết hoặc import từ file khác) ...
class BlockedDomain(db.Model):
    __tablename__ = 'blocked_domains'
    domain_id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.Text, unique=True, nullable=False, index=True)
    reason = db.Column(db.Text)
    source = db.Column(db.Text)
    reported_count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.TIMESTAMP(timezone=True), server_default=sqlalchemy.func.now())
    last_seen = db.Column(db.TIMESTAMP(timezone=True), server_default=sqlalchemy.func.now(), onupdate=sqlalchemy.func.now())
    status = db.Column(db.Text, default='active', index=True) # active, inactive, under_review

class BlockedEmail(db.Model):
    __tablename__ = 'blocked_emails'
    email_id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.Text, unique=True, nullable=False, index=True)
    reason = db.Column(db.Text)
    source = db.Column(db.Text)
    reported_count = db.Column(db.Integer, default=1)
    first_seen = db.Column(db.TIMESTAMP(timezone=True), server_default=sqlalchemy.func.now())
    last_seen = db.Column(db.TIMESTAMP(timezone=True), server_default=sqlalchemy.func.now(), onupdate=sqlalchemy.func.now())
    status = db.Column(db.Text, default='active', index=True)

class UserReport(db.Model):
    __tablename__ = 'user_reports'
    report_id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.Text, nullable=False) # 'domain', 'email', 'url', 'text_selection', 'false_positive_domain', 'false_positive_email'
    value = db.Column(db.Text, nullable=False)
    context = db.Column(db.Text)
    reporter_info = db.Column(db.Text)
    timestamp = db.Column(db.TIMESTAMP(timezone=True), server_default=sqlalchemy.func.now())
    status = db.Column(db.Text, default='pending', nullable=False, index=True) # pending, approved, rejected, investigated

class WhitelistedItem(db.Model):
     __tablename__ = 'whitelisted_items'
     item_id = db.Column(db.Integer, primary_key=True)
     item_type = db.Column(db.Text, nullable=False, index=True) # 'domain' or 'email'
     value = db.Column(db.Text, unique=True, nullable=False, index=True)
     reason = db.Column(db.Text)
     added_by = db.Column(db.Text) # 'Admin', 'System', 'User:<id>'
     timestamp = db.Column(db.TIMESTAMP(timezone=True), server_default=sqlalchemy.func.now())


# --- Helper Functions (Chuẩn hóa dữ liệu) ---
def normalize_domain_be(domain_or_url):
    if not domain_or_url or not isinstance(domain_or_url, str): return None
    try:
        domain_or_url = domain_or_url.strip().lower()
        # Bỏ schema nếu có
        if domain_or_url.startswith(('http://', 'https://')):
             hostname = urlparse(domain_or_url).hostname
        else:
             hostname = domain_or_url.split('/')[0] # Lấy phần trước dấu / đầu tiên

        if not hostname: return None

        # Bỏ port nếu có
        hostname = hostname.split(':')[0]

        # Bỏ www.
        if hostname.startswith('www.'):
            hostname = hostname[4:]

        # Kiểm tra ký tự hợp lệ cơ bản (a-z, 0-9, -, .)
        if not re.match(r'^[a-z0-9.-]+$', hostname):
             logging.warning(f"Domain chứa ký tự không hợp lệ sau chuẩn hóa: {hostname}")
             return None

        # Tránh domain chỉ có TLD hoặc trống
        if '.' not in hostname or hostname.startswith('.') or hostname.endswith('.'):
             logging.warning(f"Domain không hợp lệ sau chuẩn hóa: {hostname}")
             return None

        return hostname
    except Exception as e:
        logging.error(f"Lỗi khi chuẩn hóa domain/url '{domain_or_url}': {e}")
        return None

def normalize_email_be(email):
    if not email or not isinstance(email, str): return None
    try:
        normalized = email.strip().lower()
        # Regex chặt chẽ hơn để kiểm tra định dạng email
        email_regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
        if not re.fullmatch(email_regex, normalized):
            logging.warning(f"Địa chỉ email không hợp lệ: {normalized}")
            return None
        return normalized
    except Exception as e:
        logging.error(f"Lỗi khi chuẩn hóa email '{email}': {e}")
        return None

# --- API Endpoints ---

@app.route('/api/check', methods=['GET'])
def check_item():
    """
    Kiểm tra xem một domain hoặc email có nằm trong danh sách chặn không.
    Ưu tiên kiểm tra whitelist trước.
    Params:
        type (str): 'domain' hoặc 'email'
        value (str): Giá trị cần kiểm tra
    Returns:
        JSON: { isPhishing: bool, reason: str }
    """
    item_type = request.args.get('type')
    value = request.args.get('value')
    start_time = datetime.time.time()

    if not item_type or not value:
        logging.warning(f"/check - Thiếu tham số: type={item_type}, value={value}")
        return jsonify({"error": "Thiếu tham số 'type' hoặc 'value'"}), 400

    normalized_value = None
    Model = None
    query_column = None

    if item_type == 'domain':
        normalized_value = normalize_domain_be(value)
        Model = BlockedDomain
        query_column = BlockedDomain.domain_name
    elif item_type == 'email':
        normalized_value = normalize_email_be(value)
        Model = BlockedEmail
        query_column = BlockedEmail.email_address
    else:
        logging.warning(f"/check - Loại không hợp lệ: type={item_type}")
        return jsonify({"error": "Tham số 'type' không hợp lệ. Chỉ chấp nhận 'domain' hoặc 'email'."}), 400

    if not normalized_value:
         logging.warning(f"/check - Giá trị không hợp lệ hoặc không chuẩn hóa được: type={item_type}, value='{value}'")
         # Trả về an toàn nếu input không hợp lệ
         return jsonify({"isPhishing": False, "reason": "Giá trị cung cấp không hợp lệ"}), 200

    is_phishing = False
    reason = "An toàn"
    status_code = 200

    try:
        # 1. Kiểm tra Whitelist
        whitelisted = db.session.query(WhitelistedItem.reason).filter_by(item_type=item_type, value=normalized_value).first()
        if whitelisted:
            reason = f"Đã được whitelist: {whitelisted.reason or 'Người dùng/Admin thêm'}"
            logging.info(f"/check - Whitelisted: {item_type}={normalized_value}, reason={reason}")
            return jsonify({"isPhishing": False, "reason": reason}), status_code

        # 2. Kiểm tra Blocklist (chỉ các bản ghi 'active')
        blocked = db.session.query(Model.reason).filter(query_column == normalized_value, Model.status == 'active').first()
        if blocked:
            is_phishing = True
            reason = blocked.reason or "Nằm trong danh sách chặn"
            logging.warning(f"/check - BLOCKED: {item_type}={normalized_value}, reason={reason}")
        # else:
        #     logging.debug(f"/check - Safe: {item_type}={normalized_value}")

    except sqlalchemy.exc.SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"/check - Lỗi DB khi kiểm tra {item_type}='{normalized_value}': {e}", exc_info=True)
        is_phishing = False # An toàn nếu không kiểm tra được
        reason = "Lỗi truy vấn cơ sở dữ liệu"
        status_code = 503 # Service Unavailable (Database error)
    except Exception as e:
        logging.error(f"/check - Lỗi không xác định khi kiểm tra {item_type}='{normalized_value}': {e}", exc_info=True)
        is_phishing = False
        reason = "Lỗi máy chủ không xác định"
        status_code = 500

    processing_time = (datetime.time.time() - start_time) * 1000
    logging.info(f"/check - Result: {item_type}={normalized_value}, isPhishing={is_phishing}, time={processing_time:.2f}ms")
    return jsonify({"isPhishing": is_phishing, "reason": reason}), status_code


@app.route('/api/report', methods=['POST'])
def report_item():
    """
    Nhận báo cáo từ người dùng và lưu vào database để kiểm duyệt.
    Body (JSON):
        type (str): 'domain', 'email', 'url', 'text_selection', 'false_positive_domain', 'false_positive_email'
        value (str): Giá trị được báo cáo
        context (str, optional): Ngữ cảnh báo cáo (URL trang, tiêu đề email...)
    Returns:
        JSON: { success: bool, message: str }
    """
    global potential_domain
    start_time = datetime.time.time()
    if not request.is_json:
        return jsonify({"success": False, "message": "Yêu cầu phải là JSON."}), 415

    data = request.json
    report_type = data.get('type')
    value = data.get('value')
    context = data.get('context', None)
    # Lấy thông tin định danh an toàn hơn (ví dụ: hash của IP + User Agent)
    # Hoặc yêu cầu API key từ extension
    reporter_info = f"UA:{request.headers.get('User-Agent', 'N/A')}" # Ví dụ đơn giản

    if not report_type or not value or not isinstance(value, str):
        logging.warning(f"/report - Thiếu hoặc sai kiểu dữ liệu: type={report_type}, value={value}")
        return jsonify({"success": False, "message": "Thiếu 'type' hoặc 'value', hoặc 'value' không phải là chuỗi."}), 400

    # Chuẩn hóa giá trị tùy theo loại báo cáo
    normalized_value = None
    is_false_positive = report_type.startswith('false_positive')
    blocklist_type = None # Loại để cập nhật blocklist (nếu là báo cáo lừa đảo)

    if report_type in ['domain', 'false_positive_domain']:
        normalized_value = normalize_domain_be(value)
        blocklist_type = 'domain'
    elif report_type in ['email', 'false_positive_email']:
        normalized_value = normalize_email_be(value)
        blocklist_type = 'email'
    elif report_type == 'url':
        normalized_value = value.strip() # Giữ nguyên URL nhưng trim()
        # Có thể thử chuẩn hóa domain từ URL để lưu thêm
        potential_domain = normalize_domain_be(value)
        if potential_domain:
             context = f"{context or ''} (Domain: {potential_domain})" # Thêm domain vào context
             blocklist_type = 'domain' # Có thể báo cáo domain liên quan
             # value_to_update_blocklist = potential_domain # Cân nhắc cập nhật blocklist domain
    elif report_type == 'text_selection':
        normalized_value = value.strip()[:1000] # Giới hạn độ dài text
    else:
        logging.warning(f"/report - Loại báo cáo không được hỗ trợ: {report_type}")
        return jsonify({"success": False, "message": f"Loại báo cáo '{report_type}' không được hỗ trợ."}), 400

    if not normalized_value:
         logging.warning(f"/report - Giá trị không hợp lệ sau chuẩn hóa: type={report_type}, original_value='{value}'")
         return jsonify({"success": False, "message": "Giá trị báo cáo không hợp lệ hoặc không thể chuẩn hóa."}), 400

    try:
        # 1. Lưu báo cáo vào bảng user_reports
        new_report = UserReport(
            report_type=report_type,
            value=normalized_value,
            context=context,
            reporter_info=reporter_info,
            status='pending' # Luôn chờ duyệt
        )
        db.session.add(new_report)
        logging.info(f"/report - Received: type={report_type}, value='{normalized_value}', status=pending")

        # 2. Xử lý logic tức thì (nếu có) - Ví dụ: tăng count, đánh dấu cần review
        # Chỉ xử lý nếu không phải báo cáo false positive
        if blocklist_type and not is_false_positive:
            Model = BlockedDomain if blocklist_type == 'domain' else BlockedEmail
            query_column = Model.domain_name if blocklist_type == 'domain' else Model.email_address
            # Sử dụng giá trị đã chuẩn hóa phù hợp (domain từ URL hoặc domain/email gốc)
            value_for_blocklist = normalized_value if report_type in ['domain', 'email'] else (potential_domain if report_type == 'url' and potential_domain else None)

            if value_for_blocklist:
                existing_block = db.session.query(Model).filter(query_column == value_for_blocklist).first()
                if existing_block:
                    existing_block.reported_count = (existing_block.reported_count or 0) + 1
                    existing_block.last_seen = sqlalchemy.func.now()
                    # Nếu đang inactive, chuyển sang under_review để admin xem xét lại
                    if existing_block.status == 'inactive':
                        existing_block.status = 'under_review'
                    logging.info(f"/report - Updated count/status for existing blocked {blocklist_type}: '{value_for_blocklist}'")
                else:
                    # Thêm mới với trạng thái under_review để admin duyệt trước khi active
                    new_blocked = Model(
                        **{query_column.key: value_for_blocklist}, # Sử dụng key của column
                        source='Extension Report',
                        reason='User Reported - Pending Review',
                        status='under_review' # Chờ admin duyệt
                    )
                    db.session.add(new_blocked)
                    logging.info(f"/report - Added new {blocklist_type} for review: '{value_for_blocklist}'")

        # Commit tất cả thay đổi
        db.session.commit()
        processing_time = (datetime.time.time() - start_time) * 1000
        logging.info(f"/report - Saved successfully, time={processing_time:.2f}ms")
        return jsonify({"success": True, "message": "Đã nhận báo cáo, cảm ơn sự đóng góp của bạn!"})

    except sqlalchemy.exc.SQLAlchemyError as e:
        db.session.rollback()
        logging.error(f"/report - Lỗi DB khi lưu báo cáo {report_type}='{normalized_value}': {e}", exc_info=True)
        return jsonify({"success": False, "message": "Lỗi cơ sở dữ liệu khi lưu báo cáo."}), 503
    except Exception as e:
        db.session.rollback()
        logging.error(f"/report - Lỗi không xác định khi lưu báo cáo {report_type}='{normalized_value}': {e}", exc_info=True)
        return jsonify({"success": False, "message": "Lỗi máy chủ không xác định khi lưu báo cáo."}), 500

@app.route('/api/blocklist', methods=['GET'])
def get_blocklist():
    """
    Cung cấp danh sách các domain/email đang bị chặn (active).
    Hỗ trợ tham số 'since' để lấy cập nhật delta (tùy chọn nâng cao).
    Params:
        type (str): 'domain' hoặc 'email'
        since (int, optional): Timestamp (epoch seconds) hoặc version ID để lấy thay đổi.
    Returns:
        JSON: { version: int, request_since: int, domains/emails: list[str] }
              Hoặc 304 Not Modified nếu không có thay đổi.
    """
    start_time = datetime.time.time()
    item_type = request.args.get('type')
    try:
        # Lấy version client gửi lên (nếu có)
        since_version = int(request.args.get('since', 0))
    except ValueError:
        since_version = 0

    Model = None
    list_key = None
    query_column = None

    if item_type == 'domain':
        Model = BlockedDomain
        list_key = 'domains'
        query_column = BlockedDomain.domain_name
    elif item_type == 'email':
        Model = BlockedEmail
        list_key = 'emails'
        query_column = BlockedEmail.email_address
    else:
        logging.warning(f"/blocklist - Loại không hợp lệ: {item_type}")
        return jsonify({"error": "Tham số 'type' không hợp lệ"}), 400

    try:
        # Lấy version mới nhất (ví dụ: timestamp của lần cập nhật cuối cùng)
        # Cách đơn giản: Dùng timestamp hiện tại. Nâng cao: Quản lý version trong DB.
        latest_update_time = db.session.query(sqlalchemy.func.max(Model.last_seen)).filter(Model.status == 'active').scalar()
        current_version = int(latest_update_time.timestamp()) if latest_update_time else int(datetime.time.time())

        # --- Logic kiểm tra version (đơn giản) ---
        # Nếu client đã có version mới nhất, trả về 304
        # Lưu ý: Cần cơ chế versioning chính xác hơn trong production
        if since_version != 0 and since_version >= current_version:
             logging.info(f"/blocklist - No changes ({item_type}) since version {since_version}. Returning 304.")
             # Trả về 304 Not Modified (Flask không có cách trực tiếp, trả về response rỗng với status 304)
             return '', 304 # Client sẽ không cập nhật cache

        # --- Lấy danh sách active items ---
        # Trong production thực tế với lượng dữ liệu lớn, nên lấy delta dựa trên `since_version`
        # Ví dụ: .filter(Model.last_seen > datetime.fromtimestamp(since_version, timezone.utc))
        active_items_query = db.session.query(query_column).filter(Model.status == 'active')
        active_items = active_items_query.all()
        data_list = [item[0] for item in active_items] # Chuyển tuple thành list string

        response_data = {
            "version": current_version,
            "request_since": since_version, # Echo lại để client biết server xử lý version nào
            list_key: data_list
        }
        processing_time = (datetime.time.time() - start_time) * 1000
        logging.info(f"/blocklist - Returned {len(data_list)} active {item_type}s, version={current_version}, time={processing_time:.2f}ms")
        return jsonify(response_data)

    except sqlalchemy.exc.SQLAlchemyError as e:
        logging.error(f"/blocklist - Lỗi DB khi lấy {item_type}: {e}", exc_info=True)
        return jsonify({"error": f"Lỗi cơ sở dữ liệu khi lấy danh sách {item_type}"}), 503
    except Exception as e:
        logging.error(f"/blocklist - Lỗi không xác định khi lấy {item_type}: {e}", exc_info=True)
        return jsonify({"error": f"Lỗi máy chủ không xác định khi lấy danh sách {item_type}"}), 500

# --- Endpoint kiểm tra sức khỏe API ---
@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Kiểm tra kết nối DB cơ bản
        db.session.execute(sqlalchemy.text('SELECT 1'))
        logging.debug("/health - OK")
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        logging.error(f"/health - Database connection failed: {e}")
        return jsonify({"status": "unhealthy", "database": "disconnected", "error": str(e)}), 503


# --- Khởi tạo DB nếu chạy lần đầu (chỉ dùng cho dev) ---
# Nên dùng Alembic hoặc Flask-Migrate để quản lý migration trong production
def initialize_database():
    with app.app_context():
        logging.info("Kiểm tra và khởi tạo Schema Database nếu cần...")
        try:
            db.create_all()
            logging.info("Database schema đã được kiểm tra/tạo.")
            # Thêm dữ liệu mẫu nếu cần cho dev
            # seed_database()
        except Exception as e:
            logging.error(f"Lỗi khi khởi tạo database: {e}", exc_info=True)

# def seed_database():
#     # Chỉ chạy nếu DB trống
#     if not BlockedDomain.query.first() and not BlockedEmail.query.first():
#         logging.info("Seeding database with initial data...")
#         try:
#             # Thêm domain mẫu
#             domains = [
#                 BlockedDomain(domain_name='example-phishing-1.com', reason='Known Phishing Source A', source='SeedData', status='active'),
#                 BlockedDomain(domain_name='bank-update-required.net', reason='Reported Malicious', source='SeedData', status='active'),
#                 BlockedDomain(domain_name='inactive-phish.org', reason='Old source', source='SeedData', status='inactive'),
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
#              ]
#             db.session.add_all(whitelists)

#             db.session.commit()
#             logging.info("Database seeded successfully.")
#         except exc.SQLAlchemyError as e:
#              db.session.rollback()
#              logging.error(f"Error seeding database: {e}")
#         except Exception as e:
#              db.session.rollback()
#              logging.error(f"Unexpected error seeding database: {e}")

if __name__ == '__main__':
    initialize_database() # Chạy kiểm tra/tạo DB khi start server dev
    # Chạy Flask development server (KHÔNG DÙNG CHO PRODUCTION)
    # Trong production, dùng: gunicorn --bind 0.0.0.0:5001 app:app -w 4 --log-level info
    logging.info("Khởi chạy Flask development server trên cổng 5001...")
    app.run(host='0.0.0.0', port=5001, debug=False) # Đặt debug=False ngay cả trong dev để tránh lỗi reload SQLAlchemy