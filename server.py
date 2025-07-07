from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timedelta
import os
import jwt
from functools import wraps
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import email configuration

try:
    from email_config import SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, EMAIL_USE_TLS, EMAIL_TIMEOUT
    print(f"Email configuration loaded from email_config.py")
except ImportError as e:
    # Default values if config file is missing
    print(f"Failed to import email_config.py: {e}")
    print("Using default email configuration values.")
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
    SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "")
    EMAIL_USE_TLS = True
    EMAIL_TIMEOUT = 30

app = Flask(__name__)
# Configure CORS to allow file:// origins and handle preflight requests properly
CORS(app, 
     supports_credentials=True, 
     resources={r"/api/*": {"origins": "*"}},
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

SECRET_KEY = os.environ.get('SECRET_KEY', 'aisat_registral_secret_key')

# Dictionary to store verification codes with timestamps
verification_codes = {}

# --- Static File Serving ---
# Serve files from the sideload directory (for the desktop app)
@app.route('/sideload/<path:filename>')
def serve_sideload(filename):
    return send_from_directory('sideload', filename)

# Serve files from the mobile directory and its subdirectories (css, js)
@app.route('/mobile/<path:path>')
def serve_mobile(path):
    return send_from_directory('mobile', path)

# Serve files from the img directory
@app.route('/img/<path:filename>')
def serve_images(filename):
    return send_from_directory('img', filename)
# -------------------------

DB_CONFIG = {
    "host": "jimboyaczon.mysql.pythonanywhere-services.com",
    "user": "jimboyaczon",
    "password": "fk9lratv",
    "database": "jimboyaczon$aisat-registral-db"
}


def get_db_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        
        if not token:
            return jsonify({"error": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token. Please log in again."}), 401
        except Exception as e:
            return jsonify({"error": f"Token validation error: {str(e)}"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    idno = data.get('idno')
    password = data.get('password')

    if not idno or not password:
        return jsonify({"error": "Missing credentials"}), 400

    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)

        # Admin login check should be prioritized for the admin panel.
        # Admin table uses id_no field
        cursor.execute("SELECT * FROM admins WHERE id_no = %s AND password = %s", (idno, password))
        admin = cursor.fetchone()

        if admin:
            # Found in the 'admins' table
            token = jwt.encode({
                'id': admin['id'],
                'name': admin['full_name'],
                'is_admin': True,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, SECRET_KEY, algorithm="HS256")
            return jsonify({
                'token': token,
                'is_admin': True,
                'name': admin['full_name']
            })

        # If not an admin, check for a standard user account
        # User table uses idno field
        cursor.execute("SELECT * FROM users WHERE idno = %s AND password = %s", (idno, password))
        user = cursor.fetchone()

        if user:
            # Found in the 'users' table (is not an admin)
            token = jwt.encode({
                'id': user['id'],
                'name': user['name'],
                'is_admin': False,
                'exp': datetime.utcnow() + timedelta(days=1)
            }, SECRET_KEY, algorithm="HS256")
            return jsonify({
                'token': token,
                'is_admin': False,
                'name': user['name']
            })

        # If we get here, the user was not found in either table
        return jsonify({"error": "Invalid credentials. Please verify your ID number and password."}), 401

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "An error occurred during login. Please try again."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/auth/register', methods=['POST'])
def register():
    """Public registration for new admin accounts."""
    data = request.get_json()
    fullname = data.get('full_name')
    idno = data.get('id_no')
    email = data.get('email')
    contact_no = data.get('contact_no')
    password = data.get('password')

    if not all([fullname, idno, email, password, contact_no]):
        return jsonify({"error": "Missing required fields"}), 400

    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM admins WHERE email = %s OR id_no = %s", (email, idno))
        if cursor.fetchone():
            return jsonify({"error": "Admin with this email or ID number already exists"}), 409

        # WARNING: Storing password in plaintext per user request.
        cursor.execute(
            "INSERT INTO admins (full_name, id_no, email, contact_no, password) VALUES (%s, %s, %s, %s, %s)",
            (fullname, idno, email, contact_no, password)
        )
        conn.commit()
        return jsonify({"message": "Admin registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_session():
    """Verify the current user's token and return their data."""
    # The @token_required decorator handles validation.
    # If we get here, the token is valid.
    return jsonify({
        "valid": True,
        "name": g.user.get('name'),
        "is_admin": g.user.get('is_admin')
    })

@app.route('/api/auth/register_user', methods=['POST'])
@token_required
def register_user_by_admin():
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    idno = data.get('idno')
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if not all([idno, name, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s OR idno = %s", (email, idno))
        if cursor.fetchone():
            return jsonify({"error": "User already exists"}), 409

        # WARNING: Storing password in plaintext per user request.
        cursor.execute(
            "INSERT INTO users (idno, name, email, password) VALUES (%s, %s, %s, %s)",
            (idno, name, email, password)
        )
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/pending_requests', methods=['GET'])
@token_required
def get_pending_requests():
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)
        # Use the actual field names from the schema
        cursor.execute("SELECT id, idno, name, email, level, method, payment, schedule, status, counter, request_id FROM users WHERE status IN ('pending', 'oncall') ORDER BY schedule ASC")
        users_raw = cursor.fetchall()
        
        # Manually build a new list of dictionaries to ensure data is clean for JSON
        users_processed = []
        for user_row in users_raw:
            processed_user = {
                "id": str(user_row["id"]) if user_row["id"] is not None else "",
                "idno": str(user_row["idno"]) if user_row["idno"] is not None else "",
                "name": str(user_row["name"]) if user_row["name"] is not None else "",
                "email": str(user_row["email"]) if user_row["email"] is not None else "",
                "level": str(user_row["level"]) if user_row["level"] is not None else "",
                "method": str(user_row["method"]) if user_row["method"] is not None else "",
                "payment": str(user_row["payment"]) if user_row["payment"] is not None else "",
                "status": str(user_row["status"]) if user_row["status"] is not None else "",
                "counter": int(user_row["counter"]) if user_row["counter"] is not None else None,
                "request_id": str(user_row["request_id"]) if user_row["request_id"] is not None else "",
                "schedule": None  # Default to None
            }
            
            # Handle datetime conversion safely
            schedule = user_row["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    processed_user['schedule'] = schedule.isoformat()
                else:
                    # Try to convert to string if it's not a datetime object
                    processed_user['schedule'] = str(schedule)
                    
            users_processed.append(processed_user)
            
        return jsonify(users_processed)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/rejected_requests', methods=['GET'])
@token_required
def get_rejected_requests():
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, idno, name, email, level, method, payment, schedule, status, request_id FROM users WHERE status = 'rejected' ORDER BY schedule DESC")
        users_raw = cursor.fetchall()
        
        users_processed = []
        for user_row in users_raw:
            processed_user = {
                "id": str(user_row["id"]) if user_row["id"] is not None else "",
                "idno": str(user_row["idno"]) if user_row["idno"] is not None else "",
                "name": str(user_row["name"]) if user_row["name"] is not None else "",
                "email": str(user_row["email"]) if user_row["email"] is not None else "",
                "level": str(user_row["level"]) if user_row["level"] is not None else "",
                "method": str(user_row["method"]) if user_row["method"] is not None else "",
                "payment": str(user_row["payment"]) if user_row["payment"] is not None else "",
                "status": str(user_row["status"]) if user_row["status"] is not None else "",
                "request_id": str(user_row["request_id"]) if user_row["request_id"] is not None else "",
                "schedule": None  # Default to None
            }
            
            # Handle datetime conversion safely
            schedule = user_row["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    processed_user['schedule'] = schedule.isoformat()
                else:
                    # Try to convert to string if it's not a datetime object
                    processed_user['schedule'] = str(schedule)
                    
            users_processed.append(processed_user)

        return jsonify(users_processed)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/update_status', methods=['POST'])
@token_required
def update_status():
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    user_ids = data.get('user_ids')
    new_status = data.get('status')
    new_schedule = data.get('schedule')  # Get the new schedule time if provided

    if not user_ids or not isinstance(user_ids, list):
        return jsonify({"error": "user_ids must be a list"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        
        placeholders = ','.join(['%s'] * len(user_ids))
        
        # Handle different update scenarios
        if new_status is None:
            # Delete/clear the status
            sql = f"UPDATE users SET status = NULL WHERE id IN ({placeholders})"
            cursor.execute(sql, tuple(user_ids))
        elif new_schedule:
            # Format the datetime properly for MySQL
            # If it's an ISO string, convert it to MySQL datetime format
            try:
                # Parse the ISO string and format it as MySQL datetime
                parsed_datetime = datetime.fromisoformat(new_schedule.replace('Z', '+00:00'))
                formatted_datetime = parsed_datetime.strftime('%Y-%m-%d %H:%M:%S')
                
                # Update both status and schedule (for recalling rejected requests)
                sql = f"UPDATE users SET status = %s, schedule = %s WHERE id IN ({placeholders})"
                cursor.execute(sql, tuple([new_status, formatted_datetime] + user_ids))
            except ValueError as e:
                # If there's an error parsing the datetime, return an error
                return jsonify({"error": f"Invalid datetime format: {str(e)}"}), 400
        else:
            # Just update status
            sql = f"UPDATE users SET status = %s WHERE id IN ({placeholders})"
            cursor.execute(sql, tuple([new_status] + user_ids))
        
        conn.commit()
        
        status_desc = "deleted" if new_status is None else f"updated to '{new_status}'"
        return jsonify({"message": f"{cursor.rowcount} user(s) {status_desc}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/appointments', methods=['POST'])
@token_required
def create_appointment():
    data = request.get_json()
    user_id = g.user.get('id')
    
    level = data.get('level')
    req_type = data.get('type')
    payment = data.get('payment')
    method = data.get('method')
    date = data.get('date')
    time = data.get('time')
    request_id = data.get('request_id')  # Get request_id if provided from client
    
    # Check if we should preserve course/strand
    preserve_course_strand = data.get('preserve_course_strand', False)
    course = data.get('course', '')
    strand = data.get('strand', '')
    
    # Validate required fields
    if not all([level, req_type, payment, method, date, time]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Validate enum values
    valid_levels = ['College', 'SHS']
    valid_payments = ['express', 'regular', 'priority']
    valid_methods = ['full', 'installment']
    
    if level not in valid_levels:
        return jsonify({"error": f"Invalid level. Must be one of: {', '.join(valid_levels)}"}), 400
    
    if payment not in valid_payments:
        return jsonify({"error": f"Invalid payment. Must be one of: {', '.join(valid_payments)}"}), 400
    
    if method not in valid_methods:
        return jsonify({"error": f"Invalid method. Must be one of: {', '.join(valid_methods)}"}), 400
        
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        schedule_datetime = f"{date} {time}"
        
        # Generate a request ID if not provided
        if not request_id:
            # First letter of payment type + random 4-digit number
            first_letter = payment[0].upper()
            random_num = str(1000 + int(1000 * time.time() % 9000)).zfill(4)
            request_id = f"{first_letter}-{random_num}"
        
        # If preserve_course_strand flag is set, use the provided course/strand values
        # Otherwise, use req_type for both (original behavior)
        course_value = course if preserve_course_strand else req_type
        strand_value = strand if preserve_course_strand else req_type
        
        sql = "UPDATE users SET level=%s, course=%s, strand=%s, schedule=%s, method=%s, payment=%s, status='pending', request_id=%s WHERE id=%s"
        params = (level, course_value, strand_value, schedule_datetime, method, payment, request_id, user_id)
        
        cursor.execute(sql, params)
        conn.commit()
        
        return jsonify({
            "success": True, 
            "message": "Appointment created successfully", 
            "status": "pending",
            "request_id": request_id
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/calendar', methods=['GET'])
def get_calendar():
    """Get all calendar entries"""
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT date, status FROM schedule")
        schedule_data = cursor.fetchall()
        
        calendar_data = {}
        for entry in schedule_data:
            if entry.get('date'):
                date_str = entry['date'].strftime('%Y-%m-%d')
                calendar_data[date_str] = entry.get('status')
        
        return jsonify(calendar_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/user_profile', methods=['GET'])
@token_required
def get_user_profile():
    """Get current user's profile information"""
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, cell, idno, level, course, strand, request_id, status FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Convert to a safe dictionary
        user_data = {
            "id": str(user["id"]) if user["id"] is not None else "",
            "name": str(user["name"]) if user["name"] is not None else "",
            "email": str(user["email"]) if user["email"] is not None else "",
            "cell": str(user["cell"]) if user["cell"] is not None else "",
            "idno": str(user["idno"]) if user["idno"] is not None else "",
            "level": str(user["level"]) if user["level"] is not None else "",
            "course": str(user["course"]) if user["course"] is not None else "",
            "strand": str(user["strand"]) if user["strand"] is not None else "",
            "request_id": str(user["request_id"]) if user["request_id"] is not None else "",
            "status": str(user["status"]) if user["status"] is not None else ""
        }
        
        return jsonify(user_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/update_profile', methods=['POST'])
@token_required
def update_profile():
    """Update user profile information"""
    data = request.get_json()
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    name = data.get('name')
    email = data.get('email')
    cell = data.get('cell')
    password = data.get('password')
    
    # Validate required fields
    if not all([name, email, password]):
        return jsonify({"error": "Missing required fields"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if email already exists for another user
        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
        if cursor.fetchone():
            return jsonify({"error": "Email already in use by another account"}), 409
        
        # Update user information
        cursor.execute(
            "UPDATE users SET name = %s, email = %s, cell = %s, password = %s WHERE id = %s",
            (name, email, cell, password, user_id)
        )
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Profile updated successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/calendar', methods=['POST'])
@token_required
def update_calendar():
    """Update or create a calendar entry"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.json
    if not data or 'date' not in data or 'status' not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    date_str = data['date']
    status = data['status']
    
    if status not in ['full', 'open', 'unavail']:
        return jsonify({"error": "Invalid status"}), 400
    
    try:
        date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM schedule WHERE date = %s", (date_obj,))
        if cursor.fetchone():
            cursor.execute("UPDATE schedule SET status = %s WHERE date = %s", (status, date_obj))
        else:
            cursor.execute("INSERT INTO schedule (date, time, status) VALUES (%s, %s, %s)", (date_obj, "00:00:00", status))
        
        conn.commit()
        
        return jsonify({"success": True, "date": date_str, "status": status})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/auth/create_public_user', methods=['POST'])
@token_required
def create_public_user():
    """Create a new user from the admin panel"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    idno = data.get('idno')
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    level = data.get('level')
    course = data.get('course')
    strand = data.get('strand')
    cell = data.get('cell')
    
    if not all([idno, password, level]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Level-specific validation
    if level == 'College' and not course:
        return jsonify({"error": "Course is required for College students"}), 400
    
    if level == 'SHS' and not strand:
        return jsonify({"error": "Strand is required for SHS students"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if ID is already in use
        cursor.execute("SELECT id FROM users WHERE idno = %s", (idno,))
        if cursor.fetchone():
            return jsonify({"error": "ID number is already in use"}), 409
        
        # Check if email is already in use
        if email:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                return jsonify({"error": "Email is already in use"}), 409
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Insert user
        cursor.execute(
            "INSERT INTO users (idno, name, email, password, level, course, strand, cell) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (idno, name, email, hashed_password, level, course, strand, cell)
        )
        
        conn.commit()
        user_id = cursor.lastrowid
        
        return jsonify({"success": True, "message": "User created successfully", "user_id": user_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/admin/profile', methods=['GET'])
@token_required
def get_admin_profile():
    """Get current admin's profile information"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
        
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # First check if is_active column exists
        cursor.execute("SHOW COLUMNS FROM admins LIKE 'is_active'")
        is_active_exists = cursor.fetchone() is not None
        
        # Construct the query based on available columns
        if is_active_exists:
            # If is_active exists, include it in the query
            cursor.execute("SELECT id, full_name, email, id_no, contact_no, room_name, is_active FROM admins WHERE id = %s", (user_id,))
        else:
            # Otherwise, select without is_active
            cursor.execute("SELECT id, full_name, email, id_no, contact_no, room_name FROM admins WHERE id = %s", (user_id,))
        
        admin = cursor.fetchone()
        
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        # Convert to a safe dictionary
        admin_data = {
            "id": str(admin.get("id", "")) if admin.get("id") is not None else "",
            "full_name": str(admin.get("full_name", "")) if admin.get("full_name") is not None else "",
            "email": str(admin.get("email", "")) if admin.get("email") is not None else "",
            "id_no": str(admin.get("id_no", "")) if admin.get("id_no") is not None else "",
            "contact_no": str(admin.get("contact_no", "")) if admin.get("contact_no") is not None else "",
            "room_name": str(admin.get("room_name", "")) if admin.get("room_name") is not None else ""
        }
        
        # Add is_active if it exists
        if is_active_exists:
            admin_data["is_active"] = str(admin.get("is_active", "no")) if admin.get("is_active") is not None else "no"
        else:
            admin_data["is_active"] = "yes"  # Default to yes if the column doesn't exist
        
        return jsonify(admin_data)
    
    except Exception as e:
        print(f"Error in get_admin_profile: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
            
@app.route('/api/admin/update-profile', methods=['POST'])
@token_required
def update_admin_profile():
    """Update admin profile information"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
        
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    id_no = data.get('id_no')
    contact_no = data.get('contact_no')
    room_name = data.get('room_name')
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    # Validate required fields
    if not all([full_name, email, id_no, contact_no, current_password]):
        return jsonify({"error": "Missing required fields"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Verify current password
        cursor.execute("SELECT password FROM admins WHERE id = %s", (user_id,))
        admin = cursor.fetchone()
        
        if not admin or admin['password'] != current_password:
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Check if email already exists for another admin
        cursor.execute("SELECT id FROM admins WHERE email = %s AND id != %s", (email, user_id))
        if cursor.fetchone():
            return jsonify({"error": "Email already in use by another account"}), 409
        
        # Check if ID number already exists for another admin
        cursor.execute("SELECT id FROM admins WHERE id_no = %s AND id != %s", (id_no, user_id))
        if cursor.fetchone():
            return jsonify({"error": "ID number already in use by another account"}), 409
        
        # Update admin information
        if new_password:
            cursor.execute(
                "UPDATE admins SET full_name = %s, email = %s, id_no = %s, contact_no = %s, room_name = %s, password = %s WHERE id = %s",
                (full_name, email, id_no, contact_no, room_name, new_password, user_id)
            )
        else:
            cursor.execute(
                "UPDATE admins SET full_name = %s, email = %s, id_no = %s, contact_no = %s, room_name = %s WHERE id = %s",
                (full_name, email, id_no, contact_no, room_name, user_id)
            )
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Profile updated successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/users', methods=['GET'])
@token_required
def get_users():
    """Get all users for the admin panel"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, idno, name, email, level, course, strand FROM users ORDER BY idno")
        users_raw = cursor.fetchall()
        
        # Process the results
        users = []
        for user in users_raw:
            # Convert values to strings and handle None
            processed_user = {
                "id": str(user["id"]) if user["id"] is not None else "",
                "idno": str(user["idno"]) if user["idno"] is not None else "",
                "name": str(user["name"]) if user["name"] is not None else "",
                "email": str(user["email"]) if user["email"] is not None else "",
                "level": str(user["level"]) if user["level"] is not None else "",
                "course": str(user["course"]) if user["course"] is not None else "",
                "strand": str(user["strand"]) if user["strand"] is not None else ""
            }
            users.append(processed_user)
        
        return jsonify(users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/update_user', methods=['POST'])
@token_required
def update_user():
    """Update user information from the admin panel"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    user_id = data.get('id')
    name = data.get('name')
    email = data.get('email')
    level = data.get('level')
    course = data.get('course')
    strand = data.get('strand')
    
    if not all([user_id, name, email, level]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Level-specific validation
    if level == 'College' and not course:
        return jsonify({"error": "Course is required for College students"}), 400
    
    if level == 'SHS' and not strand:
        return jsonify({"error": "Strand is required for SHS students"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if email is already in use by another user
        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
        if cursor.fetchone():
            return jsonify({"error": "Email is already in use by another user"}), 409
        
        # Update user
        cursor.execute(
            "UPDATE users SET name = %s, email = %s, level = %s, course = %s, strand = %s WHERE id = %s",
            (name, email, level, course, strand, user_id)
        )
        
        conn.commit()
        
        return jsonify({"success": True, "message": "User updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/update_counter', methods=['POST'])
@token_required
def update_counter():
    """Update the counter for a user in on-call status"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    user_id = data.get('user_id')
    counter = data.get('counter')
    
    if not user_id or counter is None:
        return jsonify({"error": "Missing required fields"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Update user counter
        cursor.execute("UPDATE users SET counter = %s WHERE id = %s", (counter, user_id))
        conn.commit()
        
        return jsonify({"success": True, "message": "Counter updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/auth/user_login', methods=['POST'])
def user_login():
    """Login endpoint specifically for regular users (not admins)"""
    data = request.get_json()
    idno = data.get('idno')
    password = data.get('password')
    
    print(f"Login attempt with idno: {idno}")

    if not idno or not password:
        print("Missing credentials")
        return jsonify({"error": "Missing credentials"}), 400

    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             print("Database connection failed")
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)

        # First check if the user exists
        cursor.execute("SELECT * FROM users WHERE idno = %s", (idno,))
        user = cursor.fetchone()
        
        print(f"Query result: {user}")

        if not user:
            print(f"No user found with idno: {idno}")
            return jsonify({"error": "Invalid credentials. Please verify your ID number and password."}), 401

        # Try both hashed password check and direct comparison (for backward compatibility)
        password_correct = False
        
        # First try to verify with check_password_hash (for properly hashed passwords)
        try:
            if check_password_hash(user['password'], password):
                password_correct = True
                print("Password verified with hash check")
        except Exception as e:
            print(f"Hash check failed: {str(e)}")
            # If hash check fails, it might be a plaintext password
        
        # If hash check failed, compare directly (for plaintext passwords in DB)
        if not password_correct and user['password'] == password:
            password_correct = True
            print("Password verified with direct comparison")
        
        if not password_correct:
            print(f"Password doesn't match for idno {idno}")
            return jsonify({"error": "Invalid credentials. Please verify your ID number and password."}), 401

        # User found and password correct, generate token
        token = jwt.encode({
            'id': str(user['id']),
            'name': user['name'],
            'is_admin': False,
            'exp': datetime.utcnow() + timedelta(days=1)
        }, SECRET_KEY, algorithm="HS256")
        
        print(f"Login successful for user: {user['name']}")

        # Return additional user data for client-side use
        return jsonify({
            'token': token,
            'name': user['name'],
            'id': str(user['id']),
            'idno': user['idno'],
            'email': user['email'],
            'level': user['level'],
            'course': user['course'],
            'strand': user['strand']
        })

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "An error occurred during login. Please try again."}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/user/requests', methods=['GET'])
@token_required
def get_user_requests():
    """Get pending and on-call requests for regular users to view in the mobile app"""
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get all pending and on-call requests (limited information for security)
        cursor.execute("""
            SELECT id, name, level, schedule, status, counter, request_id
            FROM users 
            WHERE status IN ('pending', 'oncall')
            ORDER BY schedule ASC
            LIMIT 50
        """)
        
        requests_raw = cursor.fetchall()
        
        # Process the results
        requests_processed = []
        for req in requests_raw:
            processed_req = {
                "id": str(req["id"]) if req["id"] is not None else "",
                "name": str(req["name"]) if req["name"] is not None else "",
                "level": str(req["level"]) if req["level"] is not None else "",
                "status": str(req["status"]) if req["status"] is not None else "",
                "counter": int(req["counter"]) if req["counter"] is not None else None,
                "request_id": str(req["request_id"]) if req["request_id"] is not None else "",
                "schedule": None,
                "user_id": str(req["id"]) if req["id"] is not None else "",  # Add user_id field
                "is_current_user": str(req["id"]) == user_id  # Add flag to easily identify current user's requests
            }
            
            # Handle datetime conversion safely
            schedule = req["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    processed_req['schedule'] = schedule.isoformat()
                else:
                    processed_req['schedule'] = str(schedule)
            
            requests_processed.append(processed_req)
        
        return jsonify(requests_processed)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/scheduled_requests', methods=['GET'])
@token_required
def get_scheduled_requests():
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # Get current date and time
        now = datetime.now()
        
        # Get users with pending status and future schedule date
        cursor.execute("""
            SELECT id, idno, name, email, level, method, payment, schedule, status, request_id 
            FROM users 
            WHERE status = 'pending' AND schedule > %s
            ORDER BY schedule ASC
        """, (now,))
        
        users_raw = cursor.fetchall()
        
        users_processed = []
        for user_row in users_raw:
            processed_user = {
                "id": str(user_row["id"]) if user_row["id"] is not None else "",
                "idno": str(user_row["idno"]) if user_row["idno"] is not None else "",
                "name": str(user_row["name"]) if user_row["name"] is not None else "",
                "email": str(user_row["email"]) if user_row["email"] is not None else "",
                "level": str(user_row["level"]) if user_row["level"] is not None else "",
                "method": str(user_row["method"]) if user_row["method"] is not None else "",
                "payment": str(user_row["payment"]) if user_row["payment"] is not None else "",
                "status": str(user_row["status"]) if user_row["status"] is not None else "",
                "request_id": str(user_row["request_id"]) if user_row["request_id"] is not None else "",
                "schedule": None  # Default to None
            }
            
            # Handle datetime conversion safely
            schedule = user_row["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    processed_user['schedule'] = schedule.isoformat()
                else:
                    # Try to convert to string if it's not a datetime object
                    processed_user['schedule'] = str(schedule)
                    
            users_processed.append(processed_user)

        return jsonify(users_processed)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/call_student/<int:user_id>', methods=['POST'])
@token_required
def call_student(user_id):
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    status = data.get('status', 'oncall')
    counter = data.get('counter', 30)  # Default 30 minutes
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        
        # Update the user status to oncall and set counter
        cursor.execute(
            "UPDATE users SET status = %s, counter = %s WHERE id = %s",
            (status, counter, user_id)
        )
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Student called successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/delete_scheduled_request/<int:user_id>', methods=['DELETE'])
@token_required
def delete_scheduled_request(user_id):
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        
        # Reset the user's request-related fields
        cursor.execute("""
            UPDATE users 
            SET status = NULL, schedule = NULL, method = NULL, 
                payment = NULL, request_id = NULL 
            WHERE id = %s
        """, (user_id,))
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Request deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# Background task to check and auto-reject users with expired counters
def auto_reject_expired_users():
    print("Starting auto-reject background thread...")
    while True:
        try:
            # Find and reject expired users
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                try:
                    # Find users with status 'oncall' and counter <= 0
                    # ONLY include users with non-null counter values to prevent rejecting users without timers
                    cursor.execute("SELECT id FROM users WHERE status = 'oncall' AND counter IS NOT NULL AND counter <= 0")
                    expired_users = cursor.fetchall()
                    
                    # Auto-reject each expired user
                    for user in expired_users:
                        user_id = user['id']
                        print(f"Auto-rejecting user {user_id} due to expired counter")
                        cursor.execute("UPDATE users SET status = 'rejected', counter = NULL WHERE id = %s", (user_id,))
                    
                    if expired_users:
                        print(f"Auto-rejected {len(expired_users)} users with expired timers")
                    
                    conn.commit()
                finally:
                    cursor.close()
                    conn.close()
            
            # Decrement counter in a separate connection
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    # Count how many rows will be affected for logging
                    cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'oncall' AND counter > 0")
                    count = cursor.fetchone()[0]
                    
                    # Decrement counter for all oncall users
                    cursor.execute("UPDATE users SET counter = counter - 1 WHERE status = 'oncall' AND counter > 0")
                    conn.commit()
                    
                    if count > 0:
                        print(f"Decremented counter for {count} oncall users")
                except Exception as e:
                    print(f"Error decrementing counters: {e}")
                finally:
                    cursor.close()
                    conn.close()
                
        except Exception as e:
            print(f"Error in auto-reject background task: {e}")
        
        # Sleep for 1 minute before checking again
        time.sleep(60)

# Start the background task in a separate thread
auto_reject_thread = threading.Thread(target=auto_reject_expired_users, daemon=True)

# Start the auto-reject thread when the server starts
if __name__ == '__main__':
    # Start the auto-reject background thread
    auto_reject_thread.start()
    print("Auto-reject background thread started")
    
    # Start the Flask application
    app.run(host="0.0.0.0", port=5057, debug=False)
else:
    # When imported as a module, still start the thread
    auto_reject_thread.start()
    print("Auto-reject background thread started in module mode")

@app.route('/api/user_by_id', methods=['GET'])
@token_required
def get_user_by_id():
    """Get user information by ID number for admin request creation"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    idno = request.args.get('idno')
    if not idno:
        return jsonify({"error": "ID number is required"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, idno, name, email, level, course, strand FROM users WHERE idno = %s", (idno,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Process the user data
        processed_user = {
            "id": str(user["id"]) if user["id"] is not None else "",
            "idno": str(user["idno"]) if user["idno"] is not None else "",
            "name": str(user["name"]) if user["name"] is not None else "",
            "email": str(user["email"]) if user["email"] is not None else "",
            "level": str(user["level"]) if user["level"] is not None else "",
            "course": str(user["course"]) if user["course"] is not None else "",
            "strand": str(user["strand"]) if user["strand"] is not None else ""
        }
        
        return jsonify(processed_user)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/admin/create_appointment', methods=['POST'])
@token_required
def admin_create_appointment():
    """Create appointment for a student by admin"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    
    # Get student ID number
    idno = data.get('idno')
    if not idno:
        return jsonify({"error": "Student ID number is required"}), 400
    
    level = data.get('level')
    req_type = data.get('type')
    payment = data.get('payment')
    method = data.get('method')
    date = data.get('date')
    time = data.get('time')
    request_id = data.get('request_id')  # Get request_id if provided from client
    
    # Check if we should preserve course/strand
    preserve_course_strand = data.get('preserve_course_strand', False)
    course = data.get('course', '')
    strand = data.get('strand', '')
    
    # Validate required fields
    if not all([level, req_type, payment, method, date, time]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Validate enum values
    valid_levels = ['College', 'SHS']
    valid_payments = ['express', 'regular', 'priority']
    valid_methods = ['full', 'installment']
    
    if level not in valid_levels:
        return jsonify({"error": f"Invalid level. Must be one of: {', '.join(valid_levels)}"}), 400
    
    if payment not in valid_payments:
        return jsonify({"error": f"Invalid payment. Must be one of: {', '.join(valid_payments)}"}), 400
    
    if method not in valid_methods:
        return jsonify({"error": f"Invalid method. Must be one of: {', '.join(valid_methods)}"}), 400
        
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        
        # First, find the student by ID number
        cursor.execute("SELECT id, course, strand FROM users WHERE idno = %s", (idno,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({"error": "Student not found with the provided ID number"}), 404
            
        student_id = student[0]
        schedule_datetime = f"{date} {time}"
        
        # Generate a request ID if not provided
        if not request_id:
            # First letter of payment type + random 4-digit number
            first_letter = payment[0].upper()
            random_num = str(1000 + int(1000 * time.time() % 9000)).zfill(4)
            request_id = f"{first_letter}-{random_num}"
        
        # If preserve_course_strand flag is set, use the provided course/strand values
        # If not provided but preserve flag is set, use the student's existing values
        # Otherwise, use req_type for both (original behavior)
        if preserve_course_strand:
            # If course/strand not provided but preserve flag is set, use existing values from DB
            if not course and len(student) > 1:
                course = student[1] or ''
            if not strand and len(student) > 2:
                strand = student[2] or ''
            course_value = course
            strand_value = strand
        else:
            course_value = req_type
            strand_value = req_type
        
        sql = "UPDATE users SET level=%s, course=%s, strand=%s, schedule=%s, method=%s, payment=%s, status='pending', request_id=%s WHERE id=%s"
        params = (level, course_value, strand_value, schedule_datetime, method, payment, request_id, student_id)
        
        cursor.execute(sql, params)
        conn.commit()
        
        return jsonify({
            "success": True, 
            "message": "Appointment created successfully", 
            "status": "pending",
            "request_id": request_id
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/priority_users', methods=['GET'])
@token_required
def get_priority_users():
    """Get all priority users"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, idno, name, email, level, course, strand FROM users WHERE flags = 'priority_user'")
        users = cursor.fetchall()
        
        # Convert to safe dictionaries
        safe_users = []
        for user in users:
            safe_user = {
                "id": str(user["id"]) if user["id"] is not None else "",
                "idno": str(user["idno"]) if user["idno"] is not None else "",
                "name": str(user["name"]) if user["name"] is not None else "",
                "email": str(user["email"]) if user["email"] is not None else "",
                "level": str(user["level"]) if user["level"] is not None else "",
                "course": str(user["course"]) if user["course"] is not None else "",
                "strand": str(user["strand"]) if user["strand"] is not None else ""
            }
            safe_users.append(safe_user)
        
        return jsonify(safe_users)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/add_priority_user', methods=['POST'])
@token_required
def add_priority_user():
    """Add a user to the priority list"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    idno = data.get('idno')
    
    if not idno:
        return jsonify({"error": "Student ID number is required"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE idno = %s", (idno,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found with the provided ID number"}), 404
        
        # Update user to set priority flag
        cursor.execute("UPDATE users SET flags = 'priority_user' WHERE idno = %s", (idno,))
        conn.commit()
        
        return jsonify({"success": True, "message": "User added to priority list successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/remove_priority_user', methods=['POST'])
@token_required
def remove_priority_user():
    """Remove a user from the priority list"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    idno = data.get('idno')
    
    if not idno:
        return jsonify({"error": "Student ID number is required"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Update user to remove priority flag
        cursor.execute("UPDATE users SET flags = NULL WHERE idno = %s", (idno,))
        conn.commit()
        
        return jsonify({"success": True, "message": "User removed from priority list successfully"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/check_priority_status', methods=['GET'])
@token_required
def check_priority_status():
    """Check if the current user has priority status"""
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT flags FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        is_priority = user.get('flags') == 'priority_user'
        
        return jsonify({
            "is_priority": is_priority
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/check_new_user', methods=['GET'])
@token_required
def check_new_user():
    """Check if the current user is a new user"""
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Add new_user column if it doesn't exist
        try:
            cursor.execute("SHOW COLUMNS FROM users LIKE 'new_user'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE users ADD COLUMN new_user ENUM('yes', 'no') DEFAULT 'yes'")
                conn.commit()
        except Exception as e:
            print(f"Error checking/adding new_user column: {str(e)}")
        
        cursor.execute("SELECT new_user FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        return jsonify({
            "is_new_user": user.get('new_user', 'yes')
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/update_new_user_status', methods=['POST'])
@token_required
def update_new_user_status():
    """Update the new_user status for the current user"""
    user_id = g.user.get('id')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    data = request.get_json()
    new_status = data.get('new_user', 'no')
    
    # Validate that the new_status is either 'yes' or 'no'
    if new_status not in ['yes', 'no']:
        return jsonify({"error": "Invalid status value. Must be 'yes' or 'no'"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Add new_user column if it doesn't exist
        try:
            cursor.execute("SHOW COLUMNS FROM users LIKE 'new_user'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE users ADD COLUMN new_user ENUM('yes', 'no') DEFAULT 'yes'")
                conn.commit()
        except Exception as e:
            print(f"Error checking/adding new_user column: {str(e)}")
        
        # Update the user's new_user status
        cursor.execute("UPDATE users SET new_user = %s WHERE id = %s", (new_status, user_id))
        conn.commit()
        
        return jsonify({
            "message": "User status updated successfully",
            "new_user": new_status
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route('/api/admin/save-settings', methods=['POST'])
@token_required
def save_admin_settings():
    """Save admin settings to the database"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Unauthorized"}), 401
    
    admin_id = g.user.get('id')
    data = request.get_json()
    settings = data.get('settings')
    
    if not settings:
        return jsonify({"error": "No settings provided"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if status column exists in admins table, add if needed
        cursor.execute("SHOW COLUMNS FROM admins LIKE 'status'")
        if not cursor.fetchone():
            try:
                cursor.execute("ALTER TABLE admins ADD COLUMN status ENUM('online', 'offline') DEFAULT 'offline'")
                conn.commit()
                print("Added status column to admins table")
            except mysql.connector.Error as e:
                print(f"Error adding status column: {e}")
        
        # Check if last_active column exists in admins table, add if needed
        cursor.execute("SHOW COLUMNS FROM admins LIKE 'last_active'")
        if not cursor.fetchone():
            try:
                cursor.execute("ALTER TABLE admins ADD COLUMN last_active TIMESTAMP NULL DEFAULT NULL")
                conn.commit()
                print("Added last_active column to admins table")
            except mysql.connector.Error as e:
                print(f"Error adding last_active column: {e}")
        
        # Check if admin_settings table exists, create if not
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                settings TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_admin (admin_id)
            )
        """)
        conn.commit()
        
        # Check if settings already exist for this admin
        cursor.execute("SELECT id FROM admin_settings WHERE admin_id = %s", (admin_id,))
        existing = cursor.fetchone()
        
        # Convert settings to JSON string
        import json
        settings_json = json.dumps(settings)
        
        if existing:
            # Update existing settings
            cursor.execute("UPDATE admin_settings SET settings = %s WHERE admin_id = %s", 
                          (settings_json, admin_id))
        else:
            # Insert new settings
            cursor.execute("INSERT INTO admin_settings (admin_id, settings) VALUES (%s, %s)", 
                          (admin_id, settings_json))
        
        conn.commit()
        
        # Update admin status to online and last_active timestamp
        cursor.execute("""
            UPDATE admins 
            SET status = 'online', last_active = NOW() 
            WHERE id = %s
        """, (admin_id,))
        conn.commit()
        
        return jsonify({"success": True, "message": "Settings saved successfully"})
    except Exception as e:
        print(f"Error in save_admin_settings: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/generate', methods=['POST'])
def generate_verification_code():
    """Generate a verification code and send it to the user's email"""
    email = request.form.get('email')
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # First check in admins table
        cursor.execute("SELECT id, full_name, email FROM admins WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        # If not in admins table, check users table
        if not user:
            cursor.execute("SELECT id, name, email FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "Email not found"}), 404
        
        # Generate a random 4-digit code
        verification_code = str(random.randint(1000, 9999))
        
        # Store the code with timestamp for the user
        verification_codes[email] = {
            'code': verification_code,
            'timestamp': datetime.now()
        }
        
        # Send email with the verification code
        try:
            send_verification_email(email, verification_code)
            return jsonify({
                "success": True,
                "message": verification_code,  # Including the code in the response for testing
                "email": email
            })
        except Exception as e:
            print(f"Error sending email: {e}")
            # For testing purposes, still return the code even if email fails
            return jsonify({
                "success": False,
                "error": "Failed to send email",
                "message": verification_code  # Include code for testing
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset a user's password after verifying the code"""
    email = request.form.get('email')
    code = request.form.get('code')
    new_password = request.form.get('newPassword')
    
    if not email or not code or not new_password:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Check if the verification code is valid
    if email not in verification_codes:
        return jsonify({"error": "Verification not initiated or expired"}), 400
    
    verification = verification_codes[email]
    
    # Check if the code has expired (30 minutes)
    if (datetime.now() - verification['timestamp']).total_seconds() > 1800:
        del verification_codes[email]
        return jsonify({"error": "Verification code has expired"}), 400
    
    # Check if the code matches
    if verification['code'] != code:
        return jsonify({"error": "Invalid verification code"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor()
        
        # Update password in admins table
        cursor.execute("SELECT id FROM admins WHERE email = %s", (email,))
        admin = cursor.fetchone()
        
        if admin:
            cursor.execute("UPDATE admins SET password = %s WHERE email = %s", (new_password, email))
        else:
            # Update password in users table
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (new_password, email))
        
        conn.commit()
        
        # Remove the verification code
        del verification_codes[email]
        
        return jsonify({
            "success": True,
            "message": "Password reset successfully"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

def send_verification_email(email, verification_code):
    """Send verification code via email"""
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("Email credentials not configured")
        raise Exception("Email credentials not configured")
    
    # Create email with improved design including AISAT banner
    subject = "AISAT Registral Password Reset Code"
    
    # Use the raw GitHub URL for the image instead of embedding it
    aisat_logo_url = "https://raw.githubusercontent.com/ragej4x/aisatregistral-deployment/refs/heads/main/img/aisat.png"
    
    # Email body with better design - white background and linked image
    body = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                background-color: #ffffff;
            }}
            .header {{
                text-align: center;
                padding: 10px 0 20px 0;
                border-bottom: 2px solid #FF8C00; /* Orange border, AISAT color */
            }}
            .content {{
                padding: 20px;
                background-color: #ffffff;
            }}
            .footer {{
                text-align: center;
                margin-top: 20px;
                padding-top: 20px;
                border-top: 1px solid #e0e0e0;
                font-size: 12px;
                color: #777;
            }}
            .verification-code {{
                font-size: 36px;
                font-weight: bold;
                letter-spacing: 5px;
                text-align: center;
                margin: 30px 0;
                padding: 15px;
                background-color: #f7f7f7;
                border-radius: 5px;
                color: #0033cc; /* AISAT blue color */
            }}
            .logo {{
                max-width: 300px;
                height: auto;
                margin: 0 auto;
                display: block;
            }}
            h2 {{
                color: #0033cc; /* AISAT blue color */
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <img src="{aisat_logo_url}" class="logo" alt="AISAT College">
            </div>
            <div class="content">
                <h2>Password Reset Request</h2>
                <p>You have requested to reset your password for your AISAT Registral account.</p>
                <p>Please use the verification code below to complete the password reset process:</p>
                
                <div class="verification-code">{verification_code}</div>
                
                <p>This code will expire in 30 minutes. If you did not request a password reset, please ignore this email.</p>
                
                <p>For security reasons, please do not share this code with anyone.</p>
            </div>
            <div class="footer">
                <p>&copy; {datetime.now().year} AISAT College. All Rights Reserved.</p>
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = email
    msg['Subject'] = subject
    
    # Attach HTML body
    msg.attach(MIMEText(body, 'html'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        if EMAIL_USE_TLS:
            server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, msg.as_string())
        server.close()
        print(f"Verification email sent to {email}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        raise

@app.route('/api/admin/update-active-status', methods=['POST', 'OPTIONS'])
def admin_update_status():
    """Handle admin status updates"""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
        
    # For actual POST requests
    try:
        # Just return success for now
        return jsonify({
            "success": True,
            "message": "Status updated successfully"
        })
    except Exception as e:
        print(f"Error in admin_update_status: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/get-settings', methods=['GET', 'OPTIONS'])
@token_required
def get_admin_settings():
    """Get admin settings from the database"""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        return response
        
    # Check if user is admin
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
        
    admin_id = g.user.get('id')
    
    if not admin_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get admin settings from database
        cursor.execute("SELECT settings FROM admin_settings WHERE admin_id = %s", (admin_id,))
        settings_row = cursor.fetchone()
        
        if settings_row and settings_row.get('settings'):
            import json
            settings = json.loads(settings_row['settings'])
            return jsonify({"settings": settings})
        else:
            # Return default settings if none found
            default_settings = {
                "filter_settings": {
                    "express": True,
                    "regular": True,
                    "priority": True
                }
            }
            return jsonify({"settings": default_settings})
            
    except Exception as e:
        print(f"Error getting admin settings: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# Add a new endpoint for TV display to get admin settings without authentication
@app.route('/api/tv/get-admin-settings', methods=['GET', 'OPTIONS'])
def get_tv_admin_settings():
    """Get admin settings for TV display without authentication"""
    # Handle OPTIONS request for CORS preflight
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        return response
    
    # Get admin ID from query parameter
    admin_id = request.args.get('admin_id', '1')  # Default to admin with ID 1
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get admin settings from database
        cursor.execute("SELECT settings FROM admin_settings WHERE admin_id = %s", (admin_id,))
        settings_row = cursor.fetchone()
        
        if settings_row and settings_row.get('settings'):
            import json
            settings = json.loads(settings_row['settings'])
            return jsonify({"settings": settings})
        else:
            # Return default settings if none found
            default_settings = {
                "filter_settings": {
                    "express": True,
                    "regular": True,
                    "priority": True
                }
            }
            return jsonify({"settings": default_settings})
            
    except Exception as e:
        print(f"Error getting admin settings for TV: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/tv_display')
def tv_display_page():
    """Serve the TV display page"""
    return send_from_directory('.', 'tv_display.html')

@app.route('/api/set_admin_active', methods=['GET'])
def set_admin_active():
    """Endpoint to directly set an admin as active or inactive (for testing)"""
    try:
        admin_id = request.args.get('admin_id', '1')  # Default to admin with ID 1
        room_name = request.args.get('room')  # No default room name
        is_active = request.args.get('is_active', 'yes')  # Default to active
        
        # Validate is_active parameter
        if is_active not in ['yes', 'no']:
            is_active = 'yes'  # Default to active if invalid value
        
        conn, cursor = None, None
        try:
            conn = get_db_connection()
            if not conn:
                return jsonify({"error": "Database connection failed"}), 500
            
            cursor = conn.cursor()
            
            # First, make sure the is_active column exists
            cursor.execute("SHOW COLUMNS FROM admins LIKE 'is_active'")
            if not cursor.fetchone():
                try:
                    cursor.execute("ALTER TABLE admins ADD COLUMN is_active ENUM('yes', 'no') DEFAULT 'no'")
                    conn.commit()
                    print("Added is_active column to admins table")
                except mysql.connector.Error as e:
                    return jsonify({"error": f"Failed to add is_active column: {str(e)}"}), 500
            
            # Update room_name as well if specified
            if room_name:
                # First check if room_name column exists
                cursor.execute("SHOW COLUMNS FROM admins LIKE 'room_name'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE admins ADD COLUMN room_name VARCHAR(100) DEFAULT NULL")
                    conn.commit()
                    print("Added room_name column to admins table")
                
                # Update both is_active and room_name
                cursor.execute("UPDATE admins SET is_active = %s, room_name = %s WHERE id = %s", (is_active, room_name, admin_id))
            else:
                # Just update is_active, don't touch room_name
                cursor.execute("UPDATE admins SET is_active = %s WHERE id = %s", (is_active, admin_id))
                
            conn.commit()
            
            # Read back the updated admin
            cursor.execute("SELECT id, full_name, is_active, room_name FROM admins WHERE id = %s", (admin_id,))
            admin = cursor.fetchone()
            
            if admin:
                # Access admin as a tuple (id, full_name, is_active, room_name)
                return jsonify({
                    "success": True,
                    "message": f"Admin ID {admin_id} has been set to {is_active}",
                    "admin": {
                        "id": admin[0],
                        "name": admin[1],
                        "is_active": admin[2],
                        "room_name": admin[3]
                    }
                })
            else:
                return jsonify({"error": f"Admin ID {admin_id} not found"}), 404
                
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()
                
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/api/create_test_request', methods=['POST'])
def create_test_request():
    """Endpoint to create test requests with assigned_to field"""
    try:
        data = request.get_json()
        
        # Extract fields from the request
        idno = data.get('idno')
        name = data.get('name')
        email = data.get('email')
        level = data.get('level')
        method = data.get('method')
        payment = data.get('payment')
        status = data.get('status')
        request_id = data.get('request_id')
        assigned_to = data.get('assigned_to')
        
        conn, cursor = None, None
        try:
            conn = get_db_connection()
            if not conn:
                return jsonify({"error": "Database connection failed"}), 500
            
            cursor = conn.cursor()
            
            # Check if assigned_to column exists
            cursor.execute("SHOW COLUMNS FROM users LIKE 'assigned_to'")
            if not cursor.fetchone():
                try:
                    cursor.execute("ALTER TABLE users ADD COLUMN assigned_to INT DEFAULT NULL")
                    conn.commit()
                    print("Added assigned_to column to users table")
                except mysql.connector.Error as e:
                    return jsonify({"error": f"Failed to add assigned_to column: {str(e)}"}), 500
            
            # Insert the test request into the database
            cursor.execute("""
                INSERT INTO users (idno, name, email, level, method, payment, status, request_id, assigned_to)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (idno, name, email, level, method, payment, status, request_id, assigned_to))
            
            conn.commit()
            
            return jsonify({
                "success": True,
                "message": "Test request created successfully",
                "id": cursor.lastrowid,
                "request_id": request_id,
                "name": name,
                "idno": idno,
                "email": email,
                "assigned_to": assigned_to
            })
            
        except Exception as e:
            if conn:
                conn.rollback()
            print(f"Error creating test request: {str(e)}")
            return jsonify({"error": str(e)}), 500
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()
                
    except Exception as e:
        print(f"Error processing test request: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/tv_pending_requests', methods=['GET'])
def get_tv_pending_requests():
    """Public endpoint for TV display to get pending requests without authentication"""
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"error": "Database connection failed"}), 500
        cursor = conn.cursor(dictionary=True)
        
        # Check if assigned_to column exists
        cursor.execute("SHOW COLUMNS FROM users LIKE 'assigned_to'")
        if not cursor.fetchone():
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN assigned_to INT DEFAULT NULL")
                conn.commit()
                print("Added assigned_to column to users table")
            except mysql.connector.Error as e:
                print(f"Error adding assigned_to column: {e}")
        
        # Include assigned_to in the query
        cursor.execute("SELECT id, idno, name, level, method, payment, schedule, status, counter, request_id, assigned_to FROM users WHERE status IN ('pending', 'oncall') ORDER BY schedule ASC")
        users_raw = cursor.fetchall()
        
        # Manually build a new list of dictionaries to ensure data is clean for JSON
        users_processed = []
        for user_row in users_raw:
            processed_user = {
                "id": str(user_row["id"]) if user_row["id"] is not None else "",
                "idno": str(user_row["idno"]) if user_row["idno"] is not None else "",
                "name": str(user_row["name"]) if user_row["name"] is not None else "",
                "level": str(user_row["level"]) if user_row["level"] is not None else "",
                "method": str(user_row["method"]) if user_row["method"] is not None else "",
                "payment": str(user_row["payment"]) if user_row["payment"] is not None else "",
                "status": str(user_row["status"]) if user_row["status"] is not None else "",
                "counter": int(user_row["counter"]) if user_row["counter"] is not None else None,
                "request_id": str(user_row["request_id"]) if user_row["request_id"] is not None else "",
                "assigned_to": int(user_row["assigned_to"]) if user_row["assigned_to"] is not None else None,
                "schedule": None  # Default to None
            }
            
            # Handle datetime conversion safely
            schedule = user_row["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    processed_user['schedule'] = schedule.isoformat()
                else:
                    # Try to convert to string if it's not a datetime object
                    processed_user['schedule'] = str(schedule)
                    
            users_processed.append(processed_user)
            
        return jsonify(users_processed)
    except Exception as e:
        print(f"Error in tv_pending_requests: {str(e)}")  # Log the error for debugging
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/admin/active-status-check', methods=['GET'])
def check_admin_active_status():
    """Endpoint to check if any admin is active"""
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Check if is_active column exists
        cursor.execute("SHOW COLUMNS FROM admins LIKE 'is_active'")
        if not cursor.fetchone():
            return jsonify({"active_admins": []})
        
        # Get all active admins
        cursor.execute("SELECT id, full_name, room_name FROM admins WHERE is_active = 'yes'")
        active_admins = []
        for row in cursor.fetchall():
            active_admins.append({
                "id": row[0],
                "name": row[1],
                "room_name": row[2]
            })
        
        return jsonify({"active_admins": active_admins})
        
    except Exception as e:
        print(f"Error checking admin active status: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# Announcements data file path
ANNOUNCEMENTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'announcements.json')

# Threads data file path
THREADS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'threads.json')

# Ensure the data directory exists
os.makedirs(os.path.dirname(ANNOUNCEMENTS_FILE), exist_ok=True)

@app.route('/api/save_announcements', methods=['POST', 'OPTIONS'])
def save_announcements():
    """Save announcements to a file."""
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        return response
    
    try:
        data = request.get_json()
        if not data or 'announcements' not in data:
            return jsonify({"error": "Invalid data format"}), 400
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(ANNOUNCEMENTS_FILE), exist_ok=True)
        
        # Write the announcements to the file
        import json
        with open(ANNOUNCEMENTS_FILE, 'w') as f:
            json.dump(data, f)
        
        return jsonify({"success": True, "message": "Announcements saved successfully"}), 200
    except Exception as e:
        print(f"Error saving announcements: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_announcements', methods=['GET', 'OPTIONS'])
def get_announcements():
    """Get announcements from file."""
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        return response
    
    try:
        import json
        
        # Get the admin token if provided
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        
        # Prepare response data
        response_data = {}
        
        # Load announcements
        if os.path.exists(ANNOUNCEMENTS_FILE):
            with open(ANNOUNCEMENTS_FILE, 'r') as f:
                announcement_data = json.load(f)
                response_data.update(announcement_data)
        else:
            response_data["announcements"] = []
        
        # If token provided, try to get admin-specific filter settings
        if token:
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                admin_id = data.get('id')
                
                if admin_id and data.get('is_admin'):
                    # Get admin settings from database if available
                    conn = get_db_connection()
                    if conn:
                        cursor = conn.cursor(dictionary=True)
                        cursor.execute("SELECT settings FROM admin_settings WHERE admin_id = %s", (admin_id,))
                        settings_row = cursor.fetchone()
                        
                        if settings_row and settings_row.get('settings'):
                            admin_settings = json.loads(settings_row['settings'])
                            if 'filter_settings' in admin_settings:
                                # Add filter settings to the response
                                response_data["filterSettings"] = admin_settings['filter_settings']
                                print(f"Added filter settings for admin {admin_id} to response")
                        
                        cursor.close()
                        conn.close()
            except Exception as e:
                print(f"Error getting admin settings: {str(e)}")
        
        return jsonify(response_data), 200
    except Exception as e:
        print(f"Error getting announcements: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/save_threads', methods=['POST', 'OPTIONS'])
def save_threads():
    """Save announcement threads to a file."""
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        return response
    
    try:
        data = request.get_json()
        if not data or 'threads' not in data:
            return jsonify({"error": "Invalid data format"}), 400
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(THREADS_FILE), exist_ok=True)
        
        # Write the threads to the file
        import json
        with open(THREADS_FILE, 'w') as f:
            json.dump(data, f)
        
        return jsonify({"success": True, "message": "Threads saved successfully"}), 200
    except Exception as e:
        print(f"Error saving threads: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/get_threads', methods=['GET', 'OPTIONS'])
def get_threads():
    """Get announcement threads from file."""
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        return response
    
    try:
        import json
        
        # Prepare response data
        response_data = {"threads": []}
        
        # Load threads if file exists
        if os.path.exists(THREADS_FILE):
            with open(THREADS_FILE, 'r') as f:
                thread_data = json.load(f)
                response_data.update(thread_data)
        
        return jsonify(response_data), 200
    except Exception as e:
        print(f"Error getting threads: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/user/check_own_request', methods=['GET'])
@token_required
def check_own_request():
    """Check if the current user has a pending or oncall request"""
    user_id = g.user.get('id')
    user_idno = g.user.get('idno')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id, idno, name, level, payment, method, schedule, status, counter, request_id
            FROM users 
            WHERE (id = %s OR idno = %s) AND status IN ('pending', 'oncall')
            LIMIT 1
        """, (user_id, user_idno))
        
        request_raw = cursor.fetchone()
        
        if not request_raw:
            # No pending request found
            return jsonify({"has_request": False})
        
        # Process the result
        processed_req = {
            "has_request": True,
            "id": str(request_raw["id"]) if request_raw["id"] is not None else "",
            "idno": str(request_raw["idno"]) if request_raw["idno"] is not None else "",
            "name": str(request_raw["name"]) if request_raw["name"] is not None else "",
            "level": str(request_raw["level"]) if request_raw["level"] is not None else "",
            "payment": str(request_raw["payment"]) if request_raw["payment"] is not None else "",
            "method": str(request_raw["method"]) if request_raw["method"] is not None else "",
            "status": str(request_raw["status"]) if request_raw["status"] is not None else "",
            "counter": int(request_raw["counter"]) if request_raw["counter"] is not None else None,
            "request_id": str(request_raw["request_id"]) if request_raw["request_id"] is not None else "",
            "schedule": None
        }
        
        # Handle datetime conversion safely
        schedule = request_raw["schedule"]
        if schedule:
            if isinstance(schedule, datetime):
                processed_req['schedule'] = schedule.isoformat()
            else:
                processed_req['schedule'] = str(schedule)
        
        return jsonify(processed_req)
    
    except Exception as e:
        print(f"Error in check_own_request: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/user/notifications', methods=['GET'])
@token_required
def get_user_notifications():
    """Get both the user's own requests and all pending/oncall requests in a single call"""
    user_id = g.user.get('id')
    user_idno = g.user.get('idno')
    
    if not user_id:
        return jsonify({"error": "User ID not found in token"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # First check if the user has their own request
        cursor.execute("""
            SELECT id, idno, name, level, payment, method, schedule, status, counter, request_id
            FROM users 
            WHERE (id = %s OR idno = %s) AND status IN ('pending', 'oncall')
            LIMIT 1
        """, (user_id, user_idno))
        
        own_request_raw = cursor.fetchone()
        
        # Then get all pending and on-call requests (for notification panel)
        cursor.execute("""
            SELECT id, idno, name, level, schedule, status, counter, request_id
            FROM users 
            WHERE status IN ('pending', 'oncall')
            ORDER BY schedule ASC
            LIMIT 50
        """)
        
        all_requests_raw = cursor.fetchall()
        
        # Process the results
        result = {
            "has_own_request": False,
            "own_request": None,
            "all_requests": []
        }
        
        # Process own request if exists
        if own_request_raw:
            result["has_own_request"] = True
            result["own_request"] = {
                "id": str(own_request_raw["id"]) if own_request_raw["id"] is not None else "",
                "idno": str(own_request_raw["idno"]) if own_request_raw["idno"] is not None else "",
                "name": str(own_request_raw["name"]) if own_request_raw["name"] is not None else "",
                "level": str(own_request_raw["level"]) if own_request_raw["level"] is not None else "",
                "payment": str(own_request_raw["payment"]) if own_request_raw["payment"] is not None else "",
                "method": str(own_request_raw["method"]) if own_request_raw["method"] is not None else "",
                "status": str(own_request_raw["status"]) if own_request_raw["status"] is not None else "",
                "counter": int(own_request_raw["counter"]) if own_request_raw["counter"] is not None else None,
                "request_id": str(own_request_raw["request_id"]) if own_request_raw["request_id"] is not None else "",
                "schedule": None
            }
            
            # Handle datetime conversion safely for own request
            schedule = own_request_raw["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    result["own_request"]["schedule"] = schedule.isoformat()
                else:
                    result["own_request"]["schedule"] = str(schedule)
        
        # Process all requests
        for req in all_requests_raw:
            processed_req = {
                "id": str(req["id"]) if req["id"] is not None else "",
                "idno": str(req["idno"]) if req["idno"] is not None else "",
                "name": str(req["name"]) if req["name"] is not None else "",
                "level": str(req["level"]) if req["level"] is not None else "",
                "status": str(req["status"]) if req["status"] is not None else "",
                "counter": int(req["counter"]) if req["counter"] is not None else None,
                "request_id": str(req["request_id"]) if req["request_id"] is not None else "",
                "schedule": None,
                "is_current_user": (str(req["id"]) == user_id) or (str(req["idno"]) == user_idno)
            }
            
            # Handle datetime conversion safely
            schedule = req["schedule"]
            if schedule:
                if isinstance(schedule, datetime):
                    processed_req["schedule"] = schedule.isoformat()
                else:
                    processed_req["schedule"] = str(schedule)
            
            result["all_requests"].append(processed_req)
        
        return jsonify(result)
    
    except Exception as e:
        print(f"Error in get_user_notifications: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

# New endpoints for transaction history

@app.route('/api/create_transaction_history_table', methods=['GET'])
@token_required
def create_transaction_history_table():
    """Create transaction history table if it doesn't exist (admin only)"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor()
        
        # Create transaction_history table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS transaction_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                request_id VARCHAR(20),
                idno VARCHAR(20),
                name VARCHAR(100),
                level VARCHAR(20),
                method VARCHAR(20),
                payment VARCHAR(20),
                status VARCHAR(20),
                processed_by INT,
                admin_name VARCHAR(100),
                action_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )
        """)
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Transaction history table created successfully"})
    except Exception as e:
        print(f"Error creating transaction history table: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/log_transaction', methods=['POST'])
@token_required
def log_transaction():
    """Log a transaction to the history table"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    data = request.get_json()
    user_id = data.get('user_id')
    status = data.get('status')
    notes = data.get('notes', '')
    
    if not user_id or not status:
        return jsonify({"error": "Missing required fields"}), 400
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # First, get the user details to log
        cursor.execute("""
            SELECT idno, name, level, method, payment, request_id
            FROM users 
            WHERE id = %s
        """, (user_id,))
        
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        admin_id = g.user.get('id')
        admin_name = g.user.get('name')
        
        # Log the transaction
        cursor.execute("""
            INSERT INTO transaction_history 
            (request_id, idno, name, level, method, payment, status, processed_by, admin_name, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user.get('request_id', ''),
            user.get('idno', ''),
            user.get('name', ''),
            user.get('level', ''),
            user.get('method', ''),
            user.get('payment', ''),
            status,
            admin_id,
            admin_name,
            notes
        ))
        
        conn.commit()
        
        return jsonify({"success": True, "message": "Transaction logged successfully"})
    except Exception as e:
        print(f"Error logging transaction: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/transaction_history', methods=['GET'])
@token_required
def get_transaction_history():
    """Get transaction history with optional filters"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    # Get filter parameters from query string
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    status = request.args.get('status')
    idno = request.args.get('idno')
    payment_type = request.args.get('payment_type')
    admin_id = request.args.get('admin_id')
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Build query based on filters
        query = "SELECT * FROM transaction_history WHERE 1=1"
        params = []
        
        if start_date:
            query += " AND DATE(action_date) >= %s"
            params.append(start_date)
        
        if end_date:
            query += " AND DATE(action_date) <= %s"
            params.append(end_date)
        
        if status:
            query += " AND status = %s"
            params.append(status)
        
        if idno:
            query += " AND idno = %s"
            params.append(idno)
        
        if payment_type:
            query += " AND payment = %s"
            params.append(payment_type)
        
        if admin_id:
            query += " AND processed_by = %s"
            params.append(admin_id)
        
        # Add sorting
        query += " ORDER BY action_date DESC LIMIT 1000"
        
        cursor.execute(query, tuple(params))
        transactions_raw = cursor.fetchall()
        
        # Process transactions
        transactions = []
        for trans in transactions_raw:
            processed_trans = {
                "id": str(trans["id"]) if trans["id"] is not None else "",
                "request_id": str(trans["request_id"]) if trans["request_id"] is not None else "",
                "idno": str(trans["idno"]) if trans["idno"] is not None else "",
                "name": str(trans["name"]) if trans["name"] is not None else "",
                "level": str(trans["level"]) if trans["level"] is not None else "",
                "method": str(trans["method"]) if trans["method"] is not None else "",
                "payment": str(trans["payment"]) if trans["payment"] is not None else "",
                "status": str(trans["status"]) if trans["status"] is not None else "",
                "processed_by": str(trans["processed_by"]) if trans["processed_by"] is not None else "",
                "admin_name": str(trans["admin_name"]) if trans["admin_name"] is not None else "",
                "notes": str(trans["notes"]) if trans["notes"] is not None else "",
                "action_date": None
            }
            
            # Handle datetime conversion safely
            action_date = trans["action_date"]
            if action_date:
                if isinstance(action_date, datetime):
                    processed_trans["action_date"] = action_date.isoformat()
                else:
                    processed_trans["action_date"] = str(action_date)
            
            transactions.append(processed_trans)
        
        return jsonify(transactions)
    except Exception as e:
        print(f"Error getting transaction history: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/transaction_history_stats', methods=['GET'])
@token_required
def get_transaction_history_stats():
    """Get transaction history statistics"""
    if not g.user.get('is_admin'):
        return jsonify({"error": "Admin privileges required"}), 403
    
    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Build date filter
        date_filter = ""
        params = []
        
        if start_date:
            date_filter += " AND DATE(action_date) >= %s"
            params.append(start_date)
        
        if end_date:
            date_filter += " AND DATE(action_date) <= %s"
            params.append(end_date)
        
        # Get count by status
        cursor.execute(f"""
            SELECT status, COUNT(*) as count
            FROM transaction_history
            WHERE 1=1 {date_filter}
            GROUP BY status
        """, tuple(params))
        
        status_counts = {}
        for row in cursor.fetchall():
            status_counts[row["status"]] = row["count"]
        
        # Get count by payment type
        cursor.execute(f"""
            SELECT payment, COUNT(*) as count
            FROM transaction_history
            WHERE 1=1 {date_filter}
            GROUP BY payment
        """, tuple(params))
        
        payment_counts = {}
        for row in cursor.fetchall():
            payment = row["payment"] if row["payment"] else "unknown"
            payment_counts[payment] = row["count"]
        
        # Get count by admin
        cursor.execute(f"""
            SELECT processed_by, admin_name, COUNT(*) as count
            FROM transaction_history
            WHERE 1=1 {date_filter}
            GROUP BY processed_by, admin_name
        """, tuple(params))
        
        admin_counts = []
        for row in cursor.fetchall():
            admin_counts.append({
                "id": str(row["processed_by"]) if row["processed_by"] is not None else "",
                "name": str(row["admin_name"]) if row["admin_name"] is not None else "Unknown",
                "count": row["count"]
            })
        
        return jsonify({
            "status_counts": status_counts,
            "payment_counts": payment_counts,
            "admin_counts": admin_counts
        })
    except Exception as e:
        print(f"Error getting transaction history stats: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

if __name__ == '__main__':
    # Add mysql-connector-python to requirements.txt if not already there
    try:
        with open('requirements.txt', 'r') as f:
            requirements = f.read()
        
        if 'mysql-connector-python' not in requirements:
            with open('requirements.txt', 'a') as f:
                f.write('\nmysql-connector-python==8.0.33')
                
        if 'pyjwt' not in requirements:
            with open('requirements.txt', 'a') as f:
                f.write('\npyjwt==2.6.0')
    except:
        pass
    
    # Start the auto-reject background thread
    auto_reject_thread.start()
    
    app.run(host='0.0.0.0', port=5057, debug=True)