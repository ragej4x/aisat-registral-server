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
    from email_config import SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD
except ImportError:
    # Default values if config file is missing
    SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
    SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "")

app = Flask(__name__)
CORS(app)

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
# -------------------------

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "aisat_db"
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
        cursor.execute("SELECT id, full_name, email, id_no, contact_no, room_name FROM admins WHERE id = %s", (user_id,))
        admin = cursor.fetchone()
        
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        # Convert to a safe dictionary
        admin_data = {
            "id": str(admin["id"]) if admin["id"] is not None else "",
            "full_name": str(admin["full_name"]) if admin["full_name"] is not None else "",
            "email": str(admin["email"]) if admin["email"] is not None else "",
            "id_no": str(admin["id_no"]) if admin["id_no"] is not None else "",
            "contact_no": str(admin["contact_no"]) if admin["contact_no"] is not None else "",
            "room_name": str(admin["room_name"]) if admin["room_name"] is not None else ""
        }
        
        return jsonify(admin_data)
    
    except Exception as e:
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
    while True:
        try:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                
                # Find users with status 'oncall' and counter <= 0
                cursor.execute("SELECT id FROM users WHERE status = 'oncall' AND counter <= 0")
                expired_users = cursor.fetchall()
                
                # Auto-reject each expired user
                for user in expired_users:
                    user_id = user['id']
                    cursor.execute("UPDATE users SET status = 'rejected', counter = NULL WHERE id = %s", (user_id,))
                
                conn.commit()
                cursor.close()
                conn.close()
            
            # Decrement counter for all oncall users
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET counter = counter - 1 WHERE status = 'oncall' AND counter > 0")
                conn.commit()
                cursor.close()
                conn.close()
                
        except Exception as e:
            print(f"Error in auto-reject background task: {e}")
        
        # Sleep for 1 minute before checking again
        time.sleep(60)

# Start the background task in a separate thread
auto_reject_thread = threading.Thread(target=auto_reject_expired_users, daemon=True)

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

@app.route('/api/admins/active', methods=['GET'])
def get_active_admins():
    """Get all active admins for the TV display"""
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get all admins that are currently online (have an active status)
        cursor.execute("""
            SELECT a.id, a.full_name, a.room_name, a.email, a.contact_no, a.last_active
            FROM admins a 
            WHERE a.status = 'online' 
            AND a.last_active > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        """)
        
        admins_raw = cursor.fetchall()
        
        # Process admin data and include filter settings
        admins = []
        for admin in admins_raw:
            # Get filter settings from localStorage on client side
            # Here we're just providing default values
            admin_data = {
                "id": admin["id"],
                "full_name": admin["full_name"],
                "room_name": admin["room_name"] or f"Window {admin['id']}",
                "email": admin["email"],
                "contact_no": admin["contact_no"],
                "filter_settings": {
                    "express": True,
                    "priority": True,
                    "regular": True
                }
            }
            
            # Get admin's filter settings from the database if available
            cursor.execute("SELECT settings FROM admin_settings WHERE admin_id = %s", (admin["id"],))
            settings_row = cursor.fetchone()
            
            if settings_row and settings_row.get("settings"):
                try:
                    import json
                    settings = json.loads(settings_row["settings"])
                    if "filter_settings" in settings:
                        admin_data["filter_settings"] = settings["filter_settings"]
                except:
                    # If there's an error parsing settings, use defaults
                    pass
                    
            admins.append(admin_data)
        
        return jsonify({"admins": admins})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route('/api/queue/all', methods=['GET'])
def get_all_queue_data():
    """Get all queue data for the TV display"""
    conn, cursor = None, None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # Get express queue users
        cursor.execute("""
            SELECT id, idno, name, request_id, status, counter, assigned_to 
            FROM users 
            WHERE status = 'pending' AND payment = 'express'
            ORDER BY schedule ASC
        """)
        express_users = cursor.fetchall()
        
        # Get priority queue users
        cursor.execute("""
            SELECT id, idno, name, request_id, status, counter, assigned_to 
            FROM users 
            WHERE status = 'pending' AND payment = 'priority'
            ORDER BY schedule ASC
        """)
        priority_users = cursor.fetchall()
        
        # Get regular queue users
        cursor.execute("""
            SELECT id, idno, name, request_id, status, counter, assigned_to 
            FROM users 
            WHERE status = 'pending' AND payment = 'regular'
            ORDER BY schedule ASC
        """)
        regular_users = cursor.fetchall()
        
        # Get currently serving users
        cursor.execute("""
            SELECT u.id, u.idno, u.name, u.request_id, u.status, u.counter, u.assigned_to, a.id as admin_id
            FROM users u
            JOIN admins a ON u.assigned_to = a.id
            WHERE u.status = 'oncall'
        """)
        currently_serving_raw = cursor.fetchall()
        
        # Format currently serving as a dictionary with admin_id as key
        currently_serving = {}
        for user in currently_serving_raw:
            admin_id = user.get("admin_id")
            if admin_id:
                currently_serving[admin_id] = {
                    "id": user.get("id"),
                    "idno": user.get("idno"),
                    "name": user.get("name"),
                    "request_id": user.get("request_id"),
                    "status": user.get("status"),
                    "counter": user.get("counter")
                }
        
        return jsonify({
            "express": express_users,
            "priority": priority_users,
            "regular": regular_users,
            "currently_serving": currently_serving
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
