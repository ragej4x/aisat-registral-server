from flask import Flask, request, jsonify, send_from_directory, render_template, send_file
from flask_cors import CORS
import mysql.connector
from mail_handler import Generatecode
from datetime import datetime
import json
import os
import time
from mysql.connector import Error
from routes.auth import auth
import requests

app = Flask(__name__, static_url_path='/static', static_folder='static')
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": "*", "expose_headers": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]}})
app.register_blueprint(auth)

@app.before_first_request
def setup_tables():
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Create request_timers table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS request_timers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                request_id INT NOT NULL,
                timestamp DATETIME NOT NULL,
                admin_id VARCHAR(255),
                FOREIGN KEY (request_id) REFERENCES users(id)
            )
        """)
        
        db.commit()
        cursor.close()
    except Exception as e:
        print(f"Error setting up tables: {e}")

@app.after_request
def after_request(response):
    if 'Access-Control-Allow-Origin' not in response.headers:
        response.headers.add('Access-Control-Allow-Origin', '*')
    if 'Access-Control-Allow-Headers' not in response.headers:
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    if 'Access-Control-Allow-Methods' not in response.headers:
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

def get_db():
    connection = mysql.connector.connect(
        host='jimboyaczon.mysql.pythonanywhere-services.com',
        user='jimboyaczon', 
        password='fk9lratv',
        database='jimboyaczon$aisat-registral-db',
        autocommit=True
    )
    return connection

db = get_db()
cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(50) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    id_no VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL
)
""")

try:
    cursor.execute("SHOW COLUMNS FROM admins LIKE 'room_name'")
    if not cursor.fetchone():
        print("Adding room_name column to admins table")
        cursor.execute("ALTER TABLE admins ADD COLUMN room_name VARCHAR(100) DEFAULT NULL")
    
    cursor.execute("SHOW COLUMNS FROM admins LIKE 'contact_no'")
    if not cursor.fetchone():
        print("Adding contact_no column to admins table") 
        cursor.execute("ALTER TABLE admins ADD COLUMN contact_no VARCHAR(20) DEFAULT NULL")
        
    cursor.execute("SHOW COLUMNS FROM admins LIKE 'profile_pic'")
    if not cursor.fetchone():
        print("Adding profile_pic column to admins table")
        cursor.execute("ALTER TABLE admins ADD COLUMN profile_pic VARCHAR(255) DEFAULT NULL") 
        
    cursor.execute("SHOW COLUMNS FROM admins LIKE 'accepted_payments'")
    if not cursor.fetchone():
        print("Adding accepted_payments column to admins table")
        cursor.execute("ALTER TABLE admins ADD COLUMN accepted_payments TEXT DEFAULT NULL") 
        
    cursor.execute("SHOW COLUMNS FROM admins LIKE 'filter_preference'")
    if not cursor.fetchone():
        print("Adding filter_preference column to admins table")
        cursor.execute("ALTER TABLE admins ADD COLUMN filter_preference VARCHAR(20) DEFAULT 'all'")
        
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS call_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT NOT NULL,
        request_id INT NOT NULL,
        window_number VARCHAR(100) NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id),
        INDEX (admin_id),
        INDEX (timestamp)
    )
    """)
    print("Created call_log table if it didn't exist")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT NOT NULL,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admins(id),
        INDEX (admin_id),
        INDEX (last_activity)
    )
    """)
    print("Created sessions table if it didn't exist")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS schedule (
        id INT AUTO_INCREMENT PRIMARY KEY,
        date DATE NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'unavail',
        UNIQUE KEY (date)
    )
    """)
    print("Created schedule table if it didn't exist")
    
except mysql.connector.Error as err:
    print(f"Error checking/adding columns: {err}")

cursor.close()
db.close()

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'message': 'Internal server error', 'error': str(error)}), 500

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'message': 'Resource not found', 'error': str(error)}), 404

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({'message': 'Bad request', 'error': str(error)}), 400

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({'message': 'powta active na'})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    level = data.get('level')
    name = data.get('name')
    course = data.get('course')
    idno = data.get('idno')
    cell = data.get('cell') 
    email = data.get('email')
    password = data.get('password')

    if level == 'College':
        sql = """INSERT INTO users (level, name, course, strand, idno, cell, email, password)
                 VALUES (%s, %s, %s, NULL, %s, %s, %s, %s)"""
        values = (level, name, course, idno, cell, email, password)
    elif level == 'SHS':
        sql = """INSERT INTO users (level, name, course, strand, idno, cell, email, password)
                 VALUES (%s, %s, NULL, %s, %s, %s, %s, %s)"""
        values = (level, name, course, idno, cell, email, password)
    else:
        return jsonify({'message': 'Invalid level selected'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(sql, values)
        last_id = cursor.lastrowid
        cursor.close()
        db.close()
        return jsonify({'message': 'User Registered', 'id': last_id})
    except mysql.connector.Error as err:
        print('Register Error:', err)
        return jsonify({'message': 'Server Error'}), 500

@app.route('/api/student/login', methods=['POST'])
@app.route('/api/login', methods=['POST']) 
def student_login():
    try:
        data = request.json
        idno = data.get('idno')
        email = data.get('email')
        password = data.get('password')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE idno = %s AND email = %s AND password = %s", (idno, email, password))
        user = cursor.fetchone()

        if user:
            column_names = [desc[0] for desc in cursor.description]
            user_dict = dict(zip(column_names, user))
            
            # Check if flags field exists in the database
            try:
                cursor.execute("SELECT flags FROM users WHERE id = %s", (user_dict['id'],))
                flags_result = cursor.fetchone()
                
                if flags_result and flags_result[0]:
                    # If flags exist, add them to user data
                    user_dict['flags'] = flags_result[0].split(',') if isinstance(flags_result[0], str) else []
                else:
                    # Default empty array if no flags
                    user_dict['flags'] = []
                    
                print(f"User {user_dict['id']} flags: {user_dict['flags']}")
            except mysql.connector.Error as flags_err:
                # Handle case where flags column might not exist yet
                print(f"Error getting flags: {flags_err}")
                user_dict['flags'] = []
                
            cursor.close()
            db.close()
            
            return jsonify({
                'message': 'Login successful',
                'user': user_dict
            })
        else:
            cursor.close()
            db.close()
            return jsonify({'message': 'Invalid credentials'}), 401
    except mysql.connector.Error as err:
        print('Student login error:', err)
        return jsonify({'message': 'Database error', 'details': str(err)}), 500

@app.route('/api/admin/register', methods=['POST'])
def admin_register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    full_name = data.get('full_name')
    id_no = data.get('id_no')
    email = data.get('email')
    contact_no = data.get('contact_no')
    
    if not all([username, password, full_name, id_no, email, contact_no]):
        return jsonify({'message': 'All fields are required including contact number'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO admins (username, password, full_name, id_no, email, contact_no) VALUES (%s, %s, %s, %s, %s, %s)",
            (username, password, full_name, id_no, email, contact_no)
        )
        cursor.close()
        db.close()
        return jsonify({'message': 'Admin registered'})
    except mysql.connector.Error as err:
        print('Admin register error:', err)
        return jsonify({'message': 'Registration failed'}), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM admins WHERE username = %s AND password = %s", (username, password))
        admin = cursor.fetchone()

        if admin:
            column_names = [desc[0] for desc in cursor.description]
            admin_dict = dict(zip(column_names, admin))
            
            if 'password' in admin_dict:
                del admin_dict['password']
                
            try:
                cursor.execute("""
                    INSERT INTO sessions (admin_id, last_activity) 
                    VALUES (%s, NOW())
                    ON DUPLICATE KEY UPDATE last_activity = NOW()
                """, (admin_dict['id'],))
            except mysql.connector.Error as err:
                print(f"Error creating session: {err}")
            
            cursor.close()
            db.close()
                
            return jsonify({
                'message': 'Admin login successful',
                'admin': admin_dict
            })
        else:
            cursor.close()
            db.close()
            return jsonify({'message': 'Invalid admin credentials'}), 401
    except mysql.connector.Error as err:
        print(f"Database error in admin login: {err}")
        return jsonify({'message': 'Database error'}), 500
    except Exception as e:
        print(f"Server error in admin login: {e}")
        return jsonify({'message': 'Server error'}), 500

@app.route('/api/admin/profile', methods=['PUT'])
def update_admin_profile():
    try:
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'No authorization provided'}), 401
        
        update_admin_session(admin_id)
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE id = %s", (admin_id,))
        admin = cursor.fetchone()
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404
        
        if request.content_type and 'multipart/form-data' in request.content_type:
            data = request.form
        else:
            data = request.json
        
        update_fields = []
        values = []
        
        if 'full_name' in data:
            update_fields.append("full_name = %s")
            values.append(data['full_name'])
        
        if 'email' in data:
            update_fields.append("email = %s")
            values.append(data['email'])
        
        if 'id_no' in data:
            update_fields.append("id_no = %s")
            values.append(data['id_no'])
        
        if 'username' in data:
            update_fields.append("username = %s")
            values.append(data['username'])
            
        if 'contact_no' in data:
            update_fields.append("contact_no = %s")
            values.append(data['contact_no'])
            
        if 'room_name' in data:
            update_fields.append("room_name = %s")
            values.append(data['room_name'])
            
        if 'accepted_payments' in data:
            if isinstance(data['accepted_payments'], list):
                payments_json = json.dumps(data['accepted_payments'])
            else:
                try:
                    json.loads(data['accepted_payments'])
                    payments_json = data['accepted_payments']
                except:
                    payments_json = json.dumps([])
                    
            update_fields.append("accepted_payments = %s")
            values.append(payments_json)
        
        if 'old_password' in data and 'new_password' in data:
            cursor.execute("SELECT password FROM admins WHERE id = %s", (admin_id,))
            current_password = cursor.fetchone()[0]
            
            if data['old_password'] == current_password:
                update_fields.append("password = %s")
                values.append(data['new_password'])
            else:
                return jsonify({'message': 'Old password is incorrect'}), 400
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file:
                upload_dir = os.path.join('static', 'profiles')
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir)
                
                filename = f"admin_{admin_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"
                file_path = os.path.join(upload_dir, filename)
                file.save(file_path)
                
                update_fields.append("profile_pic = %s")
                values.append(filename)
        
        if not update_fields:
            return jsonify({'message': 'No fields to update'}), 400
        
        print(f"Updating admin {admin_id} with fields: {update_fields}")
        print(f"Values: {values}")
        
        sql = f"UPDATE admins SET {', '.join(update_fields)} WHERE id = %s"
        values.append(admin_id)
        
        cursor.execute(sql, values)
        db.commit()
        
        cursor.execute("SELECT * FROM admins WHERE id = %s", (admin_id,))
        updated_admin = cursor.fetchone()
        column_names = [desc[0] for desc in cursor.description]
        
        admin_dict = {}
        for i, name in enumerate(column_names):
            admin_dict[name] = updated_admin[i]
        
        print(f"Updated admin data: {admin_dict}")
        
        return jsonify({
            'message': 'Profile updated successfully',
            'admin': admin_dict
        })
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        db.rollback()
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/generate', methods=['POST'])
def generate():
    try:
        email = None
        skip_dev_email = False
        
        if request.form:
            email = request.form.get('email')
            skip_dev_email = request.form.get('skipDevEmail') == 'true'
        elif request.files or request.content_type and 'multipart/form-data' in request.content_type:
            email = request.form.get('email')
            skip_dev_email = request.form.get('skipDevEmail') == 'true'
        elif request.json:
            email = request.json.get('email')
            skip_dev_email = request.json.get('skipDevEmail') == True
        else:
            try:
                data = request.get_data(as_text=True)
                if '=' in data:
                    parts = data.split('=')
                    if len(parts) >= 2 and parts[0] == 'email':
                        email = parts[1]
                    if len(parts) >= 2 and parts[0] == 'skipDevEmail':
                        skip_dev_email = parts[1].lower() == 'true'
            except Exception:
                pass
        
        if not email:
            response = "Email is required"
            return response, 400
        
        code_generator = Generatecode(email, skip_dev_email=skip_dev_email)
        code = code_generator.get_code()
        
        try:
            from routes.auth import reset_codes
            reset_codes[email] = code
        except ImportError:
            pass
        except Exception:
            pass
        
        return code
        
    except Exception:
        response = "Error generating code"
        return response, 500

@app.route('/api/request', methods=['POST', 'OPTIONS'])
def handle_request():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'Preflight accepted'})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
        return response
    
    try:
        try:
            data = request.json
            if not data:
                return jsonify({'message': 'No JSON data received'}), 400
            print("Received data:", data)
        except Exception as e:
            print(f"Error parsing JSON: {str(e)}")
            return jsonify({'message': 'Invalid JSON data', 'error': str(e)}), 400

        required_fields = ['idno', 'request_id', 'track', 'section']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return jsonify({'message': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        schedule = None
        if 'schedule' in data and data['schedule']:
            try:
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"]:
                    try:
                        schedule = datetime.strptime(data['schedule'], fmt)
                        break
                    except ValueError:
                        continue
                
                if not schedule and 'T' in data['schedule']:
                    clean_schedule = data['schedule'].split('T')[0] + ' ' + data['schedule'].split('T')[1].split('.')[0]
                    schedule = datetime.strptime(clean_schedule, "%Y-%m-%d %H:%M:%S")
            except Exception as e:
                print(f"Schedule parsing error: {str(e)}")
        
        try:
            db = get_db()
            cursor = db.cursor()
        except Exception as e:
            print(f"Database connection error: {str(e)}")
            return jsonify({'message': 'Database connection error', 'error': str(e)}), 500
        
        sql = """
            UPDATE users 
            SET 
                request_id = %s,
                track = %s,
                section = %s,
                student_id = %s,
                schedule = COALESCE(%s, schedule),
                method = COALESCE(%s, method),
                payment = COALESCE(%s, payment),
                status = COALESCE(%s, 'pending')
            WHERE idno = %s
        """
        
        values = (
            data['request_id'],
            data['track'],
            data['section'],
            data.get('student_id', ''),
            schedule,
            data.get('method', ''),
            data.get('payment', ''),
            data.get('status', 'pending'),
            data['idno']
        )

        try:
            cursor.execute(sql, values)
            db.commit()
            
            if cursor.rowcount == 0:
                cursor.execute("SELECT COUNT(*) FROM users WHERE idno = %s", (data['idno'],))
                user_exists = cursor.fetchone()[0] > 0
                
                if not user_exists:
                    insert_sql = """
                        INSERT INTO users (idno, request_id, track, section, student_id, schedule, method, payment, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(insert_sql, values)
                    db.commit()
                    return jsonify({
                        'message': 'New registration added successfully',
                        'request_id': data['request_id']
                    }), 201
                else:
                    return jsonify({
                        'message': 'No changes made to user record',
                        'request_id': data['request_id']
                    }), 200
            
            return jsonify({
                'message': 'Registration updated successfully',
                'request_id': data['request_id']
            }), 200
            
        except mysql.connector.Error as err:
            print(f"SQL execution error: {str(err)}")
            db.rollback()
            return jsonify({'message': 'Database error', 'error': str(err)}), 500

    except mysql.connector.Error as err:
        print(f"MySQL error in request endpoint: {str(err)}")
        try:
            db.rollback()
        except:
            pass
        return jsonify({'message': 'Database error', 'error': str(err)}), 500
    except Exception as e:
        print(f"Unexpected error in request endpoint: {str(e)}")
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@app.route('/api/calendar', methods=['GET'])
def get_calendar():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT date, status FROM schedule")
        rows = cursor.fetchall()
        
        data = {}
        for row in rows:
            if isinstance(row[0], datetime):
                date_str = row[0].strftime('%Y-%m-%d')
            else:
                date_str = str(row[0])
            data[date_str] = row[1]
        
        cursor.close()
        db.close()
        return jsonify(data)
    except mysql.connector.Error as err:
        print('Fetch Calendar Error:', err)
        return jsonify({'message': 'Server error'}), 500

@app.route('/api/calendar', methods=['POST'])
def update_calendar():
    try:
        data = request.json
        date = data.get('date')
        status = data.get('status')
        
        if not date or not status:
            return jsonify({'message': 'Date and status are required'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT id FROM schedule WHERE date = %s", (date,))
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute("UPDATE schedule SET status = %s WHERE date = %s", (status, date))
        else:
            cursor.execute("INSERT INTO schedule (date, status) VALUES (%s, %s)", (date, status))
        
        cursor.close()
        db.close()
        return jsonify({'message': 'Calendar updated successfully'})
    except mysql.connector.Error as err:
        print('Update Calendar Error:', err)
        return jsonify({'message': 'Server error'}), 500

@app.route('/api/admin/schedule', methods=['GET'])
def admin_get_calendar():
    try:
        month = request.args.get('month')
        year = request.args.get('year')
        
        if not month or not year:
            return jsonify({'message': 'Month and year parameters are required'}), 400
        
        db = get_db()
        cursor = db.cursor()
        
        month_start = f"{year}-{month.zfill(2) if isinstance(month, str) else str(month).zfill(2)}-01"
        month_end = f"{year}-{month.zfill(2) if isinstance(month, str) else str(month).zfill(2)}-31"
        
        cursor.execute("SELECT date, status FROM schedule WHERE date BETWEEN %s AND %s", 
                      (month_start, month_end))
        rows = cursor.fetchall()
        
        schedule = {}
        for row in rows:
            if isinstance(row[0], datetime):
                date_str = row[0].strftime('%Y-%m-%d')
            else:
                date_str = str(row[0])
                
            if row[1] == 'unavail':
                status_idx = 0
            elif row[1] == 'open':
                status_idx = 1
            elif row[1] == 'full':
                status_idx = 2
            else:
                status_idx = 0
                
            schedule[date_str] = status_idx
        
        cursor.close()
        db.close()
        return jsonify({'status': 'success', 'schedule': schedule})
    except mysql.connector.Error as err:
        print('Admin Fetch Calendar Error:', err)
        return jsonify({'status': 'error', 'message': 'Server error'}), 500

@app.route('/api/admin/update-schedule', methods=['POST'])
def admin_update_calendar():
    try:
        data = request.json
        date = data.get('date')
        status = data.get('status')
        
        if date is None or status is None:
            return jsonify({'status': 'error', 'message': 'Date and status are required'}), 400
        
        status_map = ['unavail', 'open', 'full']
        if isinstance(status, int) and 0 <= status < len(status_map):
            status_str = status_map[status]
        else:
            status_str = str(status)
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT id FROM schedule WHERE date = %s", (date,))
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute("UPDATE schedule SET status = %s WHERE date = %s", (status_str, date))
        else:
            cursor.execute("INSERT INTO schedule (date, status) VALUES (%s, %s)", (date, status_str))
        
        cursor.close()
        db.close()
        return jsonify({'status': 'success', 'message': 'Schedule updated successfully'})
    except mysql.connector.Error as err:
        print('Admin Update Calendar Error:', err)
        return jsonify({'status': 'error', 'message': f'Server error: {str(err)}'}), 500

@app.route('/api/requests/pending', methods=['GET'])
def get_pending_requests():
    try:
        admin_id = request.headers.get('Authorization')
        
        if admin_id:
            update_admin_session(admin_id)
        
        accepted_payments = []
        if admin_id:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT accepted_payments FROM admins WHERE id = %s", (admin_id,))
            payment_result = cursor.fetchone()
            
            if payment_result and payment_result[0]:
                try:
                    accepted_payments = json.loads(payment_result[0])
                except:
                    accepted_payments = []
        
        if not accepted_payments:
            print("No payment filter applied, showing all pending requests")
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE status = 'pending' ORDER BY schedule ASC")
        else:
            print(f"Filtering by payment types: {accepted_payments}")
            placeholders = ', '.join(['%s'] * len(accepted_payments))
            query = f"""
                SELECT * FROM users 
                WHERE status = 'pending' 
                AND (payment IN ({placeholders}) OR payment IS NULL)
                ORDER BY 
                    CASE WHEN payment = 'priority' THEN 0 ELSE 1 END,
                    schedule ASC
            """
            db = get_db()
            cursor = db.cursor()
            cursor.execute(query, accepted_payments)
            
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        requests = [dict(zip(column_names, row)) for row in rows]
        
        cursor.close()
        db.close()
        
        print(f"Found {len(requests)} pending requests")
        
        return jsonify(requests), 200
    except mysql.connector.Error as err:
        print(f"Database error in pending requests: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error in pending requests: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/requests/rejected', methods=['GET'])
def get_rejected_requests():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE status = 'rejected'")
    rows = cursor.fetchall()
    column_names = [desc[0] for desc in cursor.description]
    requests = [dict(zip(column_names, row)) for row in rows]
    cursor.close()
    db.close()
    return jsonify(requests)

@app.route('/api/requests/<int:request_id>/status', methods=['PUT'])
def update_request_status(request_id):
    data = request.json
    new_status = data.get('status')

    if new_status not in ['pending', 'approved', 'rejected']:
        return jsonify({'message': 'Invalid status'}), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET status = %s WHERE id = %s", (new_status, request_id))
        db.commit()
        cursor.close()
        db.close()
        if cursor.rowcount == 0:
            return jsonify({'message': 'Request not found'}), 404
        return jsonify({'message': f'Request status updated to {new_status}'})
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/requests/<int:request_id>/reject', methods=['PUT'])
def reject_request(request_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE users
            SET status = 'rejected'
            WHERE id = %s
        """, (request_id,))
        db.commit()
        cursor.close()
        db.close()

        if cursor.rowcount == 0:
            return jsonify({'message': 'Request not found'}), 404

        return jsonify({'message': 'Request rejected successfully'}), 200
    except mysql.connector.Error as err:
        print('Reject Request Error:', err)
        return jsonify({'message': 'Server Error', 'error': str(err)}), 500

@app.route('/api/requests/<int:request_id>/delete', methods=['PUT'])
def delete_request(request_id):
    print(f"Received request to delete request with ID: {request_id}")
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            UPDATE users
            SET status = NULL
            WHERE id = %s
        """, (request_id,))
        db.commit()
        cursor.close()
        db.close()

        if cursor.rowcount == 0:
            return jsonify({'message': 'Request not found'}), 404

        return jsonify({'message': 'Request status reset successfully'}), 200
    except mysql.connector.Error as err:
        print('Delete Request Error:', err)
        return jsonify({'message': 'Server Error', 'error': str(err)}), 500

@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    user_id = data.get('userId')
    name = data.get('name')
    idno = data.get('idno')
    cell = data.get('cell')
    email = data.get('email')
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    print(f"UPDATE PROFILE REQUEST - Received data: {data}")
    print(f"User ID: {user_id}")
    print(f"Name: {name}")
    print(f"ID Number: {idno}")
    print(f"Cell: {cell}")
    print(f"Email: {email}")
    print(f"Password update requested: {bool(current_password and new_password)}")
    
    if not user_id:
        print("ERROR: Missing user ID")
        return jsonify({'message': 'Missing user ID'}), 400
        
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            print(f"ERROR: User not found: {user_id}")
            return jsonify({'message': 'User not found'}), 404
        
        column_names = [desc[0] for desc in cursor.description]
        user_dict = dict(zip(column_names, user))
        print(f"CURRENT USER DATA: {user_dict}")
        
        update_fields = []
        values = []
        
        if name is not None:
            print(f"Comparing name: new='{name}' vs current='{user_dict.get('name')}'")
            if name != user_dict.get('name'):
                update_fields.append("name = %s")
                values.append(name)
                print(f"Name will be updated to: {name}")
            
        if idno is not None:
            print(f"Comparing idno: new='{idno}' vs current='{user_dict.get('idno')}'")
            if idno != user_dict.get('idno'):
                cursor.execute("SELECT COUNT(*) FROM users WHERE idno = %s AND id != %s", (idno, user_id))
                count = cursor.fetchone()[0]
                if count > 0:
                    print(f"ERROR: ID number {idno} is already in use")
                    return jsonify({'message': 'ID number already in use'}), 400
                    
                update_fields.append("idno = %s")
                values.append(idno)
                print(f"ID Number will be updated to: {idno}")
            
        if email is not None:
            print(f"Comparing email: new='{email}' vs current='{user_dict.get('email')}'")
            if email != user_dict.get('email'):
                cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s AND id != %s", (email, user_id))
                count = cursor.fetchone()[0]
                if count > 0:
                    print(f"ERROR: Email {email} is already in use")
                    return jsonify({'message': 'Email already in use'}), 400
                    
                update_fields.append("email = %s")
                values.append(email)
                print(f"Email will be updated to: {email}")
            
        if cell is not None:
            print(f"Comparing cell: new='{cell}' vs current='{user_dict.get('cell')}'")
            if cell != user_dict.get('cell'):
                update_fields.append("cell = %s")
                values.append(cell)
                print(f"Cell will be updated to: {cell}")
            
        if current_password and new_password:
            stored_password = user_dict.get('password')
            print(f"Password update - Comparing current password (masked) vs stored password (masked)")
            print(f"Length comparison: current={len(str(current_password))}, stored={len(str(stored_password))}")
            
            if str(current_password) != str(stored_password):
                print("ERROR: Current password is incorrect")
                return jsonify({'message': 'Current password is incorrect'}), 400
                
            update_fields.append("password = %s")
            values.append(new_password)
            print("Password will be updated")
            
        if not update_fields:
            print("No changes detected, nothing to update")
            return jsonify({'message': 'No changes detected'}), 200
            
        values.append(user_id)
        
        sql = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
        print(f"SQL: {sql}")
        print(f"Values: {values}")
        
        cursor.execute(sql, values)
        db.commit()
        
        print("Profile update successful!")
        return jsonify({'message': 'Profile updated successfully'})
            
    except mysql.connector.Error as err:
        error_msg = str(err)
        print(f"DATABASE ERROR: {error_msg}")
        db.rollback()
        return jsonify({'message': 'Database error', 'details': error_msg}), 500

@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        column_names = [desc[0] for desc in cursor.description]
        user_dict = dict(zip(column_names, user))
        
        if 'password' in user_dict:
            del user_dict['password']
        
        # Check if flags field exists in the database and fetch flags
        try:
            # Try to get flags from the database
            cursor.execute("SELECT flags FROM users WHERE id = %s", (user_id,))
            flags_result = cursor.fetchone()
            
            if flags_result and flags_result[0]:
                # If flags exist, add them to user data
                user_dict['flags'] = flags_result[0].split(',') if isinstance(flags_result[0], str) else []
            else:
                # Default empty array if no flags
                user_dict['flags'] = []
                
            print(f"User {user_id} flags: {user_dict['flags']}")
        except mysql.connector.Error as flags_err:
            # Handle case where flags column might not exist yet
            print(f"Error getting flags: {flags_err}")
            user_dict['flags'] = []
        
        return jsonify({
            'message': 'User data retrieved successfully',
            'user': user_dict
        })
    except mysql.connector.Error as err:
        print(f"Database error getting user: {err}")
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/admin/<int:admin_id>', methods=['GET'])
def get_admin_details(admin_id):
    try:
        current_admin_id = request.headers.get('Authorization')
        if current_admin_id and str(current_admin_id) == str(admin_id):
            update_admin_session(admin_id)
            
        print(f"Fetching admin details for ID: {admin_id}")
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE id = %s", (admin_id,))
        admin = cursor.fetchone()
        
        if not admin:
            return jsonify({'message': 'Admin not found'}), 404
            
        column_names = [desc[0] for desc in cursor.description]
        admin_dict = dict(zip(column_names, admin))
        
        print(f"Get admin details: column_names = {column_names}")
        print(f"Get admin details: admin data (before cleaning) = {admin_dict}")
        
        if 'password' in admin_dict:
            del admin_dict['password']
        
        if 'contact_no' not in admin_dict or admin_dict['contact_no'] is None:
            print("WARNING: contact_no missing or null in admin data, setting to empty string")
            admin_dict['contact_no'] = ""
        
        if 'accepted_payments' in admin_dict and admin_dict['accepted_payments']:
            try:
                admin_dict['accepted_payments'] = json.loads(admin_dict['accepted_payments'])
            except:
                admin_dict['accepted_payments'] = []
        else:
            admin_dict['accepted_payments'] = []
        
        print(f"Get admin details: final admin data = {admin_dict}")
        
        return jsonify({
            'message': 'Admin data retrieved successfully',
            'admin': admin_dict
        })
    except mysql.connector.Error as err:
        print(f"Database error getting admin: {err}")
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/admin/room_name', methods=['PUT'])
def update_admin_room_name():
    try:
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'No authorization provided'}), 401
        
        update_admin_session(admin_id)
        
        data = request.json
        room_name = data.get('room_name')
        
        if not room_name:
            return jsonify({'message': 'Room name is required'}), 400
            
        print(f"Updating room_name for admin {admin_id} to: {room_name}")
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE admins SET room_name = %s WHERE id = %s", (room_name, admin_id))
        db.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'message': 'Admin not found or no changes made'}), 404
            
        cursor.execute("SELECT * FROM admins WHERE id = %s", (admin_id,))
        updated_admin = cursor.fetchone()
        column_names = [desc[0] for desc in cursor.description]
        
        admin_dict = dict(zip(column_names, updated_admin))
        
        if 'password' in admin_dict:
            del admin_dict['password']
            
        return jsonify({
            'message': 'Room name updated successfully',
            'admin': admin_dict
        })
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        db.rollback()
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/display/pending', methods=['GET'])
def get_display_pending_requests():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT u.*, a.room_name
            FROM users u
            LEFT JOIN admins a ON a.id = %s
            WHERE u.status = 'pending'
            ORDER BY 
                CASE WHEN u.payment = 'priority' THEN 0 ELSE 1 END,
                u.schedule ASC
        """, (request.headers.get('Authorization', '0'),))
        
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        
        requests = []
        for row in rows:
            request_dict = dict(zip(column_names, row))
            if not request_dict.get('request_id'):
                request_dict['request_id'] = f"RE-{str(request_dict['id']).zfill(4)}"
            requests.append(request_dict)
            
        return jsonify(requests), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': 'Database error'}), 500

@app.route('/api/display/call', methods=['POST'])
def call_request():
    try:
        data = request.json
        request_id = data.get('request_id')
        
        if not request_id:
            return jsonify({'message': 'Request ID is required'}), 400
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (request_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'Request not found'}), 404
            
        admin_id = request.headers.get('Authorization')
                        
        try:
            cursor.execute(
                "INSERT INTO call_log (admin_id, request_id, window_number) VALUES (%s, %s, %s)",
                (admin_id, request_id, "NONE")
            )
            db.commit()
            print(f"Call logged: Admin {admin_id} called request {request_id}")
        except mysql.connector.Error as log_err:
            print(f"Error logging call: {log_err}")
        
        cursor.execute("SELECT request_id FROM users WHERE id = %s", (request_id,))
        request_id_value = cursor.fetchone()[0]
        if not request_id_value:
            request_id_value = f"RE-{str(request_id).zfill(4)}"
            
        return jsonify({
            'message': 'Request called successfully',
            'request_id': request_id,
            'request_id_display': request_id_value
        })
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': 'Database error'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/display/current-call', methods=['GET'])
def get_current_call():
    return jsonify({
        'message': 'No active call',
        'requestId': None,
        'windowNumber': None
    })

@app.route('/queue/display', methods=['GET'])
@app.route('/display', methods=['GET'])
def serve_display_page():
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    return send_from_directory(static_dir, 'tv_display.html')

def update_admin_session(admin_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO sessions (admin_id, last_activity) 
            VALUES (%s, NOW())
            ON DUPLICATE KEY UPDATE last_activity = NOW()
        """, (admin_id,))
        cursor.close()
        db.close()
    except mysql.connector.Error as err:
        print(f"Error updating session: {err}")

@app.route('/api/admins/active', methods=['GET'])
def get_active_admins():
    try:
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("DELETE FROM sessions WHERE last_activity < DATE_SUB(NOW(), INTERVAL 5 MINUTE)")
        
        cursor.execute("""
            SELECT DISTINCT a.id, a.full_name, a.room_name, a.accepted_payments, a.filter_preference
            FROM admins a
            INNER JOIN sessions s ON a.id = s.admin_id
            WHERE a.room_name IS NOT NULL 
            AND a.room_name != ''
            AND s.last_activity > DATE_SUB(NOW(), INTERVAL 5 MINUTE)
        """)
        
        admins_data = cursor.fetchall()
        
        admins = []
        for admin in admins_data:
            accepted_payments = []
            if admin[3]:
                try:
                    accepted_payments = json.loads(admin[3])
                except:
                    print(f"Error parsing accepted_payments for admin {admin[0]}")
            
            filter_preference = admin[4] if admin[4] else "all"
            
            if filter_preference != "all":
                accepted_payments = [filter_preference]
            
            admins.append({
                'id': admin[0],
                'full_name': admin[1],
                'room_name': admin[2],
                'accepted_payments': accepted_payments,
                'filter_preference': filter_preference
            })
        
        cursor.close()
        db.close()
        
        print(f"Found {len(admins)} active admins with rooms")
        return jsonify(admins), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': 'Database error'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/logout', methods=['POST'])
def admin_logout():
    try:
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'No authorization provided'}), 401
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM sessions WHERE admin_id = %s", (admin_id,))
        db.commit()
        
        cursor.execute("UPDATE admins SET room_name = NULL WHERE id = %s", (admin_id,))
        db.commit()
        
        return jsonify({'message': 'Logged out successfully'}), 200
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        db.rollback()
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/filter_preference', methods=['PUT'])
def update_filter_preference():
    try:
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'No authorization provided'}), 401
        
        update_admin_session(admin_id)
        
        data = request.json
        filter_value = data.get('filter')
        
        if not filter_value:
            return jsonify({'message': 'Filter value is required'}), 400
            
        valid_filters = ['all', 'priority', 'express', 'promissory']
        if filter_value not in valid_filters:
            return jsonify({'message': 'Invalid filter value'}), 400
            
        print(f"Updating filter preference for admin {admin_id} to: {filter_value}")
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE admins SET filter_preference = %s WHERE id = %s", (filter_value, admin_id))
        db.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'message': 'Admin not found or no changes made'}), 404
            
        return jsonify({
            'message': 'Filter preference updated successfully',
            'filter': filter_value
        })
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        db.rollback()
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/display/current-calls', methods=['GET'])
def get_current_calls():
    try:
        db = get_db()
        cursor = db.cursor()
        
        # Modified query to include timer information
        cursor.execute("""
            SELECT c.request_id, c.timestamp, u.request_id as display_id,
                   t.timestamp as timer_timestamp, CASE WHEN t.timestamp IS NOT NULL THEN 1 ELSE 0 END as timer_active,
                   u.idno
            FROM call_log c
            LEFT JOIN users u ON c.request_id = u.id
            LEFT JOIN (
                SELECT request_id, MAX(timestamp) as timestamp 
                FROM request_timers 
                GROUP BY request_id
            ) t ON c.request_id = t.request_id
            ORDER BY c.timestamp DESC
            LIMIT 10
        """)
        
        result = []
        calls = cursor.fetchall()
        
        for call in calls:
            request_id = call[0]
            timestamp = call[1]
            display_id = call[2]
            timer_timestamp = call[3]
            timer_active = call[4]
            idno = call[5]
            
            if not display_id:
                display_id = f"RE-{str(request_id).zfill(4)}"
            
            if not any(r['request_id'] == request_id for r in result):
                result.append({
                    'request_id': request_id,
                    'request_id_display': display_id,
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    'timer_timestamp': timer_timestamp.isoformat() if timer_timestamp else None,
                    'timer_active': bool(timer_active),
                    'idno': idno
                })
            
        return jsonify(result), 200
            
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify([
            {
                'request_id': 64,
                'request_id_display': 'RE-0064',
                'timestamp': datetime.now().isoformat(),
                'timer_active': False,
                'timer_timestamp': None
            }
        ]), 200
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify([
            {
                'request_id': 64,
                'request_id_display': 'RE-0064',
                'timestamp': datetime.now().isoformat(),
                'timer_active': False,
                'timer_timestamp': None
            }
        ]), 200

@app.route('/api/reset-password', methods=['POST', 'OPTIONS'])
def direct_reset_password():
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        return response
        
    try:
        email = None
        code = None
        new_password = None
        skip_dev_email = False
        
        if request.form:
            email = request.form.get('email')
            code = request.form.get('code')
            new_password = request.form.get('newPassword')
            skip_dev_email = request.form.get('skipDevEmail') == 'true'
        elif request.json:
            data = request.json
            email = data.get('email')
            code = data.get('code')
            new_password = data.get('newPassword')
            skip_dev_email = data.get('skipDevEmail') == True
        else:
            try:
                data = request.get_data(as_text=True)
            except Exception:
                pass
                
        if not email or not code or not new_password:
            response = jsonify({'success': False, 'message': 'Email, code, and new password are required'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        from routes.auth import reset_codes
        stored_code = reset_codes.get(email)
        
        if not stored_code:
            response = jsonify({'success': False, 'message': 'No verification code found for this email. Please request a new code.'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        if stored_code != code:
            response = jsonify({'success': False, 'message': 'Invalid verification code. Please try again.'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 400
            
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('UPDATE users SET password = %s WHERE email = %s', 
                         (new_password, email))
            db.commit()
            cursor.close()
            db.close()
            
            if email in reset_codes:
                del reset_codes[email]
                
            from mail_handler import send_password_reset_confirmation
            try:
                send_password_reset_confirmation(email, skip_dev_email)
            except Exception:
                pass
            
            response = jsonify({'success': True, 'message': 'Password has been reset successfully'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
            
        except Exception:
            response = jsonify({'success': False, 'message': 'Database error occurred while resetting password'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response, 500
            
    except Exception:
        response = jsonify({'success': False, 'message': 'Server error occurred'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

@app.route('/api/onesignal-direct', methods=['POST'])
def direct_onesignal_notification():
    try:
        data = request.json
        message = data.get('message', 'Test notification')
        title = data.get('title', 'AISAT Queue')
        subtitle = data.get('subtitle')
        custom_data = data.get('data')
        target_type = data.get('target_type', 'broadcast')
        player_id = data.get('player_id')
        
        onesignal_app_id = "31f743ae-2b8b-4043-83f8-04d49ceb147f"
        onesignal_rest_api_key = "os_v2_app_gh3uhlrlrnaeha7yatkjz2yup755s5km2ybett5v73dpeyqsbu5lczz7hvki6jcj2dloybujiilu5qa5ra3zspsdn7acble6bb574sq"
        
        payload = {
            "app_id": onesignal_app_id,
            "headings": {"en": title},
            "contents": {"en": message},
            "priority": 10,
            "ttl": 600,
            "android_group": "aisat_queue",
            "small_icon": "ic_stat_onesignal_default", 
            "large_icon": "ic_onesignal_large_icon_default",
            "android_accent_color": "FF2ECC71",
            "android_visibility": 1
        }
        
        if subtitle:
            payload["subtitle"] = {"en": subtitle}
            
        if custom_data:
            payload["data"] = custom_data
            
        if target_type == 'player_id' and player_id:
            payload["include_player_ids"] = [player_id]
            print(f"Targeting specific player ID: {player_id}")
        else:
            payload["included_segments"] = ["All"]
            print("Targeting all users (broadcast)")
        
        print(f"Sending direct OneSignal notification: {json.dumps(payload)}")
        
        response = requests.post(
            "https://onesignal.com/api/v1/notifications",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": f"Bearer {onesignal_rest_api_key}"
            },
            data=json.dumps(payload)
        )
        
        print(f"OneSignal direct response: {response.status_code}")
        print(f"Response body: {response.text}")
        
        return jsonify({
            'message': 'Notification sent',
            'onesignal_status': response.status_code,
            'onesignal_response': response.json() if response.text else None
        }), 200
    except Exception as e:
        print(f"Error in direct OneSignal notification: {str(e)}")
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/tv')
def tv_display():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    project_root = os.path.dirname(current_dir)
    
    html_path = os.path.join(project_root, 'admin', 'tv_display.html')
    
    if os.path.exists(html_path):
        return send_file(html_path)
    else:
        return "Pucha bat ayaw", 404

@app.route('/api/admin/toggle-priority', methods=['PUT'])
def toggle_user_priority():
    try:
        # Verify admin authorization
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'Admin authorization required'}), 401

        update_admin_session(admin_id)
        
        # Get user ID from request
        data = request.json
        user_id = data.get('user_id')
        priority_status = data.get('status', True)  # Default to granting priority if not specified
        
        if not user_id:
            return jsonify({'message': 'User ID is required'}), 400
            
        # Connect to database
        db = get_db()
        cursor = db.cursor()
        
        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
            
        # Get current flags
        cursor.execute("SELECT flags FROM users WHERE id = %s", (user_id,))
        flags_result = cursor.fetchone()
        
        current_flags = []
        if flags_result and flags_result[0]:
            current_flags = flags_result[0].split(',')
        
        # Add or remove priority_user flag
        if priority_status and 'priority_user' not in current_flags:
            current_flags.append('priority_user')
        elif not priority_status and 'priority_user' in current_flags:
            current_flags.remove('priority_user')
        
        # Update flags in database
        new_flags = ','.join(current_flags) if current_flags else None
        
        try:
            cursor.execute("UPDATE users SET flags = %s WHERE id = %s", (new_flags, user_id))
            db.commit()
            
            action = "granted" if priority_status else "removed"
            print(f"Admin {admin_id} {action} priority access for user {user_id}")
            
            return jsonify({
                'message': f'Priority access {action} successfully',
                'user_id': user_id,
                'flags': current_flags
            })
        except mysql.connector.Error as update_err:
            # Check if flags column doesn't exist
            if "Unknown column 'flags'" in str(update_err):
                try:
                    # Add flags column if it doesn't exist
                    cursor.execute("ALTER TABLE users ADD COLUMN flags VARCHAR(255) DEFAULT NULL")
                    db.commit()
                    print("Added flags column to users table")
                    
                    # Try update again
                    cursor.execute("UPDATE users SET flags = %s WHERE id = %s", (new_flags, user_id))
                    db.commit()
                    
                    action = "granted" if priority_status else "removed"
                    print(f"Admin {admin_id} {action} priority access for user {user_id} (after adding column)")
                    
                    return jsonify({
                        'message': f'Priority access {action} successfully',
                        'user_id': user_id,
                        'flags': current_flags
                    })
                except mysql.connector.Error as err:
                    print(f"Error adding flags column: {err}")
                    db.rollback()
                    return jsonify({'message': f'Database error: {str(err)}'}), 500
            else:
                print(f"Error updating user flags: {update_err}")
                db.rollback()
                return jsonify({'message': f'Database error: {str(update_err)}'}), 500
                
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/users/priority', methods=['GET'])
def get_priority_users():
    try:
        # Verify admin authorization
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'Admin authorization required'}), 401

        update_admin_session(admin_id)
        
        # Connect to database
        db = get_db()
        cursor = db.cursor()
        
        # Get users with priority_user flag
        cursor.execute("""
            SELECT id, name, idno, email, cell, flags
            FROM users 
            WHERE flags LIKE '%priority_user%'
            ORDER BY name ASC
        """)
        
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        
        priority_users = []
        for row in rows:
            user_dict = dict(zip(column_names, row))
            
            # Convert flags from comma-separated string to array
            if user_dict.get('flags'):
                user_dict['flags'] = user_dict['flags'].split(',')
            else:
                user_dict['flags'] = []
                
            priority_users.append(user_dict)
        
        cursor.close()
        db.close()
        
        return jsonify(priority_users), 200
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/toggle-priority-by-idno', methods=['PUT'])
def toggle_user_priority_by_idno():
    try:
        # Verify admin authorization
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'Admin authorization required'}), 401

        update_admin_session(admin_id)
        
        # Get parameters from request
        data = request.json
        idno = data.get('idno')
        priority_status = data.get('status', True)  # Default to granting priority if not specified
        
        if not idno:
            return jsonify({'message': 'Student ID Number (idno) is required'}), 400
            
        # Connect to database
        db = get_db()
        cursor = db.cursor()
        
        # Find user by ID number
        cursor.execute("SELECT id, name, idno, flags FROM users WHERE idno = %s", (idno,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'message': f'User with ID number {idno} not found'}), 404
            
        user_id = user[0]  # Get the database ID from the result
        user_name = user[1]
        user_idno = user[2]
        current_flags = user[3].split(',') if user[3] else []
        
        # Add or remove priority_user flag
        if priority_status and 'priority_user' not in current_flags:
            current_flags.append('priority_user')
        elif not priority_status and 'priority_user' in current_flags:
            current_flags.remove('priority_user')
        
        # Update flags in database
        new_flags = ','.join(current_flags) if current_flags else None
        
        try:
            cursor.execute("UPDATE users SET flags = %s WHERE id = %s", (new_flags, user_id))
            db.commit()
            
            action = "granted" if priority_status else "removed"
            print(f"Admin {admin_id} {action} priority access for user {user_id} (ID number: {idno})")
            
            return jsonify({
                'message': f'Priority access {action} successfully for {user_name}',
                'user_id': user_id,
                'idno': user_idno,
                'flags': current_flags
            })
        except mysql.connector.Error as update_err:
            print(f"Error updating user flags: {update_err}")
            db.rollback()
            return jsonify({'message': f'Database error: {str(update_err)}'}), 500
                
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/users/search', methods=['GET'])
def search_users():
    try:
        # Verify admin authorization
        admin_id = request.headers.get('Authorization')
        if not admin_id:
            return jsonify({'message': 'Admin authorization required'}), 401

        update_admin_session(admin_id)
        
        # Get search term
        name_search = request.args.get('name', '')
        if not name_search:
            return jsonify({'message': 'Search term is required'}), 400
            
        # Connect to database
        db = get_db()
        cursor = db.cursor()
        
        # Search users by name (case insensitive)
        search_term = f"%{name_search}%"
        cursor.execute("""
            SELECT id, name, idno, email, level, flags
            FROM users 
            WHERE name LIKE %s
            ORDER BY name ASC
            LIMIT 20
        """, (search_term,))
        
        rows = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
        
        users = []
        for row in rows:
            user_dict = dict(zip(column_names, row))
            
            # Convert flags from comma-separated string to array if not None
            if user_dict.get('flags'):
                user_dict['flags'] = user_dict['flags'].split(',')
            else:
                user_dict['flags'] = []
                
            users.append(user_dict)
        
        cursor.close()
        db.close()
        
        return jsonify(users), 200
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/display/skip', methods=['POST'])
def skip_request():
    try:
        data = request.json
        request_id = data.get('request_id')
        admin_id = request.headers.get('Authorization')
        
        if not request_id:
            return jsonify({'message': 'Request ID is required'}), 400
            
        db = get_db()
        cursor = db.cursor()
        
        # Check if the request exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (request_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({'message': 'Request not found'}), 404
        
        # Add a timer for the request
        cursor.execute(
            "INSERT INTO request_timers (request_id, timestamp, admin_id) VALUES (%s, %s, %s)",
            (request_id, datetime.now(), admin_id)
        )
        
        db.commit()
        
        return jsonify({'message': 'Timer started successfully'}), 200
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify({'message': f'Database error: {str(err)}'}), 500
    except Exception as e:
        print(f"Server error: {e}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(
        host="0.0.0.0",
        port=3000,
        debug=False,
        threaded=True,
        use_reloader=False
    )

