from flask import Blueprint, request, jsonify, session
import mysql.connector
import hashlib
import secrets
import traceback
import sys

auth = Blueprint('auth', __name__)

reset_codes = {}

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root', 
            password='',
            database='aisat_registral_db'
        )
        print("Database connection created successfully")
        return connection
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}", file=sys.stderr)
        raise

def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@auth.route('/api/auth/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    print(f"Handling OPTIONS request for /api/auth/{path}")
    response = jsonify({'status': 'ok'})
    return add_cors_headers(response)

@auth.route('/api/auth/reset-password', methods=['OPTIONS'])
def reset_password_options():
    print("Handling OPTIONS request for reset-password")
    response = jsonify({'status': 'ok'})
    return add_cors_headers(response)

@auth.after_request
def after_request(response):
    return add_cors_headers(response)

@auth.route('/api/auth/send-reset-code', methods=['POST'])
def send_reset_code():
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({'success': False, 'message': 'Email not found'}), 404
        except Exception as db_error:
            print(f"Database error: {db_error}")
            traceback.print_exc()
        
        from mail_handler import Generatecode
        code_generator = Generatecode(email)
        code = code_generator.get_code()
        
        reset_codes[email] = code
        print(f"Stored code {code} for {email} in reset_codes")
        
        return jsonify({
            'success': True, 
            'message': 'Verification code sent successfully',
            'code': code
        })
    
    except Exception as e:
        print(f"Error sending reset code: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to send verification code: {str(e)}'}), 500

@auth.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        email = data.get('email')
        code = data.get('code')
        new_password = data.get('newPassword')
        
        if not email or not code or not new_password:
            return jsonify({'success': False, 'message': 'Email, code, and new password are required'}), 400
        
        stored_code = reset_codes.get(email)
        if not stored_code:
            return jsonify({'success': False, 'message': 'No verification code found for this email. Please request a new code.'}), 400
            
        if stored_code != code:
            return jsonify({'success': False, 'message': 'Invalid verification code. Please try again.'}), 400
        
        try:
            salt = secrets.token_hex(8)
            hashed_password = hashlib.sha256((new_password + salt).encode()).hexdigest()
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET password = %s, salt = %s WHERE email = %s', 
                         (hashed_password, salt, email))
            conn.commit()
            cursor.close()
            conn.close()
            
            if email in reset_codes:
                del reset_codes[email]
            
            return jsonify({'success': True, 'message': 'Password has been reset successfully'})
        except Exception as db_error:
            print(f"Database error during password reset: {db_error}")
            traceback.print_exc()
            return jsonify({'success': False, 'message': f'Database error: {str(db_error)}'}), 500
    
    except Exception as e:
        print(f"Error resetting password: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to reset password: {str(e)}'}), 500 