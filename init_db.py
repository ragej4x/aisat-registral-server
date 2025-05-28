#!/usr/bin/env python
"""
Database initialization script
"""

import mysql.connector
import sys
import traceback

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
}

def init_database():
    """Initialize database and required tables"""
    try:
        print("Creating database connection...")
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("Creating database if it doesn't exist...")
        cursor.execute("CREATE DATABASE IF NOT EXISTS aisat_registral_db")
        cursor.execute("USE aisat_registral_db")
        
        print("Creating users table if it doesn't exist...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            level VARCHAR(50),
            name VARCHAR(100),
            course VARCHAR(100),
            strand VARCHAR(100),
            idno VARCHAR(50) UNIQUE,
            cell VARCHAR(20),
            email VARCHAR(100) UNIQUE,
            password VARCHAR(255),
            salt VARCHAR(50),
            request_id VARCHAR(50),
            track VARCHAR(100),
            section VARCHAR(50),
            student_id VARCHAR(50),
            schedule DATETIME,
            method VARCHAR(50),
            payment VARCHAR(50),
            status VARCHAR(20)
        )
        """)
        
        print("Checking if test user exists...")
        cursor.execute("SELECT * FROM users WHERE email = 'test@example.com'")
        user = cursor.fetchone()
        
        if not user:
            print("Creating test user...")
            cursor.execute("""
            INSERT INTO users (level, name, idno, cell, email, password, payment, status)
            VALUES ('College', 'Test User', 'TEST-123', '1234567890', 'test@example.com', 'password123', 'regular', 'pending')
            """)
            conn.commit()
            print("Test user created successfully!")
        else:
            print("Test user already exists")
        
        cursor.close()
        conn.close()
        print("Database initialization completed successfully!")
        return True
    
    except mysql.connector.Error as err:
        print(f"MySQL error: {err}")
        traceback.print_exc()
        return False
    
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Starting database initialization...")
    success = init_database()
    if success:
        print("Database initialization completed successfully!")
    else:
        print("Database initialization failed. Check the error messages above.")
        sys.exit(1) 