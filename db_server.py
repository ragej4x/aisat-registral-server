import os
import subprocess
import time
import threading
import sys


print("=========================================")

print("MYSQL DATABASE SERVER")
print("Server is starting...")
print()
print("MINIMIZE THIS WINDOW DO NOT CLOSE IT")

print("=========================================")

def start_xampp_server():
    print("Starting XAMPP server...")
    os.system("cmd /K start /B data\\xampp\\xampp_start.exe")
    
def is_mysql_ready():
    try:
        result = subprocess.call(["data\\xampp\\mysql\\bin\\mysqladmin.exe", "ping", "-u", "root"], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result == 0  
    except Exception as e:
        print(f"Error checking MySQL status: {e}")
        return False

def database_exists(db_name):
    try:
        cmd = f"data\\xampp\\mysql\\bin\\mysql.exe -u root -e \"SHOW DATABASES LIKE '{db_name}';\""
        result = os.popen(cmd).read()
        return db_name in result
    except Exception as e:
        print(f"Error checking database existence: {e}")
        return False

def import_database():
    print("Waiting for MySQL to start...")
    max_attempts = 12  
    attempts = 0
    while attempts < max_attempts:
        if is_mysql_ready():
            print("MySQL is ready!")
            break
        print(f"MySQL not ready yet. Attempt {attempts+1}/{max_attempts}")
        time.sleep(10)
        attempts += 1
    
    if attempts >= max_attempts:
        print("ERROR: MySQL did not start in the expected time.")
        print("Please start MySQL manually and try importing the database later.")
        return
    
    print("Checking database status...")
    try:
        mysql_path = "data\\xampp\\mysql\\bin\\mysql.exe"
        sql_file = "aisat_registral_db.sql"
        
        if not os.path.exists(mysql_path):
            print(f"ERROR: MySQL client not found at {mysql_path}")
            return
            
        if not os.path.exists(sql_file):
            print(f"ERROR: SQL file not found at {sql_file}")
            return
        
        if database_exists("aisat_registral_db"):
            print("Database 'aisat_registral_db' already exists. Skipping import.")
            print("=========================================")
            print("Setup complete. You can minimize this window but DO NOT close it.")
            print("=========================================")
            return
        
        print("Creating database 'aisat_registral_db'...")
        create_db_cmd = f"{mysql_path} -u root -e \"CREATE DATABASE IF NOT EXISTS aisat_registral_db;\""
        os.system(create_db_cmd)
        time.sleep(2)
        
        print("Importing SQL data into aisat_registral_db database...")
        import_cmd = f"{mysql_path} -u root aisat_registral_db < {sql_file}"
        exit_code = os.system(import_cmd)
        
        if exit_code != 0:
            print("Error importing database. Trying alternative method...")
            with open("import_db.bat", "w") as batch:
                batch.write("@echo off\n")
                batch.write("echo Creating database...\n")
                batch.write(f"{mysql_path} -u root -e \"CREATE DATABASE IF NOT EXISTS aisat_registral_db;\"\n")
                batch.write("echo Importing data...\n")
                batch.write(f"{mysql_path} -u root aisat_registral_db < {sql_file}\n")
            
            os.system("import_db.bat")
        else:
            print("Database imported successfully.")
    
    except Exception as e:
        print(f"Exception during database import: {e}")
        print("Database import failed. Please try manually later.")
    
    print("=========================================")
    print("Setup complete. You can minimize this window but DO NOT close it.")
    print("=========================================")

xampp_thread = threading.Thread(target=start_xampp_server)
import_thread = threading.Thread(target=import_database)

xampp_thread.start()
time.sleep(5)  
import_thread.start()

import_thread.join()
    