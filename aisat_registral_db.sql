CREATE DATABASE IF NOT EXISTS aisat_db;
USE aisat_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,

    name VARCHAR(100) NOT NULL,
    course VARCHAR(100) DEFAULT NULL,  
    strand VARCHAR(100) DEFAULT NULL,   
    level ENUM('College', 'SHS') NOT NULL, 
    idno VARCHAR(50) NOT NULL UNIQUE,
    cell VARCHAR(20),
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    request_id VARCHAR(50) UNIQUE DEFAULT NULL,
    track VARCHAR(100) DEFAULT NULL,
    section VARCHAR(50) DEFAULT NULL,
    student_id VARCHAR(50) DEFAULT NULL,
    schedule DATETIME DEFAULT NULL,
    method ENUM('full', 'installment') DEFAULT NULL,
    payment ENUM( 'express', 'regular', 'priority') DEFAULT NULL,
    flags ENUM('priority_user') DEFAULT NULL,
    status ENUM('pending', 'approved', 'rejected', 'oncall') DEFAULT NULL,
    counter INT DEFAULT NULL,
    new_user ENUM('yes', 'no') DEFAULT 'yes'
);

-- Add assigned_to column if it doesn't exist
ALTER TABLE users ADD COLUMN IF NOT EXISTS assigned_to INT DEFAULT NULL;

CREATE TABLE schedule (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL,
    time TIME NOT NULL,
    status ENUM('full', 'open', 'unavail') NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    id_no VARCHAR(50) NOT NULL,
    contact_no VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    room_name VARCHAR(100) DEFAULT NULL,
    is_active ENUM('yes', 'no') DEFAULT 'no'
);




















