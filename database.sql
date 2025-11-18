CREATE DATABASE IF NOT EXISTS Clearway_Cyber_db;
USE Clearway_Cyber_db;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,    
  name VARCHAR(100),
  bio TEXT,   -- Added for Stored XSS (required for task)
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO users (email, password, name, bio) 
VALUES ('admin@clearway.com', 'admin123', 'Clearway Admin', 'Default admin bio - vulnerable to XSS');
