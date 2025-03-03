import sqlite3
import hashlib

DB_NAME = "users.db"

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to set up the database
def setup_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # ✅ Ensure the `users` table has username, email, and password
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

setup_database()  # Call this when the server starts
