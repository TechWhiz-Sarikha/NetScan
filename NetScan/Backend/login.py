from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib

app = Flask(__name__)
CORS(app)

DB_NAME = "users.db"

# Function to connect to SQLite3
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Create users table if not exists
def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
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

create_table()  # Ensure table exists on startup

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Route for User Signup
@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if not (username and email and password and confirm_password):
            return jsonify({"error": "All fields are required"}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match!"}), 400

        hashed_pw = hash_password(password)
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"error": "Username or Email already registered!"}), 400

        # Insert new user
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_pw))
        conn.commit()
        conn.close()

        return jsonify({"message": "Signup successful!", "username": username}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route for User Login
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not (email and password):
            return jsonify({"error": "Both email and password are required"}), 400

        hashed_pw = hash_password(password)
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if email and password match
        cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_pw))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({"message": "Login successful!", "username": user["username"]}), 200
        else:
            return jsonify({"error": "Invalid email or password!"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
