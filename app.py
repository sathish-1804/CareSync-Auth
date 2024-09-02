from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mysql_connector import MySQL
import bcrypt
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure MySQL
app.config['MYSQL_HOST'] = os.environ.get('HOST_NAME')
app.config['MYSQL_USER'] = os.environ.get('DB_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('DB_PASSWORD')
app.config['MYSQL_DATABASE'] = os.environ.get('DB_NAME')
mysql = MySQL(app)

# Helper function to hash passwords
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Helper function to check passwords
def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# API endpoint to register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    hashed_password = hash_password(password)

    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("INSERT INTO Users (email, password_hash) VALUES (%s, %s)", (email, hashed_password))
    conn.commit()
    cursor.close()
    return jsonify({'message': 'User registered successfully'}), 201

# API endpoint to login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM Users WHERE email = %s", (email,))
    result = cursor.fetchone()
    cursor.close()

    if result and check_password(result[0], password):
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

if __name__ == '__main__':
    app.run(debug=True)
