from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from datetime import datetime 
import os
import dotenv

dotenv.load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqlconnector://{os.environ.get('DB_USER')}:{os.environ.get('DB_PASSWORD')}@{os.environ.get('HOST_NAME')}/{os.environ.get('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    __tablename__ = 'Users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    user_details = db.Column(db.Boolean, default=False)

# Define the UserProfile model
class UserProfile(db.Model):
    __tablename__ = 'UserProfile'
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), primary_key=True)
    full_name = db.Column(db.String(255))
    DOB = db.Column(db.Date)
    age = db.Column(db.Integer)
    gender = db.Column(db.Enum('Male', 'Female'))
    phone_number = db.Column(db.String(20))
    district = db.Column(db.String(100))
    state = db.Column(db.String(100))
    occupation = db.Column(db.String(100))
    annual_income = db.Column(db.Numeric(10, 2))
    height = db.Column(db.Numeric(5, 2))
    weight = db.Column(db.Numeric(5, 2))

# Define the HealthInformation model
class HealthInformation(db.Model):
    __tablename__ = 'HealthInformation'
    health_info_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'))
    medical_history = db.Column(db.Text)
    family_medical_history = db.Column(db.Text)
    allergies = db.Column(db.Text)
    current_medications = db.Column(db.Text)

# Define the LifestyleInformation model
class LifestyleInformation(db.Model):
    __tablename__ = 'LifestyleInformation'
    lifestyle_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'))
    smoking_status = db.Column(db.Enum('Never', 'Former', 'Current'))
    alcohol_consumption = db.Column(db.Enum('None', 'Light', 'Moderate', 'Heavy'))
    physical_activity = db.Column(db.Enum('None', 'Light', 'Moderate', 'High'))
    family_history_CVD = db.Column(db.Boolean)
    family_history_diabetes = db.Column(db.Boolean)
    family_history_cancer = db.Column(db.Boolean)
    stress_level = db.Column(db.Enum('Low', 'Medium', 'High'))
    sleep_hours = db.Column(db.Integer)

# Helper function to hash passwords
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Helper function to check passwords
def check_password(hashed_password, password):
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
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

    # Insert user into the database
    new_user = User(email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'UserID': new_user.user_id, 'message': 'User registered successfully'}), 201

# API endpoint to login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if user and check_password(user.password_hash, password):
        return jsonify({'UserID': user.user_id, 'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

# API endpoint to add user profile
@app.route('/user-profile', methods=['POST'])
def add_user_profile():
    data = request.get_json()
    dob = data.get('dob')
    dob_converted = datetime.strptime(dob, "%Y-%m-%d").date()
    user_profile = UserProfile(
        user_id=data['user_id'],
        full_name=data['full_name'],
        DOB=dob_converted,
        age=data['age'],
        gender=data['gender'],
        phone_number=data['phone_number'],
        district=data['district'],
        state=data['state'],
        occupation=data['occupation'],
        annual_income=data['annual_income'],
        height=data['height'],
        weight=data['weight']
    )
    db.session.add(user_profile)
    db.session.commit()
    return jsonify({'message': 'User profile added successfully'}), 201

# API endpoint to add health information
@app.route('/health-information', methods=['POST'])
def add_health_information():
    data = request.get_json()
    health_info = HealthInformation(
        user_id=data['user_id'],
        medical_history=data['medical_history'],
        allergies=data['allergies'],
        family_medical_history = data['family_medical_history'],
        current_medications=data['current_medications']
    )
    db.session.add(health_info)
    db.session.commit()
    return jsonify({'message': 'Health information added successfully'}), 201

# API endpoint to add lifestyle information
@app.route('/lifestyle-information', methods=['POST'])
def add_lifestyle_information():
    data = request.get_json()
    lifestyle_info = LifestyleInformation(
        user_id=data['user_id'],
        smoking_status=data['smoking_status'],
        alcohol_consumption=data['alcohol_consumption'],
        physical_activity=data['physical_activity'],
        family_history_CVD=data['family_history_CVD'],
        family_history_diabetes=data['family_history_diabetes'],
        family_history_cancer=data['family_history_cancer'],
        stress_level=data['stress_level'],
        sleep_hours=data['sleep_hours']
    )
    db.session.add(lifestyle_info)
    db.session.commit()
    return jsonify({'message': 'Lifestyle information added successfully'}), 201


# API endpoint to get user details status
@app.route('/user-details-status/<int:user_id>', methods=['GET'])
def get_user_details_status(user_id):
    user = User.query.filter_by(user_id=user_id).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({'UserID': user.user_id, 'UserDetails': user.user_details}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
