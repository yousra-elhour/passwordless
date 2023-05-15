import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, render_template, request, url_for, flash, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, login_user
import boto3

# Set up encryption key
key = b'H@r*ljJi4tL02A630y0qqDchKy'

# Set up database and S3
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'snH0Jt$v&b50oDHdzA1Y9pf6K6'
s3 = boto3.client('s3')

# Set up Flask-Security
from .models import db, User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Create a route for password-less authentication
@app.route('/login')
def login():
    email = request.args.get('email')
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            send_access_link(user)
            flash('An access link has been sent to your email.')
        else:
            flash('Invalid email.')
    return render_template('login.html')

# Function to send access link to user's email
def send_access_link(user):
    # Generate unique access link and send it to the user's email
    access_link = generate_access_link(user)
    send_email(user.email, 'Access Link', access_link)

# Function to generate unique access link
def generate_access_link(user):
    # Generate unique token based on user's email
    token = generate_token(user.email)
    # Create access link with token
    access_link = url_for('access_link', token=token, _external=True)
    return access_link

# Function to generate token
def generate_token(email):
    # Generate unique token based on user's email
    token = hashlib.sha256((email + app.config['SECRET_KEY']).encode()).hexdigest()
    return token

# Function to encrypt data using AES
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    return ciphertext, iv

# Function to decrypt data using AES
def decrypt_data(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# Route for access link
@app.route('/access_link/<token>')
def access_link(token):
    email = decrypt_token(token)
    user = User.query.filter_by(email=email).first()
    if user:
        login_user(user)
        flash('Access granted.')
        return redirect(url_for('index'))
    else:
        flash('Invalid access link.')
        return redirect(url_for('login'))

# Function to decrypt token
def decrypt_token(token):
    # Decrypt token based on the encryption key
    iv = bytes.fromhex(token[:32])
    ciphertext = bytes.fromhex(token[32:])
    plaintext = decrypt_data(ciphertext, iv, key)
    return plaintext.decode()

# Route for adding a record
@app.route('/add_record', methods=['POST'])
def add_record():
    # Get data from request
    data = request.form['data'].encode()
    # Encrypt data using AES
    ciphertext, iv = encrypt_data(data, key)
    # Save encrypted data to S3
    bucket_name = 'my-bucket'
    object_name = 'records/record_{}.bin'.format(datetime.now().strftime('%Y%m%d_%H%M%S'))
    s3.put_object(Body=ciphertext, Bucket=bucket_name, Key=object_name)
    flash('Record added successfully.')
    return redirect(url_for('index'))

# Route for retrieving record
@app.route('/retrieve_record/<filename>')
def retrieve_record(filename):
    # Get encrypted data from S3
    bucket_name = 'my-bucket'
    object_name = 'records/{}'.format(filename)
    response = s3.get_object(Bucket=bucket_name, Key=object_name)
    ciphertext = response['Body'].read()
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    # Decrypt data
    plaintext = decrypt_data(ciphertext, iv, key)
    return plaintext.decode()