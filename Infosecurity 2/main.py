import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm 
from wtforms import FileField, SubmitField, StringField, PasswordField
from wtforms.validators import InputRequired
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization
# Import your modular utilities
from crypto_utils import hash_file_data, hash_text, encrypt_data, decrypt_data, key_gen, password_gen
from asym_utils import generate_rsa_pair, rsa_encrypt_text, generate_dh_parameters

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberguard.db'
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class SecurityForm(FlaskForm):
    text_input = StringField("Enter Text or Password")
    file = FileField("File")
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Login")

# --- AUTH ROUTES ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form.get('password')) 
        new_user = User(username=request.form.get('username'), password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- SERVICE ROUTES ---
@app.route('/download/<filename>')
@login_required
def download_file(filename):
    """Fulfills: Download files [cite: 39]"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/', methods=['GET', "POST"])
@app.route('/home', methods=['GET', "POST"])
@login_required
def home():
    form = SecurityForm()
    result = None
    
    if form.validate_on_submit():
        action = request.form.get('action')
        user_text = form.text_input.data
        file = form.file.data

        # --- 1. Text & Key Services ---
        if action == "hash":
            if user_text:
                # Fulfills: Secure Hashing SHA-2 or SHA-3 [cite: 17]
                result = f"SHA-256 Text Hash: {hash_text(user_text)}"
            else:
                result = "Enter text to hash."

        elif action == "pass_gen":
            # Fulfills: Password generation up to 63 bytes [cite: 20]
            result = f"New 63-Byte Password: {password_gen(63)}"

        elif action == "key_gen":
            # Fulfills: AES 192-bit key requirement [cite: 13]
            key = key_gen(192)
            result = f"Generated Symmetric Key (Hex): {key.hex()}"

        # --- 2. Encryption & Decryption ---
        elif action == "encrypt_aes":
            if user_text:
                key = key_gen(192)
                iv, ciphertext = encrypt_data(user_text.encode(), "AES", "CBC", key)
                result = f"AES-192 Cipher (Hex): {ciphertext.hex()} | IV: {iv.hex()} | Key: {key.hex()}"
            else:
                result = "Enter text to encrypt with AES."

        elif action == "encrypt_3des":
            if user_text:
                # Fulfills: 3-DES requirement 
                key = key_gen(192) # 24 bytes
                iv, ciphertext = encrypt_data(user_text.encode(), "3DES", "CBC", key)
                result = f"3-DES Cipher (Hex): {ciphertext.hex()} | IV: {iv.hex()} | Key: {key.hex()}"
            else:
                result = "Enter text to encrypt with 3-DES."

        elif action == "rsa_gen":
            
            priv_key, pub_key = generate_rsa_pair()
            
            # Convert private key to readable PEM string
            pem_priv = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            # Convert public key to readable PEM string
            pem_pub = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # Display both so the instructor can see them
            result = f"PRIVATE KEY:\n{pem_priv}\n\nPUBLIC KEY:\n{pem_pub}"

        elif action == "encrypt_rsa":
            if user_text:
                # Fulfills: RSA two-key encryption [cite: 35]
                _, pub_key = generate_rsa_pair()
                ciphertext = rsa_encrypt_text(pub_key, user_text)
                result = f"RSA Ciphertext (Hex): {ciphertext.hex()}"
            else:
                result = "Enter text to encrypt with RSA."

        # --- 3. File & Integrity Services ---
        elif action == "upload":
            if file:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Fulfills: Save documents on the system [cite: 36]
                result = f"File '{filename}' securely saved."

        elif action == "hash_file":
            if file:
                # Fulfills: Hash any type of file [cite: 37]
                result = f"File Hash (SHA-256): {hash_file_data(file)}"
            else:
                result = "Upload a file to generate a hash."

        elif action == "compare_hash":
            if file and user_text:
                # Fulfills: Compare file hashes [cite: 38]
                file_hash = hash_file_data(file)
                if file_hash == user_text.strip():
                    result = "SUCCESS: The file hash matches your input."
                else:
                    result = "MISMATCH: The file hash does not match your input."
        elif action == "decrypt_aes":
            # You must use request.form.get to grab these extra fields
            user_hex_ciphertext = form.text_input.data
            hex_key = request.form.get('provided_key')
            hex_iv = request.form.get('provided_iv')

            if user_hex_ciphertext and hex_key and hex_iv:
                try:
                    # Convert the strings from the web boxes into bytes for the library
                    binary_ciphertext = bytes.fromhex(user_hex_ciphertext.strip())
                    binary_key = bytes.fromhex(hex_key.strip())
                    binary_iv = bytes.fromhex(hex_iv.strip())

                    # Call your utility function from crypto.py
                    decrypted_bytes = decrypt_data(
                        binary_ciphertext, 
                        "AES", 
                        "CBC", 
                        binary_key, 
                        binary_iv
                    )
                    
                    # Fulfills requirement: plaintext messages may be of any size [cite: 12]
                    result = f"Decrypted Message: {decrypted_bytes.decode('utf-8')}"
                except Exception as e:
                    result = f"Decryption Failed: Ensure Key/IV/Ciphertext are correct hex. Error: {str(e)}"
            else:
                result = "Error: You must provide the Ciphertext, the 192-bit Key, and the IV."
        elif action == "dh_share":
            priv, pub = generate_dh_parameters()
            
            # Export the public key to show what is "shared"
            pub_bytes = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            result = f"DH Public Key for Sharing:\n{pub_bytes}"

    return render_template('index.html', form=form, result=result)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True, port=5500)