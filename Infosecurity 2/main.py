from flask import Flask, render_template, request
from flask_wtf import FlaskForm 
from wtforms import FileField, SubmitField , StringField
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding   
import hashlib
import os
import secrets
import string
from wtforms.validators import InputRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()    
def key_gen(size_bits):
    return os.urandom(size_bits// 8)
def password_gen(length=63):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def encrypt_data(plainttext,algorithm_name , mode_name,key):
    iv_size = 16 if algorithm_name == "AES" else 8
    iv = os.urandom(iv_size)

    if algorithm_name == "AES":
        cipher_algorithm = algorithms.AES(key)
    elif algorithm_name == "3DES":
        cipher_algorithm = algorithms.TripleDES(key)
    if mode_name == "CBC":
        cipher_mode = modes.CBC(iv)
        padder = padding.PKCS7(cipher_algorithm.block_size).padder()
        plainttext = padder.update(plainttext) + padder.finalize()
    else:
        cipher_mode = modes.CTR(iv)
    cipher = Cipher(cipher_algorithm, cipher_mode)
    encrypter = cipher.encryptor()
    ciphertext = encrypter.update(plainttext) + encrypter.finalize()

    return iv, ciphertext

def decrypt_data(ciphertext,algorithm_name , mode_name,key,iv):
    if algorithm_name == "AES":
        cipher_algorithm = algorithms.AES(key)
    else:
        cipher_algorithm = algorithms.TripleDES(key)
    
    cipher_mode = modes.CBC(iv) if mode_name == "CBC" else modes.CTR(iv)
    cipher = Cipher(cipher_algorithm, cipher_mode)
    decrypter = cipher.decryptor()
    decrypt_data = decrypter.update(ciphertext) + decrypter.finalize()
    if mode_name == "CBC":
        unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()
        decrypt_data = unpadder.update(decrypt_data) + unpadder.finalize()
    return decrypt_data
'''class UploadForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")'''

class SecurityForm(FlaskForm):
    text_input = StringField("Enter Text or Password")
    file = FileField("File")
    submit = SubmitField("Submit")


@app.route('/', methods=['GET', "POST"])
@app.route('/home',methods=['GET', "POST"])
def home():
    form = SecurityForm()
    result = None
    if form.validate_on_submit():
        
        action = request.form.get('action')
        user_text = form.text_input.data

        if action == "hash":
            if user_text:
                result = hash_text(user_text)
            else:
                result = "Please enter text to hash."
        elif action == "key_gen":
            keys = key_gen(192)
            result = "New Key Been Generated: " + keys.hex()
        elif action == "upload":
            file = form.file.data
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                # Ensure the upload folder exists
                upload_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), app.config['UPLOAD_FOLDER'])
                os.makedirs(upload_path, exist_ok=True)
                
                file.save(os.path.join(upload_path, filename))
                result = f"File '{filename}' stored successfully."
            else:
                result = "No file selected for upload."
        elif action == "encrypt_text":
            if user_text:
                key = key_gen(192) # AES-192 requirement
                iv, ciphertext = encrypt_data(user_text.encode(), "AES", "CBC", key)
                result = f"Encrypted (Hex): {ciphertext.hex()} | IV: {iv.hex()} | Key: {key.hex()}"
            else:
                result = "Enter text to encrypt."
        
    return render_template('index.html',form=form, result = result)


if __name__ == '__main__':
    app.run(debug=True,port=5500)