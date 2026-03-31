# CyberGuard Service: Flask Security Interface

## Project Overview
CyberGuard Service is a web-based security utility built with Flask that provides essential cryptographic services and secure file handling. The application allows users to perform text hashing, generate secure keys, and encrypt data using industry-standard algorithms.

## Features
* **Text Hashing:** Generates a secure SHA-256 hex digest for any input text.
* **Key Generation:** Provides a utility to generate 192-bit (24-byte) random keys using cryptographically secure methods.
* **Data Encryption:** Implements AES encryption in CBC mode with PKCS7 padding to secure text inputs.
* **Secure File Uploads:** A dedicated interface for uploading files, which are sanitized and stored in a specific server directory (`static/uploads`).

## Technical Stack
* **Backend:** Flask 3.1.3
* **Frontend:** HTML5 with Jinja2 Templating
* **Security/Cryptography:** `cryptography` library (v46.0.5)
* **Form Handling:** Flask-WTF and WTForms for CSRF protection and input validation

## Project Structure
```text
Infosecurity 2/
├── main.py              # Application logic and cryptographic functions
├── requirements.txt      # Python dependencies
├── static/
│   └── uploads/         # Destination for uploaded files
└── Templates/
    └── index.html       # Web interface template
```
## Installation & Setup

1.  **Clone or Download the Project:**
    Ensure all project files (main.py, Templates/index.html, requirements.txt) are in their respective directories.

2.  **Install Dependencies:**
    Open your terminal in the project root and install the required Python libraries:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application:**
    Start the Flask development server by running the main script:
    ```bash
    python main.py
    ```
    The application will start on `http://127.0.0.1:5500`.

## Usage Guide

### 1. Text & Password Services
* **Secure Hash (SHA-256):** Enter your text in the input box and click this button to generate a non-reversible 64-character hex string.
* **Generate New Key:** Click this to produce a random 192-bit hex key suitable for AES-192 encryption.
* **Encrypt Text:** Enter the text you wish to hide. The system will use AES in CBC mode to return an encrypted hex string, a unique IV, and the encryption key.
* **Decrypt Text:** (Requires implementation) This function is designed to take encrypted data and return the original plaintext using the provided key and IV.

### 2. File Services
* **Securely Submit File:** Click "Choose File" to select a document or image from your computer, then click the submit button.
* **Storage:** Files are automatically sanitized and stored in the `static/uploads` directory.
