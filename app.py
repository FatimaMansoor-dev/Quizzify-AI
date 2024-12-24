from flask import Flask, render_template, request, redirect
import requests
import json

app = Flask(__name__)

# Load the character mapping from JSON
with open("char_key_mapping.json", "r") as f:
    char_mapping = json.load(f)

# Firebase URL (Replace with your Firebase Realtime Database URL)
FIREBASE_URL = "https://quizifyai-7d979-default-rtdb.firebaseio.com/users.json"

# Helper Functions
def encrypt_password(password):
    """Encrypt the password using the character mapping."""
    encrypted = ""
    for letter in password:
        encrypted += char_mapping.get(letter, letter)  # Default to the letter if not in mapping
    return encrypted

def decrypt_password(encrypted_password):
    """Decrypt the password using the character mapping."""
    reverse_mapping = {v: k for k, v in char_mapping.items()}
    decrypted = ""
    for letter in encrypted_password:
        decrypted += reverse_mapping.get(letter, letter)  # Default to the letter if not in mapping
    return decrypted

@app.route('/')
def home():
    return render_template('index.html', message=None)

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    # Validation
    if not email or not password:
        message = "Please fill in both fields."
        return render_template('index.html', message=message)

    if len(password) < 9:
        message = "Password must be at least 9 characters long."
        return render_template('index.html', message=message)

    # Check against Firebase for login
    try:
        response = requests.get(FIREBASE_URL)
        if response.status_code == 200:
            users = response.json()
            for user_id, user_data in users.items():
                if user_data["email"] == email:
                    decrypted_password = decrypt_password(user_data["password"])
                    if password == decrypted_password:
                        message = "Login successful!"
                        return render_template('userProfile.html', message=message)
            message = "Invalid email or password."
        else:
            message = "Failed to connect to Firebase."
    except Exception as e:
        message = f"An error occurred: {e}"

    return render_template('index.html', message=message)

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')

    # Validation
    if not email or not password:
        message = "Please fill in both fields."
        return render_template('index.html', message=message)

    if len(password) < 9:
        message = "Password must be at least 9 characters long."
        return render_template('index.html', message=message)

    # Data to store in Firebase
    data = {
        "email": email,
        "password": encrypt_password(password)
    }

    # Save data to Firebase
    try:
        response = requests.post(FIREBASE_URL, json=data)
        if response.status_code == 200:
            message = "Account created successfully!"
        else:
            message = "Failed to create an account."
    except Exception as e:
        message = f"An error occurred: {e}"

    return render_template('index.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
