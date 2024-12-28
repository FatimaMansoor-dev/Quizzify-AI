from flask import Flask, render_template, request
import requests
import json

app = Flask(__name__)

# Load the character mapping from JSON
with open("char_key_mapping.json", "r") as f:
    char_mapping = json.load(f)

FIREBASE_URL = "https://quizifyai-7d979-default-rtdb.firebaseio.com/users.json"

def encrypt_password(password):
    encrypted = ""
    for letter in password:
        encrypted += char_mapping.get(letter, letter)
    return encrypted

def decrypt_password(encrypted_password):
    reverse_mapping = {v: k for k, v in char_mapping.items()}
    decrypted = ""
    for letter in encrypted_password:
        decrypted += reverse_mapping.get(letter, letter)
    return decrypted

@app.route('/')
def home():
    return render_template('index.html', message=None)

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return render_template('index.html', message="Please fill in both fields.")

    if len(password) < 9:
        return render_template('index.html', message="Password must be at least 9 characters long.")

    try:
        response = requests.get(FIREBASE_URL)
        if response.status_code == 200:
            users = response.json()
            for user_id, user_data in users.items():
                if user_data["email"] == email:
                    decrypted_password = decrypt_password(user_data["password"])
                    if password == decrypted_password:
                        first_name = user_data.get("first_name", "User")
                        last_name = user_data.get("last_name", "")
                        return render_template('userProfile.html', 
                                               message="Login successful!", 
                                               first_name=first_name, 
                                               last_name=last_name)
        return render_template('index.html', message="Invalid email or password.")
    except Exception as e:
        return render_template('index.html', message=f"An error occurred: {e}")

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return render_template('index.html', message="Please fill in both fields.")

    if len(password) < 9:
        return render_template('index.html', message="Password must be at least 9 characters long.")
    
    name = email.split("@")[0]
    first_name, last_name = (name.split(".")[0], name.split(".")[1]) if "." in name else (name, "")

    data = {
        "email": email,
        "password": encrypt_password(password),
        "first_name": first_name,
        "last_name": last_name
    }

    try:
        response = requests.post(FIREBASE_URL, json=data)
        if response.status_code == 200:
            return render_template('userProfile.html', 
                                   message="Account created successfully!", 
                                   first_name=first_name, 
                                   last_name=last_name)
        return render_template('index.html', message="Failed to create an account.")
    except Exception as e:
        return render_template('index.html', message=f"An error occurred: {e}")

if __name__ == '__main__':
    app.run(debug=True)
