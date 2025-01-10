from flask import Flask, render_template, request, jsonify
import requests
import json
import os
from groq import Groq

app = Flask(__name__)

# Load the character mapping from JSON
with open("char_key_mapping.json", "r") as f:
    char_mapping = json.load(f)

FIREBASE_URL = "https://quizifyai-7d979-default-rtdb.firebaseio.com/users.json"
client = Groq(api_key="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")


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

from datetime import datetime

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

                        # Process quiz attempts to remove time information from dates
                        quiz_attempts = user_data.get("quiz_attempts", [])
                        # print(quiz_attempts)
                        if quiz_attempts:
                            for attempt_data in quiz_attempts:
                                if attempt_data and isinstance(attempt_data, dict) and "date" in attempt_data:
                                    # Remove time portion (hours, minutes, seconds)
                                    attempt_data["date"] = attempt_data["date"].split(" ")[0]

                        # Extract only the dates
                        quiz_dates = [attempt.get("date") for attempt in quiz_attempts if isinstance(attempt, dict) and "date" in attempt]

                        # Check if there are any quiz attempts
                        if not quiz_dates:
                            message = "You are one quiz away from getting the 'First Step' badge."
                            quizes = 0
                        else:
                            message = "First-Step Badge"
                            quizes = len(quiz_dates)
                        print(quiz_dates)

                        return render_template('userProfile.html', 
                                            message=message, 
                                            first_name=first_name, 
                                            last_name=last_name,
                                            quizes=quizes,
                                            email=email, 
                                            quiz_attempts=quiz_dates)  # Only pass the dates
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
    
    # Check if email already exists
    try:
        response = requests.get(FIREBASE_URL)
        if response.status_code == 200:
            users = response.json()
            for user_data in users.values():
                if user_data["email"] == email:
                    return render_template('index.html', message="Email already exists. Please use a different email.")
        else:
            return render_template('index.html', message="Failed to check existing users.")
    except Exception as e:
        return render_template('index.html', message=f"An error occurred while checking existing users: {e}")

    # If email doesn't exist, proceed with signup
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
                                   message="Just a quiz away from earning First-Step Badge", 
                                   first_name=first_name, 
                                   last_name=last_name,
                                   email=email,
                                   quizes=0,
                                   quiz_attempts=0)
        return render_template('index.html', message="Failed to create an account.")
    except Exception as e:
        return render_template('index.html', message=f"An error occurred: {e}")

@app.route('/options')
def options():
    email = request.args.get('email')  # Retrieve email from query parameter
    return render_template('options.html', email=email)

@app.route('/upload')
def upload():
    return render_template('main.html')

@app.route('/topic')
def topic():
    email = request.args.get('email')
    return render_template('topic.html', email=email)

@app.route('/generateOnTopic', methods=['POST'])
def generate_on_topic():
    data = request.get_json()
    email = data.get('email')
    topic = data.get('topic')
    type = data.get('type')
    difficulty = data.get('difficulty')

    prompt = f"""
        Generate {difficulty} {type} based quiz on {topic} in this format:
        **Question 1:**
What is 2 + 2?
A) 3
B) 4
C) 5
D) 6
**Answer:** B)

    """

    try:
        completion = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": "You are responsible to generate quiz"},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=1024,
            top_p=1,
            stream=True,
            stop=None,
        )

        extended_answer = ""
        for response_chunk in completion:
            extended_answer += response_chunk.choices[0].delta.content or ""
        print(extended_answer)

        # Return the response as JSON
        return jsonify({"message": extended_answer, "email": email})

    except Exception as e:
        print(f"Error generating quiz: {e}")
        return jsonify({"error": "An error occurred while generating the quiz."}), 500

@app.route('/quiz')
def quiz():
    # Retrieve the message from the query parameters
    message = request.args.get('message', 'No quiz generated')
    email = request.args.get('email','no email')
    print("eee", email)
    
    # Pass the message to the template
    return render_template('quiz.html', message=message)


@app.route('/insertResults', methods=['POST'])
def insert_results():
    # Get the JSON data from the request
    data = request.json
    email = data.get('email')
    score = data.get('score')
    total_questions = data.get('totalQuestions')
    answers = data.get('answers')  # list of answers: [{'question': '', 'selectedAnswer': None, 'correctAnswer': 'C'}, ...]

    # Log the received data
    print("Email:", email)
    print("Score:", score)
    print("Total Questions:", total_questions)
    print("Answers:", answers)

    # Ensure email is provided
    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        # Fetch user data from Firebase
        response = requests.get(FIREBASE_URL)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch user data from Firebase"}), 500

        users = response.json()
        user_id = None
        user_data = None

        # Find the user by email
        for uid, user in users.items():
            if user["email"] == email:
                user_id = uid
                user_data = user
                break

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        # Add quiz score and date
        from datetime import datetime
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Initialize quiz_attempts as a dictionary if it doesn't exist yet
        quiz_attempts = user_data.get("quiz_attempts", [])

        # Create a new quiz attempt as a dictionary
        new_quiz_attempt = {
            "score": score,
            "date": current_date,
            "total_questions": total_questions,
            "answers": answers  # Store answers as a list
        }

        # Append the new quiz attempt to the list
        quiz_attempts.append(new_quiz_attempt)

        # Update the user data in Firebase
        update_url = f"{FIREBASE_URL.replace('.json', '')}/{user_id}.json"
        update_data = {"quiz_attempts": quiz_attempts}
        update_response = requests.patch(update_url, json=update_data)

        if update_response.status_code == 200:
            # Process quiz attempts to remove time information from dates
            quiz_dates = [attempt.get("date").split(" ")[0] for attempt in quiz_attempts if "date" in attempt]

            # Extract first name, last name, and other user info
            first_name = user_data.get("first_name", "User")
            last_name = user_data.get("last_name", "")

            # Check if there are any quiz attempts
            if not quiz_dates:
                message = "You are one quiz away from getting the 'First Step' badge."
                quizes = 0
            else:
                message = "First-Step Badge"
                quizes = len(quiz_dates)

            return render_template(
                'userProfile.html',
                message=message,
                first_name=first_name,
                last_name=last_name,
                quizes=quizes,
                email=email,
                quiz_attempts=quiz_dates  # Pass the list of quiz attempt dates to the template
            )
        else:
            return jsonify({"error": "Failed to update user data in Firebase"}), 500
    except Exception as e:
        print(f"Error storing quiz results: {e}")
        return jsonify({"error": "An error occurred while storing quiz results"}), 500

@app.route('/userProfile', methods=['GET'])
def user_profile():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required to access the user profile."}), 400

    try:
        # Fetch user data from Firebase
        response = requests.get(FIREBASE_URL)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch user data from Firebase"}), 500

        users = response.json()
        user_data = None

        # Find the user by email
        for user in users.values():
            if user["email"] == email:
                user_data = user
                break

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        # Extract user information
        first_name = user_data.get("first_name", "User")
        last_name = user_data.get("last_name", "")
        quiz_attempts = user_data.get("quiz_attempts", [])

        # Process quiz attempts to remove time information from dates
        quiz_dates = [attempt.get("date").split(" ")[0] for attempt in quiz_attempts if "date" in attempt]

        message = "You are one quiz away from getting the 'First Step' badge." if not quiz_dates else "First-Step Badge"
        quizes = len(quiz_dates)
        print(quiz_dates)

        return render_template(
            'userProfile.html',
            message=message,
            first_name=first_name,
            last_name=last_name,
            quizes=quizes,
            email=email,
            quiz_attempts=quiz_dates
        )
    except Exception as e:
        print(f"Error loading user profile: {e}")
        return jsonify({"error": "An error occurred while loading the user profile"}), 500




if __name__ == '__main__':
    app.run(debug=True)
