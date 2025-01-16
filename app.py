from flask import Flask, render_template, request, jsonify
import requests
import json
from datetime import datetime, timedelta
from groq import Groq

app = Flask(__name__)

# Load the character mapping from JSON
with open("char_key_mapping.json", "r") as f:
    char_mapping = json.load(f)

FIREBASE_URL = "https://quizifyai-7d979-default-rtdb.firebaseio.com/users.json"
client = Groq(api_key="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")


# Helper functions
def encrypt_password(password):
    return "".join(char_mapping.get(letter, letter) for letter in password)


def decrypt_password(encrypted_password):
    reverse_mapping = {v: k for k, v in char_mapping.items()}
    return "".join(reverse_mapping.get(letter, letter) for letter in encrypted_password)


def get_user_data(email):
    """Fetch user data from Firebase by email."""
    response = requests.get(FIREBASE_URL)
    if response.status_code != 200:
        raise Exception("Failed to fetch user data from Firebase")
    
    users = response.json()
    for user_id, user_data in users.items():
        if user_data["email"] == email:
            return user_data
    return None


def prepare_user_profile(user_data):
    """Prepare data for rendering the user profile."""
    first_name = user_data.get("first_name", "User")
    last_name = user_data.get("last_name", "")
    quiz_attempts = user_data.get("quiz_attempts", [])

    quiz_dates = [attempt.get("date").split(" ")[0] for attempt in quiz_attempts if "date" in attempt]
    last_score = quiz_attempts[-1].get("score") if quiz_attempts else None
    max_score = max((attempt.get("score", 0) for attempt in quiz_attempts), default=None)
    
    message = "You are one quiz away from getting the 'First Step' badge." if not quiz_dates else "First-Step Badge"
    quizes = len(quiz_dates)

    return {
        "message": message,
        "first_name": first_name,
        "last_name": last_name,
        "quizes": quizes,
        "quiz_attempts": quiz_dates,
        "last_score": last_score,
        "max_score": max_score
    }


# Routes
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
        user_data = get_user_data(email)
        if user_data:
            decrypted_password = decrypt_password(user_data["password"])
            if password == decrypted_password:
                profile_data = prepare_user_profile(user_data)
                return render_template('userProfile.html', email=email, **profile_data)
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

    try:
        if get_user_data(email):
            return render_template('index.html', message="Email already exists. Please use a different email.")
        
        # Create user
        name = email.split("@")[0]
        first_name, last_name = (name.split(".")[0], name.split(".")[1]) if "." in name else (name, "")
        data = {
            "email": email,
            "password": encrypt_password(password),
            "first_name": first_name,
            "last_name": last_name
        }

        response = requests.post(FIREBASE_URL, json=data)
        if response.status_code == 200:
            profile_data = {
                "message": "Just a quiz away from earning First-Step Badge",
                "first_name": first_name,
                "last_name": last_name,
                "quizes": 0,
                "quiz_attempts": []
            }
            return render_template('userProfile.html', email=email, **profile_data)
        return render_template('index.html', message="Failed to create an account.")
    except Exception as e:
        return render_template('index.html', message=f"An error occurred: {e}")


@app.route('/userProfile', methods=['GET'])
def user_profile():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required to access the user profile."}), 400

    try:
        user_data = get_user_data(email)
        if not user_data:
            return jsonify({"error": "User not found"}), 404

        profile_data = prepare_user_profile(user_data)
        return render_template('userProfile.html', email=email, **profile_data)
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500


@app.route('/options')
def options():
    email = request.args.get('email')
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

    if type == 'MCQs':
        prompt = f"""
        Generate 10 MCQs quiz with {difficulty} difficulty level quiz on {topic} in this format:
        **Question 1:** [question]?
        A) [option 1]
        B) [option 2]
        C) [option 3]
        D) [option 4]
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
            return jsonify({"message": extended_answer, "email": email})
        except Exception as e:
            return jsonify({"error": f"An error occurred while generating the quiz: {e}"}), 500


@app.route('/quiz')
def quiz():
    message = request.args.get('message', 'No message provided')
    email = request.args.get('email', 'No email provided')
    return render_template('quiz.html', message=message, email=email)


@app.route('/insertResults', methods=['POST', 'GET'])
def insert_results():
    if request.method == 'POST':
        # Handle POST request
        data = request.json
        email = data.get('email')
        score = data.get('score')

        print("Email:", email)
        print("Score:", score)

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
            from datetime import datetime, timedelta
            current_date = datetime.now() + timedelta(hours=2)
            formatted_date = current_date.strftime("%Y-%m-%d %H:%M:%S")

            # Add new quiz attempt
            quiz_attempts = user_data.get("quiz_attempts", [])
            quiz_attempts.append({"score": score, "date": formatted_date})

            ## Update the user data in Firebase
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
                return jsonify({"error": "done done"}), 200  ## ab yahan se score pass krdo wapis udhr jaiyag wahan se user profile call krdo
                # return render_template(
                #     'userProfile.html',
                #     message=message,
                #     first_name=first_name,
                #     last_name=last_name,
                #     quizes=quizes,
                #     email=email,
                #     quiz_attempts=quiz_dates  # Pass the list of quiz attempt dates to the template
                # )
            else:
                return jsonify({"error": "Failed to update user data in Firebase"}), 500
        except Exception as e:
            print(f"Error storing quiz results: {e}")
            return jsonify({"error": "An error occurred while storing quiz results"}), 500



if __name__ == '__main__':
    app.run(debug=True)
