from flask import Flask, render_template, request, jsonify, session
import requests
from flask import jsonify, send_from_directory
import json
from datetime import datetime, timedelta
import random
from flask_mail import Mail, Message
from groq import Groq
import re
from youtube_transcript_api import YouTubeTranscriptApi
import speech_recognition as sr
from pydub import AudioSegment
import io

app = Flask(__name__)
app.secret_key = 'your-unique-secret-key'

# ---------------------
# CORS, Mail, Groq Setup
# ---------------------
from flask_cors import CORS
CORS(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'benzenering032@gmail.com'
app.config['MAIL_PASSWORD'] = 'kpfa yprh zdev kafn'
app.config['MAIL_DEFAULT_SENDER'] = 'benzenering032@gmail.com'
mail = Mail(app)

client = Groq(api_key="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")

# ---------------------
# Firebase / JSON config
# ---------------------
FIREBASE_URL = "https://quizifyai-7d979-default-rtdb.firebaseio.com/users.json"

# Load character mapping from JSON
with open("char_key_mapping.json", "r") as f:
    char_mapping = json.load(f)

# ---------------------
# Helper Functions
# ---------------------
def encrypt_password(password):
    return "".join(char_mapping.get(letter, letter) for letter in password)

def decrypt_password(encrypted_password):
    reverse_mapping = {v: k for k, v in char_mapping.items()}
    return "".join(reverse_mapping.get(letter, letter) for letter in encrypted_password)

def get_user_data(email):
    """Fetch user data from Firebase by email."""
    try:
        response = requests.get(FIREBASE_URL)
        print(response.json())  # Debugging: prints all users

        if response.status_code != 200:
            raise Exception("Failed to fetch user data from Firebase")

        users = response.json()
        if not users:
            return None  # No users found

        if isinstance(users, dict):
            for user_id, user_info in users.items():
                if user_info.get("email") == email:
                    return user_info
        return None
    except Exception as e:
        print(f"Error fetching user data: {e}")
        return None

def prepare_user_profile(user_data):
    first_name = user_data.get("first_name", "User")
    last_name = user_data.get("last_name", "")
    quiz_attempts = user_data.get("quiz_attempts", [])
    # For calendar display, we only need the date strings.
    quiz_dates = [attempt.get("date").split(" ")[0] for attempt in quiz_attempts if "date" in attempt]
    last_score = quiz_attempts[-1].get("score") if quiz_attempts else None
    max_score = max((attempt.get("score", 0) for attempt in quiz_attempts), default=None)
    difficulty_counts = {"easy": 0, "medium": 0, "hard": 0}
    for attempt in quiz_attempts:
        difficulty = attempt.get("difficulty", "").lower()
        if difficulty in difficulty_counts:
            difficulty_counts[difficulty] += 1
    quiz_count = len(quiz_attempts)
    message = get_badge_message(quiz_count)

    return {
        "message": message,
        "first_name": first_name,
        "last_name": last_name,
        "quizes": quiz_count,
        "quiz_attempts": quiz_attempts,  # full data for quiz cards
        "quiz_dates": quiz_dates,          # date-only list for calendar & streak tracker
        "last_score": last_score,
        "max_score": max_score,
        "difficulty_counts": difficulty_counts  
    }


def get_badge_message(quiz_count):
    badges = {
        1: "First Step",
        5: "Quiz Master",
        50: "Quiz Enthusiast",
        100: "Quiz Prodigy",
        500: "Quiz Mastermind"
    }
    earned_badges = []
    # Add badges earned so far
    for threshold in sorted(badges.keys()):
        if quiz_count >= threshold:
            earned_badges.append(f"{badges[threshold]} Badge")
    # Check if user is 1 quiz away from next badge
    for threshold in sorted(badges.keys()):
        if quiz_count + 1 == threshold:
            earned_badges.append(f"You are one quiz away from getting the '{badges[threshold]}' badge.")
            break
    return earned_badges if earned_badges else ["Keep going! Your first badge is just one quiz away!"]

def store_quiz_in_firebase(email, quiz_content, difficulty, qtype, score=None):
    """
    Stores the entire quiz attempt in Firebase for the given email.
    This attempt includes:
      - date: current date/time,
      - difficulty: provided difficulty,
      - score: provided score (None if not available yet),
      - type: quiz type (e.g., MCQs, blanks, etc.),
      - quiz_content: the full generated quiz.
    """
    # 1) Fetch all users from Firebase
    resp = requests.get(FIREBASE_URL)
    if resp.status_code != 200:
        raise Exception("Failed to fetch user data from Firebase")
    users = resp.json() or {}
    
    # 2) Find the user by email
    user_id = None
    user_info = None
    for uid, info in users.items():
        if info.get("email") == email:
            user_id = uid
            user_info = info
            break
    if not user_info:
        raise Exception("User not found in Firebase")
    
    # 3) Prepare the new quiz attempt with all required fields
    quiz_attempts = user_info.get("quiz_attempts", [])
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_attempt = {
        "date": current_date,
        "difficulty": difficulty,
        "score": score,       # Will be None for a newly generated quiz
        "type": qtype,
        "quiz_content": quiz_content
    }
    quiz_attempts.append(new_attempt)
    
    # 4) Update the user's quiz_attempts in Firebase
    update_url = FIREBASE_URL.replace('.json', '') + f'/{user_id}.json'
    update_data = {"quiz_attempts": quiz_attempts}
    patch_resp = requests.patch(update_url, json=update_data)
    if patch_resp.status_code != 200:
        raise Exception("Failed to update user data in Firebase")


# ---------------------
# Routes
# ---------------------
@app.route('/')
def home():
    return render_template('home.html', message=None)

@app.route('/sign')
def sign():
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
                # Prepare profile info
                profile_data = prepare_user_profile(user_data)
                # Pass entire user_data as JSON
                print(profile_data)
                return render_template(
                    'userProfile.html',
                    email=email,
                    user_data=json.dumps(user_data),  # Entire user record
                    **profile_data
                )
        return render_template('index.html', message="Invalid email or password.")
    except Exception as e:
        return render_template('index.html', message=f"An error occurred: {e}")

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    password = request.form.get('password')
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')

    if not email or not password or not first_name or not last_name:
        return render_template('index.html', message="Please fill in all fields.")
    if len(password) < 9:
        return render_template('index.html', message="Password must be at least 9 characters long.")

    try:
        # Check if email exists
        if get_user_data(email):
            return render_template('index.html', message="Email already exists. Please use a different email.")

        # Generate OTP
        otp = random.randint(100000, 999999)
        session['otp'] = otp
        session['email'] = email
        session['password'] = encrypt_password(password)
        session['first_name'] = first_name
        session['last_name'] = last_name

        # Send OTP email
        message = Message("Verify Your Email - QuizifyAI", recipients=[email])
        message.body = f"Your OTP for email verification is: {otp}"
        mail.send(message)

        return render_template('verify_otp.html', email=email)
    except Exception as e:
        return render_template('index.html', message=f"An error occurred: {e}")

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    user_otp = request.form.get('otp_combined')
    stored_otp = session.get('otp')
    email = session.get('email')
    encrypted_password = session.get('password')
    first_name = session.get('first_name')
    last_name = session.get('last_name')

    if not user_otp or not stored_otp:
        return render_template('verify_otp.html', email=email, message="OTP is required.")

    try:
        if int(user_otp) == stored_otp:
            # OTP verified, create user in Firebase
            data = {
                "email": email,
                "password": encrypted_password,
                "first_name": first_name,
                "last_name": last_name
            }
            response = requests.post(FIREBASE_URL, json=data)
            if response.status_code == 200:
                # Now user_data is "data" we just inserted
                profile_data = prepare_user_profile(data)
                return render_template(
                    'userProfile.html',
                    email=email,
                    user_data=json.dumps(data),
                    **profile_data
                )
            return render_template('verify_otp.html', email=email, message="Failed to create an account.")
        else:
            return render_template('verify_otp.html', email=email, message="Invalid OTP. Please try again.")
    except Exception as e:
        return render_template('verify_otp.html', email=email, message=f"An error occurred: {e}")

@app.route('/userProfile', methods=['GET'])
def user_profile():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        user_data = get_user_data(email)
        if not user_data:
            return jsonify({"error": "User not found"}), 404

        profile_data = prepare_user_profile(user_data)
        # Pass entire user_data to template
        return render_template(
            'userProfile.html',
            email=email,
            user_data=json.dumps(user_data),
            **profile_data
        )
    except Exception as e:
        return jsonify({"error": f"An error occurred: {e}"}), 500

@app.route('/options')
def options():
    email = request.args.get('email')
    return render_template('options.html', email=email)

@app.route('/youtube')
def youtube():
    email = request.args.get('email')
    return render_template('youtube.html', email=email)

@app.route('/pdf')
def pdf():
    email = request.args.get('email')
    return render_template('pdf.html', email=email)

@app.route('/website')
def website():
    email = request.args.get('email')
    return render_template('website.html', email=email)

@app.route('/scrape', methods=['POST'])
def scrape():
    data = request.get_json()
    url = data.get('url')
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; QuizRiseScraper/1.0)'}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        content = soup.body.get_text(separator=' ', strip=True) if soup.body else ""
        if content:
            return jsonify({'success': True, 'content': content})
        else:
            return jsonify({'success': False, 'message': "No content extracted"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/topic')
def topic():
    email = request.args.get('email')
    return render_template('topic.html', email=email)

# ---------------------
# GENERATE QUIZ & STORE
# ---------------------
@app.route('/generateOnTopic', methods=['POST'])
@app.route('/generateOnTopic', methods=['POST'])
def generate_on_topic():
    data = request.get_json()
    email = data.get('email')
    topic = data.get('topic')
    qtype = data.get('type')  # 'MCQs', 'blanks', 'truefalse', 'generalqa', etc.
    difficulty = data.get('difficulty')

    # Construct your prompt based on the quiz type
    if qtype == 'MCQs':
        prompt = f"""
        Generate 10 MCQs quiz with {difficulty} difficulty level quiz on {topic} in this format:
        **Question 1:** [question]?
        A) [option 1]
        B) [option 2]
        C) [option 3]
        D) [option 4]
        **Answer:** B)
        """
    elif qtype in ['blanks', 'fillintheblank']:
        prompt = f"""
        Generate 10 meaningful {difficulty} fill-in-the-blank questions on {topic} with single blanks + their answers.
        Reply in the format:
        **Question 1:** [question]
        **Answer:** [answer]
        """
    elif qtype in ['truefalse', 'true/false']:
        prompt = f"""
        Generate 10 meaningful {difficulty} True/False questions on {topic} + their answers.
        Format:
        **Question 1:** [statement]
        **Answer:** [True/False]
        """
    else:
        prompt = f"""
        Generate 10 {difficulty} descriptive Q&A on {topic}.
        Format:
        **Question 1:** [question]
        **Answer:** [answer]
        """
    
    try:
        completion = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": "You are responsible to generate quizzes."},
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
    
        # Store the generated quiz (score remains None until the user takes the quiz)
        store_quiz_in_firebase(email, extended_answer, difficulty, qtype, score=None)
    
        return jsonify({
            "message": extended_answer,
            "email": email,
            "difficulty": difficulty,
            "type": qtype
        })
    except Exception as e:
        return jsonify({"error": f"An error occurred while generating the quiz: {e}"}), 500

@app.route('/generate_transcript', methods=['POST'])
def generate_transcript():
    youtube_url = request.form.get("youtube_url")
    if not youtube_url:
        return jsonify({'error': 'Missing YouTube URL'}), 400

    # Extract video ID
    pattern = r"(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:[^\/\n\s]+\/\S+|(?:v|embed|shorts|watch)\/?|watch\?v=)|youtu\.be\/)([^\"&?\/\s]{11})"
    match = re.search(pattern, youtube_url)
    if not match:
        return jsonify({'error': 'Invalid YouTube URL'}), 400

    video_id = match.group(1)
    try:
        transcript = YouTubeTranscriptApi.get_transcript(video_id)
        text_paragraph = " ".join([entry['text'] for entry in transcript])
        return jsonify({'transcript': text_paragraph})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/voice')
def voice():
    email = request.args.get('email')
    return render_template('voice.html', email=email)

@app.route("/transcribe", methods=["POST"])
def transcribe():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        audio_file = request.files["file"]
        file_ext = audio_file.filename.rsplit(".", 1)[-1].lower()
        valid_formats = ["mp3", "wav", "m4a", "flac", "ogg", "aac"]

        if file_ext not in valid_formats:
            return jsonify({"error": "Unsupported file format"}), 400

        # Convert to WAV (16-bit PCM) in-memory
        audio_bytes = audio_file.read()
        audio_io = io.BytesIO(audio_bytes)
        audio = AudioSegment.from_file(audio_io, format=file_ext)
        wav_io = io.BytesIO()
        audio.export(wav_io, format="wav", parameters=["-acodec", "pcm_s16le"])
        wav_io.seek(0)

        # Transcribe using SpeechRecognition
        recognizer = sr.Recognizer()
        with sr.AudioFile(wav_io) as source:
            audio_data = recognizer.record(source)
            text = recognizer.recognize_google(audio_data)

        return jsonify({"text": text})
    except sr.UnknownValueError:
        return jsonify({"error": "Could not understand audio"}), 400
    except sr.RequestError:
        return jsonify({"error": "Speech recognition service error"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/quiz')
def quiz():
    message = request.args.get('message', 'No message provided')
    email = request.args.get('email', 'No email provided')
    return render_template('quiz.html', message=message, email=email)

@app.route('/blank')
def blank():
    message = request.args.get('message', 'No message provided')
    email = request.args.get('email', 'No email provided')
    return render_template('blank.html', email=email, message=message)

@app.route('/truefalse')
def truefalse():
    message = request.args.get('message', 'No message provided')
    email = request.args.get('email', 'No email provided')
    return render_template('truefalse.html', email=email, message=message)

@app.route('/qa')
def generalqa():
    message = request.args.get('message', 'No message provided')
    email = request.args.get('email', 'No email provided')
    return render_template('qa.html', email=email, message=message)

@app.route('/insertResults', methods=['POST', 'GET'])
def insert_results():
    """
    If you still want to store user quiz *scores* after they've attempted
    the quiz, you can keep or adjust this route.
    """
    if request.method == 'POST':
        data = request.json
        email = data.get('email')
        score = data.get('score')
        difficulty = data.get('difficulty')

        if not email:
            return jsonify({"error": "Email is required"}), 400

        try:
            # Fetch user data
            response = requests.get(FIREBASE_URL)
            if response.status_code != 200:
                return jsonify({"error": "Failed to fetch user data from Firebase"}), 500

            users = response.json()
            user_id = None
            user_data = None

            # Find user by email
            for uid, user in users.items():
                if user["email"] == email:
                    user_id = uid
                    user_data = user
                    break

            if not user_data:
                return jsonify({"error": "User not found"}), 404

            current_date = datetime.now() + timedelta(hours=2)
            formatted_date = current_date.strftime("%Y-%m-%d %H:%M:%S")

            quiz_attempts = user_data.get("quiz_attempts", [])
            quiz_attempts.append({
                "score": score,
                "date": formatted_date,
                "difficulty": difficulty
            })

            # Update Firebase
            update_url = f"{FIREBASE_URL.replace('.json', '')}/{user_id}.json"
            update_data = {"quiz_attempts": quiz_attempts}
            update_response = requests.patch(update_url, json=update_data)

            if update_response.status_code == 200:
                return jsonify({"success": "Score saved"}), 200
            else:
                return jsonify({"error": "Failed to update user data in Firebase"}), 500
        except Exception as e:
            print(f"Error storing quiz results: {e}")
            return jsonify({"error": "An error occurred while storing quiz results"}), 500

if __name__ == '__main__':
    app.run(debug=True)
