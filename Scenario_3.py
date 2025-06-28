import hashlib
import os
import base64
import time
from flask import Flask, request, jsonify
from flask_cors import CORS

# In the terminal, run: `pip install Flask Flask-Cors`

app = Flask(__name__)
CORS(app) # Enable CORS for development to connect to the HTML file

# Simulated user database
users_db = {}

# --- Configuration for PBKDF2 ---
PBKDF2_ITERATIONS = 300000  # Number of iterations for PBKDF2-HMAC-SHA256
PBKDF2_KEY_LENGTH = 32      # Length of the derived key (256 bits)
PBKDF2_HASH_ALGORITHM = 'sha256' # Hashing algorithm for PBKDF2


def generate_salt(length=16):
    """
    Generates a cryptographically secure pseudorandom salt.
    Args:
        length (int): The length of the salt in bytes.
    Returns:
        bytes: The generated salt.
    """
    return os.urandom(length)

def hash_password(password):
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a unique salt.
    Args:
        password (str): The plaintext password.
    Returns:
        tuple: A tuple containing (salt_b64, hashed_password_b64, iterations),
               where salt_b64 and hashed_password_b64 are base64 encoded strings.
    """
    start_time = time.time()

    # Generate a unique salt for each password
    salt = generate_salt()

    # Derive the key using PBKDF2
    # The `pbkdf2_hmac` function returns bytes
    hashed_password_bytes = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_ALGORITHM,
        password.encode('utf-8'), # Password must be bytes
        salt,
        PBKDF2_ITERATIONS,
        dklen=PBKDF2_KEY_LENGTH
    )

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    # Simulate performance based on iterations
    # These are arbitrary values for demonstration, adjust as needed
    simulated_latency_ms = latency_ms + (PBKDF2_ITERATIONS / 1000) # Add latency based on iterations

    return {
        "salt_b64": base64.b64encode(salt).decode('utf-8'),
        "hashed_password_b64": base64.b64encode(hashed_password_bytes).decode('utf-8'),
        "iterations": PBKDF2_ITERATIONS,
        "latency_ms": round(simulated_latency_ms, 2)
    }

def verify_password(username, password_attempt):
    """
    Verifies a plaintext password attempt against a stored hashed password.
    Args:
        username (str): The username.
        password_attempt (str): The plaintext password attempt.
    Returns:
        dict: A dictionary indicating if verification was successful and performance metrics.
    """
    start_time = time.time()

    if username not in users_db:
        # Return technical details even if user not found, but with empty/default values
        return {
            "success": False,
            "message": "User not found.",
            "latency_ms": 0,
            "throughput_ops_s": 0,
            "technical_details": {
                "retrieved_salt_b64": "N/A",
                "rehashed_attempt_b64": "N/A",
                "iterations": PBKDF2_ITERATIONS
            }
        }

    stored_data = users_db[username]
    stored_salt = base64.b64decode(stored_data['salt_b64'])
    stored_hash = base64.b64decode(stored_data['hashed_password_b64'])
    iterations = stored_data['iterations']

    # Re-hash the provided password attempt with the stored salt and iterations
    hashed_attempt_bytes = hashlib.pbkdf2_hmac(
        PBKDF2_HASH_ALGORITHM,
        password_attempt.encode('utf-8'),
        stored_salt,
        iterations,
        dklen=PBKDF2_KEY_LENGTH
    )

    # Compare the newly generated hash with the stored hash
    is_correct = (hashed_attempt_bytes == stored_hash)

    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    # Simulate performance based on iterations
    simulated_latency_ms = latency_ms + (iterations / 1000) # Add latency based on iterations

    return {
        "success": is_correct,
        "message": "Password verified successfully." if is_correct else "Incorrect password.",
        "latency_ms": round(simulated_latency_ms, 2),
        "throughput_ops_s": round(1000 / simulated_latency_ms, 2) if simulated_latency_ms > 0 else 0, # Operations per second
        "technical_details": { # Added for frontend display
            "retrieved_salt_b64": base64.b64encode(stored_salt).decode('utf-8'),
            "rehashed_attempt_b64": base64.b64encode(hashed_attempt_bytes).decode('utf-8'),
            "iterations": iterations
        }
    }

def register_user_logic(username, password):
    """
    Registers a new user by hashing their password and storing it.
    Args:
        username (str): The username to register.
        password (str): The plaintext password.
    Returns:
        dict: Registration status and technical details.
    """
    if username in users_db:
        return {"success": False, "message": "Username already exists."}

    hash_result = hash_password(password)
    users_db[username] = {
        'salt_b64': hash_result['salt_b64'],
        'hashed_password_b64': hash_result['hashed_password_b64'],
        'iterations': hash_result['iterations']
    }
    return {
        "success": True,
        "message": "User registered successfully.",
        "technical_details": {
            "salt_b64": hash_result['salt_b64'],
            "hashed_password_b64": hash_result['hashed_password_b64'],
            "iterations": hash_result['iterations']
        },
        "performance": {
            "latency_ms": hash_result['latency_ms'],
            "throughput_ops_s": round(1000 / hash_result['latency_ms'], 2) if hash_result['latency_ms'] > 0 else 0
        }
    }

# Flask Routes
@app.route('/register_user', methods=['POST'])
def api_register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    result = register_user_logic(username, password) # Call the logic function
    return jsonify(result)

@app.route('/verify_password', methods=['POST'])
def api_verify_password():
    data = request.json
    username = data.get('username')
    password_attempt = data.get('password_attempt')
    if not username or not password_attempt:
        return jsonify({"error": "Username and password attempt are required"}), 400
    result = verify_password(username, password_attempt)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000) # Change the port if 5000 is in use