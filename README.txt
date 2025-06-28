Cryptographic 3 Scenarios Demo


### Scenario 1: Secure User Authentication (Python Only)

**Description:** Demonstrates password hashing (PBKDF2) and verification.
**Files:** `Scenario_1.py`
**Dependencies:** `pycryptodome`
**How to Run:**
1.  Save the Python code as `Scenario_1.py`.
2.  Install `pip install pycryptodome` in the same directory as the Python code.
3.  Run in terminal: `python Scenario_1.py`
4.  Follow prompts.

---

### Scenario 2: Secure Local Document Archiving (Python Only)

**Description:** Demonstrates AES, RSA, and ECDSA for document archiving.
**Files:** `Scenario_2.py`, `secret.txt`
**Dependencies:** `pycryptodome`
**How to Run:**
1.  Save the Python code as `Scenario_2.py`.
2.  Save the `secret.txt` in the same directory.
3.  Install `pip install pycryptodome` in the same directory.
4.  Run in terminal: `Scenario_2.py`
5.  Follow prompts.
6.  Type `yes` or `no` when prompted for performance test.

---

### Scenario 3: Secure User Authentication (HTML Frontend with Flask Backend)

**Description:** Interactive web demo for password hashing/verification.
**Files:** `Scenario_3.py`, `Scenario_3_web.html`
**Dependencies:** `Flask`, `Flask-Cors`
**How to Run:**
1.  Save Python code as `Scenario_3.py`.
2.  Save HTML code as `Scenario_3_web.html` (ensure no Python code inside).
3.  Install `pip install Flask Flask-Cors` in the same directory.
4.  **Terminal (Backend) Run the Python code (Keep this running):**
    ```
    python Scenario_3.py
    ```
5.  **Browser:** Open `Scenario_3_web.html` file
    * If "Failed to fetch", ensure the server is running `http://127.0.0.1:5000`.
6.  Start by registering an account with a username and password.
7.  Try logging in with the username and password.
8.  Observe the cryptographic process.

---
