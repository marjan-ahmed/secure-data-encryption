import streamlit as st    

st.set_page_config("Secure Data Encryption", "🔐")

from cryptography.fernet import Fernet, InvalidToken
import hashlib
import os

# Persistent key storage
KEY_FILE = "fernet.key"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)

cipher = Fernet(KEY)

# Hashing utility
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Simulated database (store usernames, hashed passwords, and encrypted data)
if "users" not in st.session_state:
    st.session_state.users = {}  # { username: hashed_password }

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False

if "username" not in st.session_state:
    st.session_state.username = ""

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # { encrypted_text: {passkey: hash, owner: username} }

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

# Registration page
def register():
    st.title("🔐 Register")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Register"):
        if new_user in st.session_state.users:
            st.warning("🚫 Username already exists.")
        elif new_user and new_pass:
            st.session_state.users[new_user] = hash_text(new_pass)
            st.success("✅ Registered successfully. You can now log in.")

# Login page
def login():
    st.title("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in st.session_state.users:
            if st.session_state.users[username] == hash_text(password):
                st.session_state.is_logged_in = True
                st.session_state.username = username
                st.success(f"✅ User successfully Loged In")
            else:
                st.error("❌ Incorrect password.")
        else:
            st.error("❌ User not found.")

# Encrypt and store data
def encrypt_and_store(data, passkey):
    encrypted_text = cipher.encrypt(data.encode()).decode()
    st.session_state.stored_data[encrypted_text] = {
        "passkey": hash_text(passkey),
        "owner": st.session_state.username
    }
    return encrypted_text

# Decrypt data
def decrypt_and_get(encrypted_text, passkey, username):
    entry = st.session_state.stored_data.get(encrypted_text)
    if not entry or entry["owner"] != username:
        return "🔒 Unauthorized or Data Not Found"

    if hash_text(passkey) == entry["passkey"]:
        st.session_state.failed_attempts[username] = 0
        try:
            return cipher.decrypt(encrypted_text.encode()).decode()
        except InvalidToken:
            return "❌ Decryption failed. Data may be invalid or corrupted."
    else:
        st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
        return "❌ Incorrect passkey."

# Logout
def logout():
    st.session_state.is_logged_in = False
    st.session_state.username = ""
    st.success("👋 Logged out successfully.")

# App flow
def main_app():
    st.title("🛡️ Secure Data Encryption")
    
    st.sidebar.header(f"👋 Welcome, {(st.session_state.username).capitalize()}!")
    menu = ["Store Data", "Retrieve Data", "View Stored Data", "Logout"]
    choice = st.sidebar.radio("Navigation", menu)

    if choice == "Store Data":
        st.header("📥 Store Encrypted Data")
        text = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Passkey", type="password")
        if st.button("Encrypt & Save"):
            if text and passkey:
                result = encrypt_and_store(text, passkey)
                st.success("✅ Data encrypted and saved.")
                st.code(result, language="text")

    elif choice == "Retrieve Data":
        st.header("📤 Retrieve Encrypted Data")
        encrypted_text = st.text_area("Enter encrypted text")
        passkey = st.text_input("Passkey", type="password")
        if st.button("Decrypt"):
            if encrypted_text and passkey:
                result = decrypt_and_get(encrypted_text, passkey, st.session_state.username)
                st.info("Decryption Result:")
                st.write(result)
    
    elif choice == "View Stored Data":
        st.header("🔎 View Your Encrypted Data")
        user_data = [
            (key, value) for key, value in st.session_state.stored_data.items()
            if value["owner"] == st.session_state.username
        ]
        
        if user_data:
            for i, (enc_text, meta) in enumerate(user_data, 1):
                with st.expander(f"🔐 Encrypted Entry #{i}"):
                    st.code(enc_text, language="text")
        else:
            st.info("📭 You have no encrypted data stored.")


    elif choice == "Logout":
        logout()

# Page selector
page = st.sidebar.selectbox("Choose Page", ["Login", "Register", "App"])

if page == "Register":
    register()
elif page == "Login":
    login()
elif page == "App":
    if st.session_state.is_logged_in:
        main_app()
    else:
        st.warning("🔐 Please log in to access the app.")