import re
import bcrypt

def register_user(username: str, password: str, email: str, user_store: dict) -> int:
    if not isinstance(username, str) or not isinstance(password, str) or not isinstance(email, str):
        return 400

    username = username.strip()
    email = email.strip().lower()

    if not username or not email:
        return 400

    if len(username) < 3 or len(username) > 32:
        return 400

    if len(password) < 8:
        return 400

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return 400

    if username in user_store:
        return 409

    for user in user_store.values():
        if user.get("email") == email:
            return 409

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_store[username] = {
        "email": email,
        "password_hash": password_hash,
    }

    return 201