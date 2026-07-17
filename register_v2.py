import re
import bcrypt

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

USER_STORE: dict[str, dict[str, str]] = {}


def register_user(
    username: str,
    password: str,
    email: str | None = None,
    user_store: dict[str, dict[str, str]] | None = None,
) -> int:
    """
    注册用户。
    返回状态码：
    - 201: 注册成功
    - 400: 参数非法
    - 409: 用户名已存在
    """
    if user_store is None:
        user_store = USER_STORE

    if not isinstance(username, str) or not isinstance(password, str):
        return 400

    username = username.strip()
    if not username or not USERNAME_PATTERN.fullmatch(username):
        return 400

    if not password or not PASSWORD_PATTERN.fullmatch(password):
        return 400

    if email is not None:
        email = email.strip()
        if email and not EMAIL_PATTERN.fullmatch(email):
            return 400
    else:
        email = ""

    if username in user_store:
        return 409

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_store[username] = {
        "password_hash": password_hash,
        "email": email,
    }

    return 201