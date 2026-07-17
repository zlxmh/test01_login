# 用 Python 写一个用户注册函数，参数为用户名、密码、邮箱，返回状态码。
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

# """ 用 Python 写一个用户注册函数，参数为 username、password、email。要求：

1. username 必填，3-20 位字母数字下划线
2. password 必填，至少 8 位，含大小写字母和数字
3. email 可选，若填写需校验邮箱格式
4. 返回标准化状态码（201/400/409）
5. 密码使用 bcrypt 加密存储
6. 用户名已存在返回 409"""


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

# 请先思考用户注册功能需要处理哪些安全风险（如重复用户名、弱密码、注入攻击等），并设计一个合理的存储方案，然后再给出完整的 Python 代码实现。
import re
import bcrypt

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

USER_STORE: dict[str, dict[str, str | None]] = {}


def register_user(
    username: str,
    password: str,
    email: str | None = None,
    user_store: dict[str, dict[str, str | None]] | None = None,
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

    # 基本类型校验
    if not isinstance(username, str) or not isinstance(password, str):
        return 400

    # 规范化输入
    username = username.strip()
    if email is not None:
        email = email.strip()

    # 用户名校验
    if not username or not USERNAME_PATTERN.fullmatch(username):
        return 400

    # 密码校验
    if not password or not PASSWORD_PATTERN.fullmatch(password):
        return 400

    # 邮箱校验（可选）
    if email is not None and email != "" and not EMAIL_PATTERN.fullmatch(email):
        return 400

    # 重复用户名校验
    if username in user_store:
        return 409

    # 密码哈希
    try:
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    except Exception:
        return 400

    # 存储用户信息
    user_store[username] = {
        "password_hash": password_hash,
        "email": email,
    }

    return 201

    # Prompt 策略手册 v2.0

## 1. 策略一：直接指令
适用场景：快速原型、功能验证
优点：生成速度快，代码简洁，能快速得到可运行版本
缺点：缺少约束细节，边界处理不足，安全性较弱，需要人工后续补充
模板：用 [语言] 写一个 [功能] 函数，参数为 [参数列表]，返回 [返回值描述]

## 2. 策略二：带约束指令
适用场景：有明确业务规范的功能开发
优点：输出代码更规范，覆盖大部分边界条件，可直接在开发环境中使用
缺点：需要提前想清楚所有约束，否则容易遗漏
模板：用 [语言] 写一个 [功能] 函数，参数为 [参数列表]。要求：[具体约束清单]

## 3. 策略三：分步思考指令
适用场景：复杂功能、生产级代码、对安全性和健壮性要求高的场景
优点：AI 先思考后输出，代码更健壮，考虑了异常处理和安全性
缺点：输出较长，耗时稍多
模板：请先思考 [功能] 需要考虑哪些 [安全/性能/架构] 风险，并设计方案，再给出完整的 [语言] 代码实现。

**总结**：在开发时间充裕、功能复杂、要求严格时，优先选择「分步思考指令」策略；在快速验证或原型阶段，「直接指令」策略更高效；而「带约束指令」策略适用于大多数常规开发场景。