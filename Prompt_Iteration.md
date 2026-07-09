# 第一次提示词：写一个验证用户登陆账号用户名＋密码的函数
def validate_login(username, password):
    # 基础校验
    if not username or not password:
        return False

    if len(username) < 3 or len(username) > 20:
        return False

    if len(password) < 6:
        return False

    # 这里可以替换成你的用户数据库/表
    valid_users = {
        "admin": "123456",
        "alice": "abc123",
        "bob": "password"
    }

    return valid_users.get(username) == password


# 示例调用
print(validate_login("admin", "123456"))  # True
print(validate_login("admin", "wrong"))   # False


# 第二次提示词：写一个验证用户登陆账号用户名＋密码的函数 用户名非空 密码长度至少六位 返回成功或失败的状态码
def validate_login(username, password):
    if not username:
        return 400  # 用户名为空

    if len(password) < 6:
        return 401  # 密码长度不足

    return 200  # 登录验证成功


# 示例调用
print(validate_login("admin", "123456"))   # 200
print(validate_login("", "123456"))        # 400
print(validate_login("admin", "123"))      # 401
# 第二次ai加入了一个新的验证用户密码的函数，加入了非法密码的验证 需要和之前的函数共用


# 第三次提示词 这个登录验证函数需要考虑那些安全风险，解释你的设计思路，然后再给出完整的python代码实现
我会先把常见的登录安全风险和一个更稳妥的实现思路梳理清楚，然后给出完整的 Python 代码。
下面这个登录验证函数，除了满足“用户名非空、密码至少 6 位”之外，还考虑了几个常见的安全风险。
需要考虑的安全风险
明文密码存储
不能把密码直接以明文存到数据库里。
正确做法是注册时把密码进行哈希加盐处理，登录时再比对哈希值。
密码比较方式
不能用普通字符串比较直接判断密码是否相等。
应该使用安全的密码哈希库，例如 bcrypt 或 argon2，并利用常量时间比较。
用户名枚举
登录失败时，最好不要明确告诉用户“用户名不存在”还是“密码错误”。
否则攻击者可以通过枚举用户名。
暴力破解
登录接口应限制频率，避免被不断尝试密码。
生产环境中通常会加上限流、锁定账户、验证码等机制。
输入处理
用户名和密码都应做基本的类型检查和长度检查。
还应避免过长输入导致资源浪费。
设计思路
对用户名做去空格处理，判断是否为空。
对密码做长度校验，至少 6 位。
不直接存储明文密码，而是使用 bcrypt 哈希。
登录失败时统一返回 401，避免泄露具体原因。
成功时返回 200，格式错误返回 400。

先安装依赖
pip install bcrypt

import bcrypt

 #示例：实际项目中这里应该从数据库读取
USER_STORE = {
    "alice": bcrypt.hashpw(b"StrongPass123!", bcrypt.gensalt()).decode("utf-8"),
}

def validate_login(username: str, password: str) -> int:
    # 1. 基本类型检查
    if not isinstance(username, str) or not isinstance(password, str):
        return 400

    # 2. 用户名校验
    username = username.strip()
    if not username:
        return 400

    # 3. 密码长度校验
    if len(password) < 6:
        return 401

    # 4. 查找用户
    stored_hash = USER_STORE.get(username)
    if stored_hash is None:
        # 为了避免用户名枚举，统一返回 401
        return 401

    # 5. 使用 bcrypt 验证密码
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8")):
        return 401

    # 6. 登录成功
    return 200


# 示例调用
print(validate_login("alice", "StrongPass123!"))  # 200
print(validate_login("", "StrongPass123!"))       # 400
print(validate_login("alice", "123"))             # 401
print(validate_login("bob", "wrongpass"))         # 401

