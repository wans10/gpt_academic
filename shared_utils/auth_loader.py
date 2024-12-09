import mysql.connector
import bcrypt
from mysql.connector import Error

# MySQL 数据库连接配置
db_config = {
    'host': '34.146.163.169',  # 替换为你的数据库地址
    'user': 'oneapi_XZH6Zi',   # 替换为你的数据库用户名
    'password': 'oneapi_4AMN4Y',  # 替换为你的数据库密码
    'database': 'oneapi_nzfhah'
}

# 数据库连接上下文管理器
class DatabaseConnection:
    def __enter__(self):
        self.connection = mysql.connector.connect(**db_config)
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection.is_connected():
            self.connection.close()

# 验证用户密码
def authenticate_user(username, password):
    query = "SELECT password FROM users WHERE username = %s"

    with DatabaseConnection() as connection:
        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (username,))
                user = cursor.fetchone()

                if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                    return True
        except Error as e:
            print(f"Database error during authentication: {e}")

    return False

# 获取用户 API 密钥
def get_api_key_by_username(username):
    user_query = "SELECT id FROM users WHERE username = %s AND status = 1"
    token_query = "SELECT `key` FROM tokens WHERE user_id = %s AND status = 1"

    with DatabaseConnection() as connection:
        try:
            with connection.cursor(dictionary=True) as cursor:
                # 获取用户 ID
                cursor.execute(user_query, (username,))
                user = cursor.fetchone()

                if user:
                    # 获取 API 密钥
                    cursor.execute(token_query, (user['id'],))
                    token = cursor.fetchone()

                    if token and token.get('key'):
                        return f"sk-{token['key']}"
        except Error as e:
            print(f"Database error while retrieving API key: {e}")

    return None