import os
import mysql.connector
import bcrypt
from mysql.connector import Error

# 从环境变量读取数据库配置，提升安全性
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'test')
}

# 数据库连接上下文管理器
class DatabaseConnection:
    def __enter__(self):
        try:
            self.connection = mysql.connector.connect(**db_config)
            return self.connection
        except Error as e:
            print(f"Database connection error: {e}")
            return None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection and self.connection.is_connected():
            self.connection.close()

# 验证用户密码
def authenticate_user(username, password):
    query = "SELECT password FROM users WHERE username = %s"

    with DatabaseConnection() as connection:
        if connection is None:
            return False  # 数据库连接失败

        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (username,))
                user = cursor.fetchone()

                if user and user['password']:
                    # 验证密码
                    stored_password = user['password'].encode('utf-8')
                    if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                        return True
                    else:
                        print("Password does not match.")
                else:
                    print("User not found or password is empty.")
        except Error as e:
            print(f"Database error during authentication: {e}")

    return False

# 获取用户 API 密钥
def get_api_key_by_username(username):
    user_query = "SELECT id FROM users WHERE username = %s AND status = 1"
    token_query = "SELECT `key` FROM tokens WHERE user_id = %s AND status = 1"

    with DatabaseConnection() as connection:
        if connection is None:
            return None  # 数据库连接失败

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
                    else:
                        print("Token not found or invalid.")
                else:
                    print("User not found or inactive.")
        except Error as e:
            print(f"Database error while retrieving API key: {e}")

    return None
