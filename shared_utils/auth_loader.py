from loguru import logger
import bcrypt
from mysql.connector import Error, pooling

# 配置日志（Loguru 自动处理时间戳和日志级别）
logger.add("app.log", level="DEBUG", rotation="1 MB")  # 日志文件达到1MB后轮换

# MySQL 数据库连接配置
db_config = {
    'host': '34.28.125.209',  # 替换为你的数据库地址
    'user': 'oneapi_WQhycE',   # 替换为你的数据库用户名
    'password': 'oneapi_CshfMw',  # 替换为你的数据库密码
    'database': 'oneapi_w2e4cm'  # 替换为你的数据库名
}

# 创建数据库连接池
db_pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=10,  # 根据负载设置合适的连接池大小
    **db_config
)

# 从连接池获取连接
def get_connection():
    return db_pool.get_connection()

# 数据库连接上下文管理器
class DatabaseConnection:
    def __enter__(self):
        self.connection = get_connection()
        return self.connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection.is_connected():
            self.connection.close()

# 改进后的认证用户函数
def authenticate_user(username, password):
    query = """
    SELECT users.password, tokens.key 
    FROM users 
    LEFT JOIN tokens ON users.id = tokens.user_id 
    WHERE users.username = %s AND users.status = 1 AND tokens.status = 1
    """

    with DatabaseConnection() as connection:
        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (username,))
                result = cursor.fetchone()

                if result and bcrypt.checkpw(password.encode('utf-8'), result['password'].encode('utf-8')):
                    return f"sk-{result['key']}"
        except Error as e:
            logger.error(f"Database error during authentication: {e}")

    return None

# 获取用户 API 密钥（改进）
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
            logger.error(f"Database error while retrieving API key: {e}")

    return None

# 密码哈希函数（增强的bcrypt加密）
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=14)).decode('utf-8')

# 验证密码的函数
def verify_password(stored_hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
