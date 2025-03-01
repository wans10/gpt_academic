import mysql.connector
from loguru import logger
import bcrypt
from mysql.connector import Error, pooling
from typing import Optional, Dict, Any
import time
from contextlib import contextmanager

# 配置日志
logger.add(
    "app.log",
    level="DEBUG",
    rotation="1 MB",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)

# 数据库配置
db_config = {
    'host': '34.45.76.142',
    'user': 'llmhub',
    'password': 'cJWw5JaJSm7mcnp3',
    'database': 'one-hub',
    'auth_plugin': 'mysql_native_password',
    'connection_timeout': 5
}

# 创建数据库连接池
try:
    db_pool = pooling.MySQLConnectionPool(
        pool_name="mypool",
        pool_size=10,
        **db_config
    )
    logger.info("Database connection pool created successfully")
except Error as e:
    logger.error(f"Error creating connection pool: {e}")
    raise

class DatabaseConnection:
    """数据库连接上下文管理器"""
    def __enter__(self):
        try:
            self.connection = db_pool.get_connection()
            return self.connection
        except Error as e:
            logger.error(f"Error getting connection from pool: {e}")
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self, 'connection') and self.connection.is_connected():
            self.connection.close()

def diagnostic_query(username: str) -> Dict[str, Any]:
    """诊断查询函数，用于调试认证问题"""
    query = """
    SELECT 
        u.id,
        u.username,
        u.status as user_status,
        t.status as token_status,
        CASE WHEN u.password IS NULL THEN 'null' ELSE 'exists' END as has_password,
        CASE WHEN t.key IS NULL THEN 'null' ELSE 'exists' END as has_key
    FROM users u
    LEFT JOIN tokens t ON u.id = t.user_id
    WHERE u.username = %s
    """

    with DatabaseConnection() as connection:
        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (username,))
                result = cursor.fetchone()
                logger.debug(f"Diagnostic result for {username}: {result}")
                return result or {}
        except Error as e:
            logger.error(f"Diagnostic query error: {e}")
            return {}

def authenticate_user(username: str, password: str) -> Optional[str]:
    """
    用户认证函数
    返回: None 表示认证失败，否则返回 API key
    """
    if not username or not password:
        logger.warning("Empty username or password provided")
        return None

    # 首先检查用户和密码
    auth_query = """
    SELECT u.id, u.password 
    FROM users u 
    WHERE u.username = %s AND u.status = 1
    """

    with DatabaseConnection() as connection:
        try:
            with connection.cursor(dictionary=True) as cursor:
                # 第一步：验证用户
                cursor.execute(auth_query, (username,))
                user = cursor.fetchone()

                if not user or not user.get('password'):
                    logger.debug(f"User not found or no password set: {username}")
                    return None

                # 第二步：验证密码
                try:
                    password_valid = bcrypt.checkpw(
                        password.encode('utf-8'),
                        user['password'].encode('utf-8')
                    )
                except ValueError as e:
                    logger.error(f"Password validation error: {e}")
                    return None

                if not password_valid:
                    logger.debug(f"Invalid password for user: {username}")
                    return None

                # 第三步：获取有效的API密钥
                token_query = """
                SELECT `key` 
                FROM tokens 
                WHERE user_id = %s AND status = 1 
                LIMIT 1
                """
                cursor.execute(token_query, (user['id'],))
                token = cursor.fetchone()

                if token and token.get('key'):
                    api_key = f"sk-{token['key']}"
                    logger.info(f"Successfully authenticated user: {username}")
                    return api_key
                else:
                    logger.debug(f"No active token found for user: {username}")
                    return None

        except Error as e:
            logger.error(f"Database error during authentication: {e}")
            return None

def verify_password(stored_hash: str, password: str) -> bool:
    """验证密码"""
    try:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            stored_hash.encode('utf-8')
        )
    except ValueError as e:
        logger.error(f"Password verification error: {e}")
        return False

def hash_password(password: str) -> str:
    """生成密码哈希"""
    try:
        return bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=12)
        ).decode('utf-8')
    except ValueError as e:
        logger.error(f"Password hashing error: {e}")
        raise

def get_api_key_by_username(username: str) -> Optional[str]:
    """获取用户的API密钥"""
    if not username:
        return None

    query = """
    SELECT t.key
    FROM users u
    JOIN tokens t ON u.id = t.user_id
    WHERE u.username = %s 
    AND u.status = 1 
    AND t.status = 1
    LIMIT 1
    """

    with DatabaseConnection() as connection:
        try:
            with connection.cursor(dictionary=True) as cursor:
                cursor.execute(query, (username,))
                result = cursor.fetchone()

                if result and result.get('key'):
                    return f"sk-{result['key']}"
                logger.debug(f"No active API key found for user: {username}")
                return None
        except Error as e:
            logger.error(f"Database error while retrieving API key: {e}")
            return None
