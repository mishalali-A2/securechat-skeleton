"""
MySQL database layer for secure chat user management.
Handles user registration, authentication with salted password hashing.
"""

import os
import sys
import secrets
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv
from ..common.utils import create_sha256_hex_hash


class DatabaseConfiguration:
    """Database connection configuration from environment variables."""
    
    def __init__(self):
        load_dotenv()  # Load environment variables from .env file
        
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", "3306"))
        self.username = os.getenv("DB_USER", "scuser")
        self.password = os.getenv("DB_PASSWORD", "scpass")
        self.database_name = os.getenv("DB_NAME", "securechat")
    
    def get_connection_parameters(self) -> dict:
        """Return connection parameters as dictionary."""
        return {
            'host': self.host,
            'port': self.port,
            'user': self.username,
            'password': self.password,
            'database': self.database_name
        }


class UserDatabaseManager:
    """Manages user data storage and authentication operations."""
    
    # SQL statement to create users table
    CREATE_USERS_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    
    # SQL statements for user operations
    INSERT_USER_SQL = """
    INSERT INTO users (email, username, salt, pwd_hash) 
    VALUES (%s, %s, %s, %s)
    """
    
    SELECT_USER_AUTH_DATA_SQL = """
    SELECT salt, pwd_hash FROM users WHERE username = %s
    """
    
    CHECK_USER_EXISTS_SQL = """
    SELECT 1 FROM users WHERE username = %s OR email = %s
    """

    def __init__(self):
        """Initialize database connection and ensure table exists."""
        self.config = DatabaseConfiguration()
        self.connection = None
        self.cursor = None
        self._establish_database_connection()
        self._verify_table_structure()

    def _establish_database_connection(self):
        """Establish connection to MySQL database."""
        try:
            self.connection = mysql.connector.connect(
                **self.config.get_connection_parameters()
            )
            self.cursor = self.connection.cursor()
        except mysql.connector.Error as connection_error:
            print(f"[DATABASE] Connection failed: {connection_error}")
            print("Please ensure MySQL service is running and credentials are correct.")
            self.connection = None
            self.cursor = None

    def _verify_table_structure(self):
        """Ensure users table exists with correct schema."""
        if not self.connection:
            return
            
        try:
            self.cursor.execute(self.CREATE_USERS_TABLE_SQL)
            self.connection.commit()
        except mysql.connector.Error as table_error:
            print(f"[DATABASE] Table creation failed: {table_error}")

    def _generate_cryptographic_salt(self) -> bytes:
       
        return os.urandom(16)

    def _compute_salted_password_hash(self, password: str, salt: bytes) -> str:
      
        salted_input = salt + password.encode('utf-8')
        return create_sha256_hex_hash(salted_input)

    def register_new_user(self, email: str, username: str, password: str) -> bool:
       
        if not self.connection:
            return False
            
        try:
            # Check if user already exists
            self.cursor.execute(self.CHECK_USER_EXISTS_SQL, (username, email))
            if self.cursor.fetchone():
                return False  # User already exists
            
            # Generate salt and compute hash
            salt_bytes = self._generate_cryptographic_salt()
            password_hash = self._compute_salted_password_hash(password, salt_bytes)
            
            # Store user in database
            user_parameters = (email, username, salt_bytes, password_hash)
            self.cursor.execute(self.INSERT_USER_SQL, user_parameters)
            self.connection.commit()
            
            return True
            
        except mysql.connector.IntegrityError:
            # Unique constraint violation (username/email already exists)
            return False
        except mysql.connector.Error as db_error:
            print(f"[DATABASE] Registration error: {db_error}")
            return False

    def authenticate_user(self, username: str, password: str) -> bool:
      
        if not self.connection:
            return False
            
        try:
            # Retrieve stored salt and hash
            self.cursor.execute(self.SELECT_USER_AUTH_DATA_SQL, (username,))
            auth_data = self.cursor.fetchone()
            
            if not auth_data:
                return False  # User not found
                
            stored_salt, stored_hash = auth_data
            
            # Recompute hash with provided password and stored salt
            computed_hash = self._compute_salted_password_hash(password, stored_salt)
            
            # Constant-time comparison to prevent timing attacks
            return stored_hash == computed_hash
            
        except mysql.connector.Error as auth_error:
            print(f"[DATABASE] Authentication error: {auth_error}")
            return False

    def close_connection(self):
        """Close database connection gracefully."""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()


def initialize_database_schema():
    
    config = DatabaseConfiguration()
    
    try:
        print(f"Connecting to MySQL at {config.host}:{config.port}...")
        database_connection = mysql.connector.connect(
            **config.get_connection_parameters()
        )
        database_cursor = database_connection.cursor()

        print("Creating 'users' table if it doesn't exist...")
        database_cursor.execute(UserDatabaseManager.CREATE_USERS_TABLE_SQL)
        database_connection.commit()

        print("✅ Database schema initialized successfully.")
        
    except mysql.connector.Error as database_error:
        if database_error.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("❌ Database access denied: Check username and password.")
        elif database_error.errno == errorcode.ER_BAD_DB_ERROR:
            print("❌ Database does not exist. Please create it first.")
        else:
            print(f"❌ MySQL Error: {database_error}")
    finally:
        if 'database_cursor' in locals():
            database_cursor.close()
        if 'database_connection' in locals():
            database_connection.close()


if __name__ == "__main__":
    # Allow database initialization via command line
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        initialize_database_schema()
    else:
        print("Usage: python -m storage.db --init")