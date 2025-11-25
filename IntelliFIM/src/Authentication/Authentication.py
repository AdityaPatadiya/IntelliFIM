"""
authentication.py
-----------------
Handles user registration and authentication using SQLAlchemy ORM
and the users table from the auth database.
"""

import getpass
import hashlib
import os
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from src.api.database.connection import AuthSessionLocal
from src.api.models.user_model import User

load_dotenv()


class Authentication:
    def __init__(self):
        self.db = AuthSessionLocal()

    def hash_password(self, password: str) -> str:
        """Generate a SHA-256 hash for the password using a pepper."""
        salt = os.getenv('PEPPER', 'default-secret-pepper')
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def register_new_user(self):
        """Register a new user using SQLAlchemy ORM."""
        username = input("Enter new username: ").strip()
        email = input("Enter email: ").strip()
        password = getpass.getpass("Enter new password: ")

        if not username or not email:
            print("Username and email cannot be empty.")
            return

        if len(password) < 8:
            print("Password must be at least 8 characters.")
            return

        hashed_password = self.hash_password(password)

        new_user = User(
            username=username,
            email=email,
            hashed_password=hashed_password,
            is_admin=True
        )

        try:
            self.db.add(new_user)
            self.db.commit()
            print("✅ User registered successfully.")
            return username
        except IntegrityError:
            self.db.rollback()
            print("⚠️ Username or email already exists. Try logging in instead.")
            return self.login_existing_user()
        except Exception as e:
            self.db.rollback()
            print(f"❌ Registration failed: {e}")

    def login_existing_user(self):
        """Authenticate an existing user using SQLAlchemy ORM."""
        email = input("Enter email: ").strip()
        password = getpass.getpass("Enter password: ")
        hashed_password = self.hash_password(password)

        user = (
            self.db.query(User)
            .filter(User.email == email, User.hashed_password == hashed_password)
            .first()
        )

        if user:
            print("✅ Authentication successful.")
        else:
            print("❌ Access denied. Invalid credentials.")
            exit(1)
        return email

    def authorised_credentials(self):
        """Prompt user to register or log in."""
        while True:
            choice = input("Are you a new user? (yes/no): ").strip().lower()
            if choice == 'yes':
                return self.register_new_user()
            elif choice == 'no':
                return self.login_existing_user()
            else:
                print(f"Invalid choice. Please enter 'yes' or 'no'. You entered: {choice}")

    def close_connection(self):
        """Close the SQLAlchemy session."""
        self.db.close()
