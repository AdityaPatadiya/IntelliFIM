from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from src.api.models.user_model import User
from src.api.utils.password_utils import hash_password, verify_password
from src.api.utils.jwt_utils import create_access_token
from typing import cast
import logging

logger = logging.getLogger(__name__)

def register_user(db: Session, username: str, email: str, password: str, is_admin: bool = False):
    logger.info(f"🔍 Register attempt - Username: {username}, Email: {email}")

    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        logger.warning(f"❌ Email already registered: {email}")
        raise HTTPException(status_code=400, detail="Email already registered.")

    hashed_pw = hash_password(password)
    logger.info(f"🔍 Password hashed: {hashed_pw[:20]}...")

    new_user = User(
        username=username,
        email=email,
        hashed_password=hashed_pw,
        is_admin=is_admin
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"User registered - ID: {new_user.id}, Admin: {new_user.is_admin}")

    # Create token for the new user
    token = create_access_token({"sub": new_user.email})
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "is_admin": new_user.is_admin
        },
        "message": f"User {new_user.username} registered successfully!"+ 
                  (" You are the administrator." if new_user.is_admin else "")
    }


def login_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()

    if not user:
        logger.warning(f"User not found: {email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    logger.info(f"🔍 User found - ID: {user.id}, Username: {user.username}, Admin: {user.is_admin}")

    # Verify password
    is_valid = verify_password(password, cast(str, user.hashed_password))
    logger.info(f"🔍 Password valid: {is_valid}")
    
    if not is_valid:
        logger.warning(f"Invalid password for user: {email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token = create_access_token({"sub": user.email})
    logger.info(f"Login successful - Token created for: {user.email}")
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        },
        "message": f"Welcome back, {user.username}!" + 
                  (" (Administrator)" if cast(bool, user.is_admin) else "")
    }
