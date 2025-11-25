from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from src.api.schemas.user_schema import UserCreate, UserLogin, UserResponse
from src.api.database.connection import get_auth_db
from src.api.services.auth_service import register_user, login_user
from src.api.utils.jwt_utils import verify_token
from src.api.models.user_model import User

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Helper function to verify admin access
def verify_admin_access(token_data: dict, db: Session) -> User:
    """Verify that the current user is an admin"""
    admin = db.query(User).filter(User.email == token_data["sub"]).first()
    if not admin or not getattr(admin, 'is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return admin

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_auth_db)):
    return register_user(db, user.username, user.email, user.password, is_admin=True)

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_auth_db)):
    return login_user(db, user.email, user.password)

@router.get("/me")
def get_me(token_data: dict = Depends(verify_token), db: Session = Depends(get_auth_db)):
    user = db.query(User).filter(User.email == token_data["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": getattr(user, 'is_admin', False)
    }

@router.get("/users")
def get_all_users(
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_auth_db)
):
    """Get all users (admin only)"""
    verify_admin_access(token_data, db)
    users = db.query(User).all()

    return [
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": getattr(user, 'is_admin', False)
        }
        for user in users
    ]

@router.post("/users")
def create_user(
    user: UserCreate,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_auth_db)
):
    """Create a new user (admin only)"""
    verify_admin_access(token_data, db)

    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    return register_user(db, user.username, user.email, user.password)

@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    user_update: UserCreate,  # Renamed to avoid conflict
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_auth_db)
):
    """Update a user (admin only)"""

    verify_admin_access(token_data, db)
    existing_user = db.query(User).filter(User.id == user_id).first()
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_update.email != existing_user.email:
        email_exists = db.query(User).filter(
            User.email == user_update.email, 
            User.id != user_id
        ).first()
        if email_exists:
            raise HTTPException(status_code=400, detail="Email already in use")

    existing_user.username = user_update.username  # type:ignore
    existing_user.email = user_update.email  # type:ignore

    if user_update.password:
        from src.api.utils.password_utils import hash_password
        existing_user.hashed_password = hash_password(user_update.password)  # type:ignore

    db.commit()
    db.refresh(existing_user)

    return {
        "id": existing_user.id,
        "username": existing_user.username,
        "email": existing_user.email,
        "is_admin": getattr(existing_user, 'is_admin', False)
    }

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_auth_db)
):
    """Delete a user (admin only)"""
    admin = verify_admin_access(token_data, db)

    if admin.id == user_id:  # type:ignore
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

@router.put("/users/{user_id}/admin")
def toggle_admin_status(
    user_id: int,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_auth_db)
):
    """Toggle admin status for a user (admin only)"""
    admin = verify_admin_access(token_data, db)

    if admin.id == user_id:  # type:ignore
        raise HTTPException(status_code=400, detail="Cannot modify your own admin status")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_admin = not user.is_admin  # type:ignore
    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_admin": user.is_admin,
        "message": f"User {'promoted to' if user.is_admin else 'demoted from'} admin"  # type:ignore
    }
