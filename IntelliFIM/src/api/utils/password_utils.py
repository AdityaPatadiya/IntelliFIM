from passlib.context import CryptContext
import bcrypt

# Use a simpler approach with direct bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash using bcrypt directly
    """
    try:
        # Convert to bytes and verify
        plain_bytes = plain_password.encode('utf-8')
        
        # If password is too long, truncate it
        if len(plain_bytes) > 72:
            plain_bytes = plain_bytes[:72]
            
        # Verify using bcrypt directly
        return bcrypt.checkpw(plain_bytes, hashed_password.encode('utf-8'))
    except Exception as e:
        print(f"❌ Password verification error: {e}")
        return False

def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt directly
    """
    try:
        # Convert to bytes
        password_bytes = password.encode('utf-8')
        
        # If password is too long, truncate it
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
            
        # Generate salt and hash
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        return hashed.decode('utf-8')
    except Exception as e:
        print(f"❌ Password hashing error: {e}")
        raise e
