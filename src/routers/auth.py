import os
import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import EmailStr
from src.database import get_db
from src.models.db_models import User
from src.schemas import UserCreate, UserResponse

# ------------------- Logging Setup -------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ------------------- Environment Variables -------------------
SECRET_KEY = "26fb81bf2adbda2b225009d386e156fa0979451294ba06963fb11907011cc0fc"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
EMAIL_TOKEN_EXPIRE_MINUTES = 15

GOOGLE_CLIENT_ID = "your_google_client_id"
GOOGLE_CLIENT_SECRET = "your_google_client_secret"
FACEBOOK_CLIENT_ID = "your_facebook_client_id"
FACEBOOK_CLIENT_SECRET = "your_facebook_client_secret"

# ------------------- Password Hashing -------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ------------------- Email Configuration -------------------
conf = ConnectionConfig(
    MAIL_USERNAME="your_actual_email@gmail.com",  # 🔹 Replace with your Gmail
    MAIL_PASSWORD="your_generated_app_password",  # 🔹 Replace with the App Password from Google
    MAIL_FROM="your_actual_email@gmail.com",  # 🔹 Same as MAIL_USERNAME
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
)



mail = FastMail(conf)
router = APIRouter(prefix="/auth", tags=["Authentication"])

# ------------------- Token Handling -------------------
def create_token(data: dict, expires_delta: timedelta):
    expire = datetime.now(timezone.utc) + expires_delta
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(user: User):
    return create_token({"sub": user.email, "role": user.role}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(user: User):
    return create_token({"sub": user.email}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))


# ------------------- Password Handling -------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ------------------- Email Sending -------------------
async def send_email_background(background_tasks: BackgroundTasks, subject: str, email: str, body: str):
    try:
        message = MessageSchema(
            subject=subject,
            recipients=[email],
            body=body,
            subtype="html"
        )
        print(f"📨 Preparing to send email to {email}...")
        background_tasks.add_task(mail.send_message, message)
        print(f"✅ Email task added successfully to {email}")
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")


# ------------------- User Authentication -------------------
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.email == email).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")

        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ------------------- User Registration & Email Verification -------------------
@router.post("/register")
async def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or Username already registered")

    hashed_password = hash_password(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        phone_number=user_data.phone_number,
        password=hashed_password,
        location=user_data.location,
        is_active=False,
        role="user"
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Send verification email directly
    token = create_token({"sub": new_user.email}, timedelta(minutes=EMAIL_TOKEN_EXPIRE_MINUTES))
    email_body = f"Click the link to verify your email: http://localhost:8000/auth/verify-email?token={token}"

    try:
        message = MessageSchema(
            subject="Verify Your Email",
            recipients=[new_user.email],
            body=email_body,
            subtype="html"
        )
        await mail.send_message(message)
        print(f"✅ Email sent successfully to {new_user.email}")
    except Exception as e:
        print(f"❌ Failed to send email: {str(e)}")

    return {"message": "Registration successful. Please check your email to verify your account."}

@router.get("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.is_active = True
        db.commit()

        return {"message": "Email verified successfully. You can now log in."}
    
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


# ------------------- Login & Refresh Token -------------------
@router.post("/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        (User.email == form_data.username) | (User.username == form_data.username)
    ).first()

    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Please verify your email first")

    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role
    }


@router.post("/refresh")
def refresh_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        new_access_token = create_token({"sub": email}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid refresh token")


# ------------------- Forgot & Reset Password -------------------
@router.post("/forgot-password")
async def forgot_password(email: EmailStr, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = create_token({"sub": user.email}, timedelta(minutes=EMAIL_TOKEN_EXPIRE_MINUTES))

    email_body = f"Click the link to reset your password: http://localhost:8000/auth/reset-password?token={token}"
    await send_email_background(background_tasks, "Reset Your Password", email, email_body)

    return {"message": "Password reset link has been sent to your email"}


@router.post("/reset-password")
def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.password = hash_password(new_password)
        db.commit()

        return {"message": "Password has been successfully reset"}
    
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

def get_admin_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return user
