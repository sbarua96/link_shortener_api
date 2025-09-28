# main.py

# === IMPORTS: Bringing in the necessary tools ===
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone

# === CONFIGURATION: Your application's settings ===
# IMPORTANT: Replace this with your actual MongoDB connection string!
MONGO_URI = "mongodb+srv://<username>:<password>@cluster...mongodb.net/"
# This key should be kept secret. Generate a real one with: openssl rand -hex 32
SECRET_KEY = "your-secret-key" 
ALGORITHM = "HS256" # The algorithm used to sign the JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# === DATABASE CONNECTION & SETUP ===
client = MongoClient(MONGO_URI)
db = client.link_shortener_db # Using a new database for this project
users_collection = db.users # Collection to store user data
# Create a unique index on the email field to prevent duplicate accounts
users_collection.create_index("email", unique=True)

# === SECURITY & HASHING SETUP ===
# Sets up the password hashing scheme (bcrypt is the standard)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Tells FastAPI where the token login endpoint is
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# === UTILITY FUNCTIONS (Security Helpers) ===
def verify_password(plain_password, hashed_password):
    """Checks if a plain password matches a hashed one."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generates a secure hash for a plain password."""
    return pwd_context.hash(password)

def create_access_token(data: dict):
    """Creates a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire}) # Add an expiration time to the token
    # Encode the token with your data, secret key, and algorithm
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# === PYDANTIC MODELS (Data Schemas) ===
class UserCreate(BaseModel):
    """The data shape required to create a new user."""
    email: EmailStr
    password: str

class Token(BaseModel):
    """The data shape of the token response after logging in."""
    access_token: str
    token_type: str

# === AUTHENTICATION DEPENDENCY ===
# A function that protected endpoints will depend on to get the current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the token to see the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub") # "sub" is the standard claim for the subject (user's email)
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Find the user from the database based on the email in the token
    user = users_collection.find_one({"email": email})
    if user is None:
        raise credentials_exception
    return user

# === FASTAPI APP INSTANCE ===
app = FastAPI(title="Link Shortener API")

# === API ENDPOINTS (The actual API functionality) ===
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate):
    """Endpoint to register a new user."""
    # Hash the user's password before storing it
    hashed_password = get_password_hash(user.password)
    user_in_db = {"email": user.email, "hashed_password": hashed_password}
    try:
        # Insert the new user into the database
        users_collection.insert_one(user_in_db)
        return {"message": "User created successfully"}
    except DuplicateKeyError:
        # If the email already exists, raise an error
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Endpoint to log in a user and get an access token."""
    # Find the user by their email (which is 'username' in the form)
    user = users_collection.find_one({"email": form_data.username})
    # If user doesn't exist or password doesn't match, raise an error
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # If successful, create a new access token
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}