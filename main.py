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
from typing import List
import string
import random

# === CONFIGURATION: Your application's settings ===
# IMPORTANT: Replace this with your actual MongoDB connection string!
MONGO_URI = "mongodb+srv://sbarua:batman123@cluster0.wnsbwvu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
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
links_collection = db.links # Collection to store link data

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
# Add these t classes in your Pydantic Models section

# === PYDANTIC MODELS (Data Schemas) ===

class UserCreate(BaseModel):
    """The data shape required to create a new user."""
    email: EmailStr
    password: str

class Token(BaseModel):
    """The data shape of the token response after logging in."""
    access_token: str
    token_type: str

class LinkCreate(BaseModel):
    original_url: str

class Link(BaseModel):
    """The data shape for a link object."""
    original_url: str
    short_code: str
    clicks: int = 0

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

# Add these two endpoints to your main.py file

@app.post("/links", response_model=Link)
def create_link(link: LinkCreate, current_user: dict = Depends(get_current_user)):
    short_code = "".join(random.choices(string.ascii_letters + string.digits, k=6))
    link_doc = {
        "original_url": link.original_url,
        "short_code": short_code,
        "owner_email": current_user["email"],
        "clicks": 0
    }
    try:
        links_collection.insert_one(link_doc)
        return link_doc
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not create unique short link. Please try again.")
    
    # Add this function right after your create_link function

@app.get("/links", response_model=List[Link])
def get_user_links(current_user: dict = Depends(get_current_user)):
    """
    Retrieves all links created by the currently authenticated user.
    """
    # Find all links where the owner_email matches the current user's email
    links_cursor = links_collection.find(
        {"owner_email": current_user["email"]},
        # Projection: Exclude fields we don't need in the response
        {"_id": 0, "owner_email": 0} 
    )
    return list(links_cursor)

@app.delete("/links/{short_code}", status_code=status.HTTP_204_NO_CONTENT)
def delete_link(short_code: str, current_user: dict = Depends(get_current_user)):
    """
    Deletes a link, but only if the requester is the owner.
    """
    # This is the AUTHORIZATION check. We're verifying the user is allowed to do this.
    link = links_collection.find_one({"short_code": short_code, "owner_email": current_user["email"]})

    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found or you don't have permission to delete it")

    links_collection.delete_one({"short_code": short_code})
    return # A 204 response has no body, so we return nothing.

# Add this inside your FastAPI app

@app.get("/stats/my-links")
def get_my_link_stats(current_user: dict = Depends(get_current_user)):
    # MongoDB Interview Point #3: Aggregation Pipeline
    pipeline = [
        # Stage 1: Match documents for the current user
        {
            "$match": {"owner_email": current_user["email"]}
        },
        # Stage 2: Group them and calculate statistics
        {
            "$group": {
                "_id": None, # Group all matched documents into one
                "total_links": {"$sum": 1},
                "total_clicks": {"$sum": "$clicks"}
            }
        },
        # Stage 3: Clean up the output
        {
            "$project": {
                "_id": 0
            }
        }
    ]
    stats = list(links_collection.aggregate(pipeline))
    if not stats:
        return {"total_links": 0, "total_clicks": 0}
    return stats[0]

@app.get("/stats/my-links")
def get_my_link_stats(current_user: dict = Depends(get_current_user)):
    pipeline = [
        {"$match": {"owner_email": current_user["email"]}},
        {"$group": {
            "_id": None,
            "total_links": {"$sum": 1},
            "total_clicks": {"$sum": "$clicks"}
        }},
        {"$project": {"_id": 0}}
    ]
    stats = list(links_collection.aggregate(pipeline))
    if not stats:
        return {"total_links": 0, "total_clicks": 0}
    return stats[0]