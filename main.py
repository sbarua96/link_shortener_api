# main.py - CORRECTED AND COMPLETE VERSION

# === IMPORTS: Bringing in the necessary tools ===
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from typing import List
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
import string
import random

# === CONFIGURATION: Your application's settings ===
MONGO_URI = "mongodb+srv://sbarua:batman123@cluster0.wnsbwvu.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
SECRET_KEY = "your-secret-key" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
BASE_URL = "http://127.0.0.1:8000"

# === DATABASE CONNECTION & SETUP ===
client = MongoClient(MONGO_URI)
db = client.link_shortener_db
users_collection = db.users
links_collection = db.links
users_collection.create_index("email", unique=True)
links_collection.create_index("short_code", unique=True) # <-- Important index

# === SECURITY & HASHING SETUP ===
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# === UTILITY FUNCTIONS (Security Helpers) ===
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# === PYDANTIC MODELS (Data Schemas) ===
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class LinkCreate(BaseModel):
    original_url: str

class Link(BaseModel):
    original_url: str
    short_code: str
    clicks: int = 0

# === AUTHENTICATION DEPENDENCY ===
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = users_collection.find_one({"email": email})
    if user is None: raise credentials_exception
    return user

# === FASTAPI APP INSTANCE ===
app = FastAPI(title="Link Shortener API")

# === API ENDPOINTS (The actual API functionality) ===
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    user_in_db = {"email": user.email, "hashed_password": hashed_password}
    try:
        users_collection.insert_one(user_in_db)
        return {"message": "User created successfully"}
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    access_token = create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/links", response_model=Link)
def create_link(link: LinkCreate, current_user: dict = Depends(get_current_user)):
    short_code = "".join(random.choices(string.ascii_letters + string.digits, k=6))
    link_doc = {"original_url": link.original_url, "short_code": short_code, "owner_email": current_user["email"], "clicks": 0}
    try:
        links_collection.insert_one(link_doc)
        return link_doc
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not create unique short link. Please try again.")

@app.get("/links", response_model=List[Link])
def get_user_links(current_user: dict = Depends(get_current_user)):
    links_cursor = links_collection.find({"owner_email": current_user["email"]}, {"_id": 0, "owner_email": 0})
    return list(links_cursor)

@app.delete("/links/{short_code}", status_code=status.HTTP_204_NO_CONTENT)
def delete_link(short_code: str, current_user: dict = Depends(get_current_user)):
    link = links_collection.find_one({"short_code": short_code, "owner_email": current_user["email"]})
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found or you don't have permission to delete it")
    links_collection.delete_one({"short_code": short_code})
    return

# ##############################################################
# ### THIS IS THE MISSING ENDPOINT THAT YOU NEED TO ADD ###
# ##############################################################
@app.get("/{short_code}")
def redirect_to_url(short_code: str):
    link_doc = links_collection.find_one_and_update(
        {"short_code": short_code},
        {"$inc": {"clicks": 1}},
        projection={"original_url": 1, "_id": 0}
    )
    if not link_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Link not found")
    return RedirectResponse(url=link_doc["original_url"])
# ##############################################################

@app.get("/stats/my-links")
def get_my_link_stats(current_user: dict = Depends(get_current_user)):
    pipeline = [
        {"$match": {"owner_email": current_user["email"]}},
        {"$group": {"_id": None, "total_links": {"$sum": 1}, "total_clicks": {"$sum": "$clicks"}}},
        {"$project": {"_id": 0}}
    ]
    stats = list(links_collection.aggregate(pipeline))
    if not stats:
        return {"total_links": 0, "total_clicks": 0}
    return stats[0]