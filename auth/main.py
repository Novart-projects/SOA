import uvicorn
import os
import jwt
from fastapi import FastAPI, HTTPException, Response, Request, Depends
from fastapi.responses import PlainTextResponse
from typing import Dict
import hashlib
from argparse import ArgumentParser
from sqlalchemy import Column, Integer, String, Date, TIMESTAMP, create_engine
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from pydantic import BaseModel
from datetime import date

DATABASE_URL = "sqlite:///./users.db"


engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    username = Column(String, primary_key=True)
    name = Column(String)
    surname = Column(String)
    password_hash = Column(String, nullable=False)
    phone_number = Column(String)
    birthday = Column(String)
    email = Column(String, index=True)
    create_date = Column(TIMESTAMP)
    update_date = Column(TIMESTAMP)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

path_pub = ""
path_priv = ""

def jwt_private():
    with open(path_priv, 'rb') as file:
        key = file.read()
    return key

def jwt_public():
    with open(path_pub, 'rb') as file:
        key = file.read()
    return key


@app.post("/signup")
async def signup(request: Request, response: Response, db: Session = Depends(get_db)):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    user = db.query(User).filter(User.username == username).first()
    if user:
        raise HTTPException(status_code=403, detail="Username already in use")
    password_hash = hashlib.md5((password).encode()).hexdigest()
    user = User(username=username, email=email, password_hash=password_hash, create_date=date.today(), update_date=date.today())
    db.add(user)
    db.commit()
    token = jwt.encode({"username": username}, jwt_private(), algorithm="RS256")
    response.set_cookie(key="jwt", value=token, httponly=True)

@app.post("/login")
async def login(request: Request, response: Response, db: Session = Depends(get_db)):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    user = db.query(User).filter(User.username == username).first()
    if not user or user.password_hash != hashlib.md5((password).encode()).hexdigest():
        raise HTTPException(status_code=403, detail="Invalid login request")
    token = jwt.encode({"username": username}, jwt_private(), algorithm="RS256")
    response.set_cookie(key="jwt", value=token, httponly=True)


@app.get("/whoami")
async def whoami(request: Request, db: Session = Depends(get_db)):
    cookie_header = request.headers.get("Cookie")
    if not cookie_header:
        raise HTTPException(status_code=401, detail="Cookie is missing")
    jwt_token = cookie_header.split("=")[1]
    decoded = None
    try:
        decoded = jwt.decode(jwt_token, jwt_public(), algorithms=["RS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid cookie")
    username = decoded.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Bad token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Bad username")
    return PlainTextResponse(f'Hello, {username}')

@app.post("/update-profile")
async def update_profile(request: Request, db: Session = Depends(get_db)):
    cookie_header = request.headers.get("Cookie")
    if not cookie_header:
        raise HTTPException(status_code=401, detail="Cookie is missing")
    jwt_token = cookie_header.split("=")[1]
    decoded = None
    try:
        decoded = jwt.decode(jwt_token, jwt_public(), algorithms=["RS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid cookie")
    username = decoded.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Bad token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Bad username")
    data = await request.json()
    user.name = data.get('name')
    user.email = data.get('email')
    user.surname = data.get('surname')
    user.phone_number = data.get('phone-number')
    user.birthday = data.get('birthday')
    user.update_date = date.today()
    db.commit()

@app.get("/get-profile")
async def update_profile(request: Request, db: Session = Depends(get_db)):
    cookie_header = request.headers.get("Cookie")
    if not cookie_header:
        raise HTTPException(status_code=401, detail="Cookie is missing")
    jwt_token = cookie_header.split("=")[1]
    decoded = None
    try:
        decoded = jwt.decode(jwt_token, jwt_public(), algorithms=["RS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid cookie")
    username = decoded.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Bad token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Bad username")
    return user

if __name__ == "__main__":
    parser = ArgumentParser(description="Auth service")
    parser.add_argument("--private", required=True, help="Path to private key")
    parser.add_argument("--public", required=True, help="Path to public key")
    parser.add_argument("--port", type=int, required=True, help="Port to run the server on")
    args = parser.parse_args()
    path_priv = args.private
    path_pub = args.public
    uvicorn.run(app, host="0.0.0.0", port=args.port)