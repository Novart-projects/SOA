import uvicorn
import os
import jwt
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.responses import PlainTextResponse
from typing import Dict
import hashlib
from argparse import ArgumentParser
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session



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

active_users: Dict[str, str] = {}

@app.post("/signup")
async def signup(request: Request, response: Response):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    if username in active_users:
        raise HTTPException(status_code=403, detail="Username already in use")
    active_users[username] = hashlib.md5((password).encode()).hexdigest()
    token = jwt.encode({"username": username}, jwt_private(), algorithm="RS256")
    response.set_cookie(key="jwt", value=token, httponly=True)

@app.post("/login")
async def login(request: Request, response: Response):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    if username not in active_users or active_users[username] != hashlib.md5((password).encode()).hexdigest():
        raise HTTPException(status_code=403, detail="Invalid login request")
    token = jwt.encode({"username": username}, jwt_private(), algorithm="RS256")
    response.set_cookie(key="jwt", value=token, httponly=True)


@app.get("/whoami")
async def whoami(request: Request):
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
    if username not in active_users.keys():
        raise HTTPException(status_code=400, detail="Bad username")
    return PlainTextResponse(f'Hello, {username}')

@app.post("update-profile")
async def update_profile(request: Request):
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
    if username not in active_users.keys():
        raise HTTPException(status_code=400, detail="Bad username"
    

if __name__ == "__main__":
    parser = ArgumentParser(description="Auth service")
    parser.add_argument("--private", required=True, help="Path to private key")
    parser.add_argument("--public", required=True, help="Path to public key")
    parser.add_argument("--port", type=int, required=True, help="Port to run the server on")
    args = parser.parse_args()
    path_priv = args.private
    path_pub = args.public
    uvicorn.run(app, host="0.0.0.0", port=args.port)