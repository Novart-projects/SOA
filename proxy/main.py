from fastapi import FastAPI, HTTPException, Request, Response, Depends
from argparse import ArgumentParser
import httpx
import os
import uvicorn
import grpc
import posts_pb2
import posts_pb2_grpc
import jwt

app = FastAPI()

auth_service_url = ""
post_service_url = ""

grpc_channel = None
grpc_client = None

def jwt_private():
    path = os.environ.get('JWT_PRIVATE_KEY_FILE', 'secret')
    with open(path, 'rb') as file:
        key = file.read()
    return key


def jwt_public():
    path = os.environ.get('JWT_PUBLIC_KEY_FILE', 'secret')
    with open(path, 'rb') as file:
        key = file.read()
    return key

# @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
# async def proxy_request(request: Request, path: str):
#     async with httpx.AsyncClient() as client:
#         url = ""
#         if path in ["signup", "login", "whoami", "update-profile", "get-profile"]:
#             url = f"{auth_service_url}/{path}"
#             method = request.method
#             headers = dict(request.headers)
#             headers.pop('host', None)
        
#             response = await client.request(
#                 method=method,
#                 url=url,
#                 headers=headers,
#                 content=await request.body()
#             )

#             return Response(
#                 content=response.content,
#                 status_code=response.status_code,
#                 headers=dict(response.headers),
#                 media_type=response.headers.get('content-type')
#             )
#         else:
#             return Response(status_code=404, content=f"Service not found. {path}")

@app.post("/signup")
async def signup(request: Request):
    async with httpx.AsyncClient() as client:
        url = ""
        url = f"{auth_service_url}/signup"
        method = request.method
        headers = dict(request.headers)
        headers.pop('host', None)
    
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=await request.body()
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get('content-type')
        )

@app.post("/login")
async def signup(request: Request):
    async with httpx.AsyncClient() as client:
        url = ""
        url = f"{auth_service_url}/login"
        method = request.method
        headers = dict(request.headers)
        headers.pop('host', None)
    
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=await request.body()
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get('content-type')
        )

@app.post("/update-profile")
async def signup(request: Request):
    async with httpx.AsyncClient() as client:
        url = ""
        url = f"{auth_service_url}/update-profile"
        method = request.method
        headers = dict(request.headers)
        headers.pop('host', None)
    
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=await request.body()
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get('content-type')
        )

@app.get("/get-profile")
async def signup(request: Request):
    async with httpx.AsyncClient() as client:
        url = ""
        url = f"{auth_service_url}/get-profile"
        method = request.method
        headers = dict(request.headers)
        headers.pop('host', None)
    
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=await request.body()
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get('content-type')
        )
    
@app.get("/whoami")
async def signup(request: Request):
    async with httpx.AsyncClient() as client:
        url = ""
        url = f"{auth_service_url}/whoami"
        method = request.method
        headers = dict(request.headers)
        headers.pop('host', None)
    
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=await request.body()
        )

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get('content-type')
        )

def get_current_user(request: Request):
    cookie_header = request.headers.get("Cookie")
    if not cookie_header:
        raise HTTPException(status_code=401, detail="Cookie is missing")
    jwt_token = cookie_header.split("=")[1]
    try:
        decoded = jwt.decode(jwt_token, jwt_public(), algorithms=["RS256"])
        return decoded.get("username")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid cookie")
    
@app.post("/posts")
async def create_post(request: Request, username: str = Depends(get_current_user)):
    data = await request.json()
    post_request = posts_pb2.CreatePostRequest(post=posts_pb2.Post(
        title=data.get('title'),
        creator_id=username,
        description=data.get('description'),
        is_private=data.get('is_private'),
        tags=data.get('tags', [])
    ))
    response = grpc_client.CreatePost(post_request)
    return response.post

@app.delete("/posts/{post_id}")
async def delete_post(post_id: str, username: str = Depends(get_current_user)):
    response = grpc_client.DeletePost(posts_pb2.DeletePostRequest(post_id=post_id))
    if response.post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"detail": "Post deleted"}

@app.put("/posts/{post_id}")
async def update_post(post_id: str, request: Request, username: str = Depends(get_current_user)):
    data = await request.json()
    post_request = posts_pb2.UpdatePostRequest(post=posts_pb2.Post(
        id=post_id,
        title=data.get('title'),
        description=data.get('description'),
        is_private=data.get('is_private'),
        tags=data.get('tags', [])),  
        creator_id=username)
    response = grpc_client.UpdatePost(post_request)
    if not response.post:
        raise HTTPException(status_code=404, detail="Post not found")
    return response.post

@app.get("/posts/{post_id}")
async def get_post(post_id: str, username: str = Depends(get_current_user)):
    response = grpc_client.GetPostById(posts_pb2.GetPostRequest(post_id=post_id, creator_id=username))
    if not response.post:
        raise HTTPException(status_code=404, detail="Post not found")
    return response.post

@app.get("/posts/")
async def list_posts(page: int = 0, page_size: int = 10, username: str = Depends(get_current_user)):
    response = grpc_client.ListPosts(posts_pb2.ListPostsRequest(page=page, page_size=page_size, creator_id=username))
    return {"posts": response.posts, "total_count": response.total_count}


if __name__ == "__main__":
    parser = ArgumentParser(description="Proxy service")
    parser.add_argument("--port", type=int, required=True, help="Port to run the server on")
    args = parser.parse_args()
    auth_service_url = os.environ.get('AUTH_SERVER_URL', 'http://127.0.0.1:8090')
    post_service_url = os.environ.get('POST_SERVER_URL', 'http://127.0.0.1:8092')
    grpc_channel = grpc.insecure_channel(post_service_url)
    grpc_client = posts_pb2_grpc.PostsServiceStub(grpc_channel)
    uvicorn.run(app, host="0.0.0.0", port=args.port)