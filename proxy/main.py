from fastapi import FastAPI, HTTPException, Request, Response
from argparse import ArgumentParser
import httpx
import os
import uvicorn

app = FastAPI()

auth_service_url = ""

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request, path: str):
    async with httpx.AsyncClient() as client:
        url = ""
        if path in ["signup", "login", "whoami", "update-profile", "get-profile"]:
            url = f"{auth_service_url}/{path}"
        else:
            return Response(status_code=404, content=f"Service not found. {path}")
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

if __name__ == "__main__":
    parser = ArgumentParser(description="Proxy service")
    parser.add_argument("--port", type=int, required=True, help="Port to run the server on")
    args = parser.parse_args()
    auth_service_url = os.environ.get('AUTH_SERVER_URL', 'http://127.0.0.1:8090')
    uvicorn.run(app, host="0.0.0.0", port=args.port)