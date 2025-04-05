FROM python:3.12-slim

WORKDIR /social-network/posts

COPY main.py .
COPY requirements.txt .
COPY posts.db .
COPY proto/posts.proto .

RUN pip install -r requirements.txt

RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ./posts.proto

ENTRYPOINT ["python", "main.py"]