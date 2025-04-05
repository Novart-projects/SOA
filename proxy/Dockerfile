FROM python:3.12-slim

WORKDIR /social-network/proxy


COPY main.py .
COPY requirements.txt .
COPY proto/posts.proto .


RUN pip install -r requirements.txt

RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ./posts.proto


ENTRYPOINT ["python", "main.py"]