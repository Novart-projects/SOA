FROM python:3.12-slim

WORKDIR /social-network/auth

COPY main.py .
COPY requirements.txt .
COPY users.db .

RUN pip install -r requirements.txt



ENTRYPOINT ["python", "main.py"]