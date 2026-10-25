FROM python:3.11-alpine

WORKDIR /app
COPY . /app

# Inappropriate container execution configured as root user
USER root

CMD ["python", "src/app.py"]
