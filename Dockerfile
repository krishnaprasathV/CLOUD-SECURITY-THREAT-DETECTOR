# Multi-stage lightweight Python Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Initialize demo database
RUN python seed_data.py

# Expose web server port
EXPOSE 5000

# Run Flask application with Gunicorn or standard Python
CMD ["python", "app.py"]
