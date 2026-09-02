FROM python:3.12-slim

# Prevents Python from writing .pyc files and forces unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Forces Rich and Typer to retain ANSI color formatting inside containers
ENV FORCE_COLOR=1

WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/

# Set CLI entrypoint
ENTRYPOINT ["python", "-m", "src.cli"]