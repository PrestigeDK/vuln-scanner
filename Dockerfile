FROM python:3.12-slim

# Prevents Python from writing .pyc files and forces unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Forces Rich and Typer to retain ANSI color formatting inside containers
ENV FORCE_COLOR=1

WORKDIR /app

# Copy dependencies and project setup
COPY requirements.txt pyproject.toml ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and README
COPY src/ ./src/
COPY README.md ./

# Install the package locally to expose the "vulnscanner" command
RUN pip install --no-cache-dir -e .

# Set CLI entrypoint to the newly created command
ENTRYPOINT ["vulnscanner"]