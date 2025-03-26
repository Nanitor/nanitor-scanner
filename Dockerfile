# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Install nmap and other required system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the scanner code
COPY nanscan.py .

# Set the entrypoint and default command
ENTRYPOINT ["python", "nanscan.py"]
CMD ["--help"]
