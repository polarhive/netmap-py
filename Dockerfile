# Use an official Python image with Debian base (which includes libstdc++)
FROM python:3.12-slim

# Set environment variables for Python
ENV PYTHONUNBUFFERED=1

# Install system dependencies
# The build-essential package will install the required GCC libraries if needed.
RUN apt-get update && apt-get install -y \
    gcc \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements if you have a requirements.txt, or list dependencies here.
# For example, if you have these dependencies:
# Flask and matplotlib, you can create a requirements.txt with:
#     flask
#     matplotlib
# Otherwise, install them directly.
COPY requirements.txt .

RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the rest of your application code
COPY . .

# Expose the port used by Flask
EXPOSE 5000

# Command to run the application.
CMD ["python", "scanner.py"]

