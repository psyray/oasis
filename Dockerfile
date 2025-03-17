# Use a slim and specific Debian base image to minimize attack surface
FROM debian:12.9-slim

# Set non-root user for better security
RUN useradd -ms /bin/bash appuser

# Installs (requires root privileges)
RUN apt-get update && \
    apt-get install -y git curl python3 python3-pip python3-venv && \
    apt-get clean

# Set the working directory for the application
WORKDIR /app

# Define build arguments for flexibility during image creation
ARG GIT_REPO
ARG MODEL_NB

# Copy application files into the container
COPY . /app

# Create and secure a volume for reports
VOLUME /reports

# Install pip and pipx
RUN pip install pipx --break-system-packages && \
    pipx ensurepath

# Install application dependencies with pipx to isolate them
RUN pipx install --editable .

# Download Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Pull required models
RUN ollama pull mistral && ollama pull nomic-embed-text

# Clone the repository 
RUN git clone $GIT_REPO repo && \
    oasis /app/repo | echo ${MODEL_NB}

# Move security reports to the designated volume for access
RUN mv /app/security_reports/ /app/reports/

# Switch to the non-root user for improved security during runtime
USER appuser
