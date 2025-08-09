FROM python:3.11-alpine

# Install Trivy dependencies and Trivy itself
RUN apk add --no-cache curl wget git && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin


# gitleaks 8.28.0 
RUN wget -O /tmp/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz && \
    cd /tmp && \
    tar -xvzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    chmod +x /usr/local/bin/gitleaks && \
    rm -rf /tmp/gitleaks* 
    
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# Add this line:
ENV PYTHONPATH=/app/src

EXPOSE 8800

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8800"]