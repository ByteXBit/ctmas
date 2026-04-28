FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Start the uvicorn API
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
