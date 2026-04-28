FROM python:3.9-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy both backend and ml modules
COPY backend/ ./backend/
COPY ml/ ./ml/

# The CMD assumes we run from root where backend is a module
# We should change WORKDIR to /app and run uvicorn with module path
WORKDIR /app/backend
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
