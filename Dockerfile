FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and GUI
COPY . .

EXPOSE 5050

ENV PORT=5050
ENV PYTHONUNBUFFERED=1

CMD ["python", "app.py"]
