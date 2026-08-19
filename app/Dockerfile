# Small, official Python base image - slim cuts unnecessary OS packages
# to keep the image size (and attack surface) down.
FROM python:3.12-slim

WORKDIR /app

# Copy just the dependency list first and install before copying the rest
# of the code. Docker caches each instruction as a layer - this way, if you
# only change app.py later, Docker reuses the cached "pip install" layer
# instead of redownloading every dependency on every rebuild.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]