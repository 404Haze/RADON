FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY radon/ radon/
COPY gcp_emulator/ gcp_emulator/

RUN pip install --no-cache-dir .

EXPOSE 8000 8080

CMD ["uvicorn", "radon.api:app", "--host", "0.0.0.0", "--port", "8000"]
