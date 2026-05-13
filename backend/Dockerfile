FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Гарантируем наличие Pillow отдельной инструкцией, чтобы избежать ситуации,
# когда BuildKit возвращает закешированный слой `pip install`, собранный до
# добавления Pillow в requirements.txt (PIL нужен app.services для нормализации
# изображений в отчётах).
RUN pip install --no-cache-dir Pillow==10.4.0

COPY . /app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
