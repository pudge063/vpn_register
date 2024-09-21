FROM python:3.10-slim

# Установка необходимых пакетов
RUN apt-get update && \
    apt-get install -y strongswan && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Копируем приложение
COPY . /app
WORKDIR /app

# Установка зависимостей
RUN pip install -r requirements.txt

# Запуск приложения
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
