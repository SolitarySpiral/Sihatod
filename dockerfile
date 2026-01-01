FROM python:3.14-slim

# 1. Системные настройки
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

# 2. Установка poetry
RUN pip install --no-cache-dir poetry

WORKDIR /app

# 3. Создание пользователя заранее
# Используем системные флаги --system для минимизации прав
RUN groupadd --system -g 10001 sihatodgroup && \
    useradd --system -u 10001 -g sihatodgroup -s /bin/false -m sihatoduser

# 4. Установка зависимостей (используем кэширование слоев)
COPY pyproject.toml poetry.lock* ./
RUN poetry install --no-root --only main

# 5. Копирование кода
COPY main.py auth.py crypto.py ./

# 6. Права доступа
# Устанавливаем права: только чтение кода для пользователя
RUN chown -R sihatoduser:sihatodgroup /app && \
    chmod -R 550 /app

# 7. Безопасность
USER 10001

# 8. Запуск
# Добавляем --workers, чтобы использовать ресурсы эффективно
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "5001", \
     "--workers", "4", \
     "--ssl-keyfile", "./certs/redis.key", \
     "--ssl-certfile", "./certs/redis.crt"]