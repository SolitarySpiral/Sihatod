FROM python:3.14-slim

# Устанавливаем системные зависимости для poetry
RUN pip install --no-cache-dir poetry

WORKDIR /app

# Копируем только файлы зависимостей
COPY pyproject.toml poetry.lock* ./

# Настраиваем poetry так, чтобы он не создавал виртуальное окружение внутри контейнера
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

COPY . .

# Запускаем через uvicorn напрямую, чтобы задействовать несколько воркеров
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5001", "--workers", "2"]