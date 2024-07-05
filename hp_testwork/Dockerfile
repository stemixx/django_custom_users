FROM python:3.11

# Определяем переменные среды
ENV DJANGO_SETTINGS_MODULE=myproject.settings
ENV PYTHONUNBUFFERED=1

# рабочая директория внутри проекта
WORKDIR /usr/src/app

# Устанавливаем зависимости из файла requirements.txt
COPY requirements.txt .

# Копируем все файлы проекта в Docker-контейнер
COPY . .

# Обновляем pip и устанавливаем зависимости
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Прослушиваем порт 8000
EXPOSE 8000

# Запускаем команду для работы приложения
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
