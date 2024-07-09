FROM python:3.11

# Определяем переменные среды
ENV DJANGO_SETTINGS_MODULE=hp_testwork.settings
ENV PYTHONDONTWRITEBYTECODE=1
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
