FROM python:3.7.4

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements.txt /usr/src/app/

RUN pip install -r requirements.txt

ENV MONGO_INITDB_ROOT_USERNAME=root
ENV MONGO_INITDB_ROOT_PASSWORD=password

COPY . /usr/src/app

CMD ["gunicorn", "-k", "gevent", "app:app"]