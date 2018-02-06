FROM python:3.6
MAINTAINER Daniel Jones <tortxof@gmail.com>

RUN groupadd -r app && useradd -r -m -g app app

WORKDIR /app
RUN pip install pipenv
COPY . /app/

RUN chown -R app:app /app

USER app

RUN pipenv install

EXPOSE 5000

ENV FLASK_DEBUG=true

CMD ["pipenv", "run", "python", "app.py"]
