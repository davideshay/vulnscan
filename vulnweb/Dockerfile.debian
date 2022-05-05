FROM python:slim-bullseye

WORKDIR /app

COPY app/requirements.txt /app

RUN set -x \
      && apt-get update \
      && apt-get install -y gcc libpq-dev  \
      && pip install -r requirements.txt \
      && apt-get purge -y --auto-remove gcc

COPY app/ /app/

CMD [ "python", "/app/app.py"]
