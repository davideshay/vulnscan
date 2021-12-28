FROM python:slim-bullseye

WORKDIR /app

COPY app/requirements.txt /app

RUN pip install -r requirements.txt

COPY app/* /app

CMD [ "python3", "/app/podreader.py"]
