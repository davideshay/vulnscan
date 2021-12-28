FROM python:slim-bullseye

WORKDIR /app

COPY app/requirements.txt /app

RUN apt-get update && \
    apt-get install -y curl

RUN pip install -r requirements.txt

RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY app/* /app

CMD [ "python3", "/app/vulngen.py"]
