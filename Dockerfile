FROM python:3.10-slim
ARG CLAMD_HOST
ARG CLAMD_PORT
ARG DATABASE_URI
ENV CLAMD_HOST=${CLAMD_HOST}
ENV CLAMD_PORT=${CLAMD_PORT}
ENV DATABASE_URI=${DATABASE_URI}

RUN apt-get update && apt-get install -y curl libpq-dev gcc python3-dev libmagic1 file p7zip-full unrar-free

WORKDIR /app


COPY main.py /app/main.py

RUN pip3 install requests pytz fastapi flask pyclamd werkzeug patool python-magic flask_sqlalchemy psycopg2-binary prometheus_client py7zr rarfile
SHELL ["/bin/bash", "-c"]

# timezone
#ENV TZ="" 

#RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
#    echo $TZ > /etc/timezone

CMD ["python3", "/app/main.py"]
