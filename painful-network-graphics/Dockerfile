FROM debian:stretch

RUN apt-get update -y && apt-get install -y python python-pip build-essential

WORKDIR /build
COPY . .

RUN pip install -r requirements.txt

RUN ./build.sh
