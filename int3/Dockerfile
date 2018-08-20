FROM debian:stretch
RUN apt-get update -y && apt-get install -y build-essential python

COPY . .
RUN sh build.sh
