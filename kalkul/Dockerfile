FROM debian:testing as builder

RUN apt-get update -y
RUN apt-get install -y python-gmpy2

WORKDIR /build/

COPY template.py .
COPY generate.py .
COPY flag .
COPY doit.py .
COPY test.py .
COPY Makefile .

RUN python generate.py
RUN python doit.py
