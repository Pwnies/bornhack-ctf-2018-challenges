# Build image
FROM debian:stretch as builder

RUN apt-get update -y
RUN apt-get install -y gcc

WORKDIR /
COPY knaek_mig.c .
RUN gcc knaek_mig.c -o knaek_mig
