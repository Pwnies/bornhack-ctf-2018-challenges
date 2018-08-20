FROM debian:testing

RUN apt-get update -y
RUN apt-get install python -y
RUN apt-get install python-numpy -y

COPY generate.py .
COPY flag .

RUN python ./generate.py > flagcheck.py
