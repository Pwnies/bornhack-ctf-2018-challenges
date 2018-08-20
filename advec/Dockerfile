FROM debian:stretch

RUN apt-get update -qy
RUN apt-get install -qy build-essential python-pip
RUN pip install pyelftools

COPY fixup.py .
COPY main.c . 
COPY sha256.c .
COPY rc4.c .

RUN gcc -o vector.unfixed main.c
RUN cp vector.unfixed vector && python fixup.py vector
RUN strip -s vector
