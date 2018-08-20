FROM debian

RUN apt-get update -y
RUN apt-get install -y python socat

ENV USER fib
ENV PORT 1337

RUN useradd $USER
RUN mkdir /home/$USER
WORKDIR /home/$USER

COPY run .
COPY securehash.py .
COPY flag .

RUN chmod 555 run securehash.py

EXPOSE $PORT
ENTRYPOINT ["./run", "./securehash.py"]
