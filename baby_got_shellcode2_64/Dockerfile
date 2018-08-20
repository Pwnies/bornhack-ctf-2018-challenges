FROM debian:stretch
RUN apt-get update && apt-get install -y python socat

ENV USER baby
ENV PORT 1337

RUN useradd $USER
RUN mkdir /home/$USER
WORKDIR /home/$USER

COPY run .
COPY flag .
COPY level1.py .
RUN chmod 555 run

EXPOSE $PORT

CMD ["./run", "python -u level1.py"]
