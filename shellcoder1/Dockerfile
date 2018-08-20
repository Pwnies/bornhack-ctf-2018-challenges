FROM debian

RUN apt-get update -y
RUN apt-get install -y build-essential git socat python-dev python-pip

ENV UNICORN_ARCHS "x86 arm aarch64 mips sparc m68k"
WORKDIR /build
RUN git clone --depth=1 https://github.com/unicorn-engine/unicorn
WORKDIR /build/unicorn
RUN ./make.sh && ./make.sh install
RUN pip install unicorn

ENV USER fib
ENV PORT 1337

RUN useradd $USER
RUN mkdir /home/$USER
WORKDIR /home/$USER

COPY run .
COPY engine.py .
COPY fib.py .
COPY flag .

RUN chmod 555 run fib.py

EXPOSE $PORT
ENTRYPOINT ["./run", "./fib.py"]
