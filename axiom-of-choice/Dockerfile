FROM debian:stretch

RUN apt-get update && apt-get -y install \
    python2.7                            \
    python-flask                         \
    python-pil                           \
    gunicorn

RUN useradd -m aoc
WORKDIR /home/aoc

COPY app/ ./
COPY flag ./
ADD static.tgz ./
ADD challenges.tgz ./

USER aoc

CMD ["./run.sh"]
