# Must be included before using e.g. PORT_EXAMPLE
include ../ports.mk

# Files that should be included in handout.tar.gz
HANDOUT=INTRO.md level2.py

# Arguments to docker run
DOCKER_ARGS=-p $(PORT_BABYSHELLCODE3_32):1337

# Docker image name
DOCKER_NAME=baby_got_shellcode3_32

# Files to be included in the Docker image
DOCKER_DEPS=run

# Must be included at the bottom
include ../build.mk
