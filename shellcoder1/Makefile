# Must be included before using e.g. PORT_EXAMPLE
include ../ports.mk

# Files that should be included in handout.tar.gz
HANDOUT=engine.py fib.py Dockerfile run

# Arguments to docker run
DOCKER_ARGS=-p $(PORT_SHELLCODER1):1337

# Docker image name
DOCKER_NAME=shellcoder1

# Files to be included in the Docker image
DOCKER_DEPS=

# Must be included at the bottom
include ../build.mk
