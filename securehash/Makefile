# Must be included before using e.g. PORT_EXAMPLE
include ../ports.mk

# Files that should be included in handout.tar.gz
HANDOUT=securehash.py Dockerfile run

# Arguments to docker run
DOCKER_ARGS=-p $(PORT_SECUREHASH):1337

# Docker image name
DOCKER_NAME=securehash

# Files to be included in the Docker image
DOCKER_DEPS=securehash.py Dockerfile run

# Must be included at the bottom
include ../build.mk
