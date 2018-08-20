# Must be included before using e.g. PORT_EXAMPLE
include ../ports.mk

# Files that should be included in handout.tar.gz
HANDOUT=vector

# Arguments to docker run
DOCKER_ARGS=

# Docker image name
DOCKER_NAME=vector

# Files to be included in the Docker image
DOCKER_DEPS=main.c sha256.c rc4.c

# Must be included at the bottom
include ../build.mk

clean:
	rm -rf handout.tar.xz vector*
