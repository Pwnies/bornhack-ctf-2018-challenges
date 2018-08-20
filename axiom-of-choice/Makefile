# Must be included before using e.g. PORT_EXAMPLE
include ../ports.mk

# Files that should be included in handout.tar.gz
HANDOUT=INTRO.md

# Arguments to docker run
DOCKER_ARGS=-p $(PORT_AXIOM_OF_CHOICE):8081

# Docker image name
DOCKER_NAME=axiom-of-choice

# Files to be included in the Docker image
DOCKER_DEPS=

# Must be included at the bottom
include ../build.mk
