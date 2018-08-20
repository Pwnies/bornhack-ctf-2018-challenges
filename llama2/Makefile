include ../ports.mk

HANDOUT=llama2.py
DOCKER_ARGS=
DOCKER_NAME=
DOCKER_DEPS=

llama2.py: flag generate.py
	python generate.py > llama2.py

clean:
	rm -rf llama2.py

include ../build.mk

.PHONY: clean
