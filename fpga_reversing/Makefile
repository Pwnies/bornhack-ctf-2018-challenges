# Must be included before using e.g. PORT_EXAMPLE
include ../ports.mk

# Files that should be included in handout.tar.gz
HANDOUT=challenge.bin

# Arguments to docker run
DOCKER_ARGS=

# Docker image name
DOCKER_NAME=fpga_reversing

# Files to be included in the Docker image
DOCKER_DEPS=challenge.v challenge.pcf build.sh

# Must be included at the bottom
include ../build.mk

clean:
	rm -rf *.bin *.rpt *.asc a.out *.vcd *.blif handout.tar.xz
