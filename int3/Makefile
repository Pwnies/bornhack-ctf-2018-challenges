#int3: main.fixed.s fixup.c
#	gcc -o int3 main.fixed.s fixup.c
#	strip -s int3
#
#int3.unfucked: main.c
#	gcc -o int3.unfucked main.c
#
#main.fixed.s: main.s fixup.py
#	python fixup.py main.s > main.fixed.s
#
#main.s: main.c flag_data.h
#	gcc -S main.c
#
#flag_data.h: flag gen_flag_data.py
#	python gen_flag_data.py flag > flag_data.h

clean:
	rm -rf *.s *.h int3*

# Files that should be included in handout.tar.gz
HANDOUT=int3
DOCKER_ARGS=
DOCKER_NAME=int3
DOCKER_DEPS=flag main.c gen_flag_data.py fixup.py 

# Must be included at the bottom
include ../build.mk

