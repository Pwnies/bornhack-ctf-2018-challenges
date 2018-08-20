.PHONY: all clean

all: lizards.py

lizards.py: genlizards.py lizards.template.py lizards2.template.py
	python $<
	chmod +x $@

clean:
	-rm -f lizards.py flag

# Files that should be included in handout.tar.gz
HANDOUT=lizards.py

# Must be included at the bottom
include ../build.mk

