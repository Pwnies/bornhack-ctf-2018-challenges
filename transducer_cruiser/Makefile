.PHONY: all clean

all: cruiser cruiser.c

# We save the C file so we don't depend on Kleenex being installed
#cruiser.c cruiser:
#	kexc compile --act=false cruiser.kex --srcout cruiser.c --out cruiser

cruiser: cruiser.c
	gcc -O3 -o cruiser -D FLAG_WORDALIGNED cruiser.c

clean:
	@rm -f cruiser


# Files that should be included in handout.tar.gz
HANDOUT=cruiser cruiser.c

# Must be included at the bottom
include ../build.mk

