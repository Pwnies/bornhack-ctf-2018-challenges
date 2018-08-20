HANDOUT=INTRO.md forensics_0.jpg

forensics_0.jpg: hidden.zip original.jpg
	cp original.jpg forensics_0.jpg
	cat hidden.zip >> forensics_0.jpg

clean:
	rm -f forensics_0.jpg handout.tar.xz

.PHONY: clean

# Must be included at the bottom
include ../build.mk