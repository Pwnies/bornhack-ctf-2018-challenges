HANDOUT=INTRO.md stego_0.bmp

stego_0.bmp: flag original.bmp
	cp original.bmp stego_0.bmp
	cat flag | base64 >> stego_0.bmp

clean:
	rm -f stego_0.bmp handout.tar.xz

.PHONY: clean

# Must be included at the bottom
include ../build.mk