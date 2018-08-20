all: doit

%: %.c
	gcc -O9 -lz -lm $< -o $@

.PHONY: run clean
run: doit
	./doit ../flag.png.enc

clean:
	-rm -f doit flag.png
