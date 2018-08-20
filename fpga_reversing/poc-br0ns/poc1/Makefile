# http://www.clifford.at/icestorm/

.PHONY: all clean flag
all: flag

chip.asc: ../../challenge.bin
	iceunpack $< $@

chip.v: chip.asc
	icebox_vlog -ls $< > $@

chip1.v: chip.v
	sed "s/n223 = 0/n223 = 1/" < $< > $@

chip1.blif: chip1.v
	yosys -p "synth_ice40 -blif $@" $<

chip1.asc: chip1.blif
	arachne-pnr -d 8k -p chip.pcf chip1.blif -o chip1.asc

chip2.v: chip1.asc
	icebox_vlog -ls $< > $@

simul: tb.v chip2.v
	iverilog $^ -o $@

bits: simul
	./$< > $@

flag: extract.py bits
	python $<

clean:
	-rm -f chip.asc chip.v chip1.v chip1.blif chip1.asc chip2.v simul bits
