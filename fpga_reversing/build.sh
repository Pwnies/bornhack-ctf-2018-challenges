#!/bin/sh
yosys -p "synth_ice40 -abc2 -blif challenge.blif" challenge.v
arachne-pnr -d 8k challenge.blif -r -o challenge.asc -p challenge.pcf
icepack challenge.asc challenge.bin
