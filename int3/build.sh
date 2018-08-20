#!/bin/sh
python gen_flag_data.py flag > flag_data.h
gcc -S main.c
python fixup.py main.s > main.fixed.s
gcc -o int3 main.fixed.s fixup.c
strip -s int3
