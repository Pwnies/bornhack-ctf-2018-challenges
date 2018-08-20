#!/bin/bash

cd "$(dirname "$(realpath "$0")")"

if [ $# -ne 1 ] ; then
   echo 'usage: $0 <num>' >&2
   exit 1
fi

# `$CORES * ceil($NUM / $CORES)` instances (aka too many) are generated because
# math is hard
#
# On the other hand some instances are overwritten (aka too few are left) due to
# a race condition because parellalism is hard
#
# I guess it kind of evens out in the end, and I don't have to wrap my head
# around anything hard, \o/!

NUM=$1
CORES=`nproc`
NUM_PER_CORE=$((($NUM + $CORES - 1) / $CORES))

for i in `seq $CORES` ; do
    echo GENERATE $i
    ./gen.py ../app/challenges $NUM_PER_CORE &
done

while [ -n "`jobs -r`" ] ; do
    echo DRAW
    ./draw.py ../app/challenges ../app/static 4 &
    sleep 5
done
