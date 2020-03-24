#!/bin/bash
# Ping an AS from another one.

if [ "$#" -lt "2" ]; then
    echo "Usage: $0 <workdir> <destination> <source> <port>"
    exit 1
fi

./ixp-testbed.py -w $1 exec ${3:-'.*'} \
"./bin/pingpong -sciond /run/shm/sciond/sd{file_fmt}.sock -local {isd_as},[127.0.0.1]:0 \
-remote $2,[127.0.0.1]:${4:-40002} -count 4"
