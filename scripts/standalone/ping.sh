#!/bin/bash
# Ping an AS from another one.

if [ "$#" -lt "2" ]; then
    echo "Usage: $0 <workdir> <destination> <source>"
    exit 1
fi

./ixp-testbed.py -w $1 exec ${3:-'.*'} "./bin/scmp echo -remote $2,[127.0.0.1] -c 4"
