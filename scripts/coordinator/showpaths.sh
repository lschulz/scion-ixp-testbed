#!/bin/bash
# Show paths from one AS to others

if [ "$#" -lt "2" ]; then
    echo "Usage: $0 <workdir> <destination> <source>"
    exit 1
fi

./ixp-testbed.py -w $1 exec ${3:-'.*'} \
"./bin/showpaths -srcIA {isd_as} -dstIA $2"
