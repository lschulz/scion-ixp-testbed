#!/bin/bash
# Start pinpong server in all ASes.

./ixp-testbed.py -w ${1:-./network-gen} exec -d '.*' \
"./bin/pingpong -mode server -sciond /run/shm/sciond/sd{file_fmt}.sock -local {isd_as},[127.0.0.1]:${2:-40002}"
