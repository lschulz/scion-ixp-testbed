#!/bin/bash
# Terminate pinpong server in all ASes.

./ixp-testbed.py -w ${1:-./network-gen} exec '.*' "pkill pingpong"
