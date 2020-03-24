#!/bin/bash
# Delete path and beacon caches in all ASes.

find -path ${1:-./network-gen}'/*/gen-cache/*.beacon.db*' -delete
find -path ${1:-./network-gen}'/*/gen-cache/*.path.db*' -delete
