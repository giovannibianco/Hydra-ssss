#!/bin/sh

# exit after the first problem
set -e

./test-shamir 32 5 2
./test-shamir 8 7 3

