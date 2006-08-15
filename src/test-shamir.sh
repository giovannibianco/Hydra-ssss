#!/bin/bash

#export GLITE_SSSS_LOG_LEVEL=DEBUG

# exit after the first problem
set -e

KEY32=$(./glite-ssss-generate-key 32)
./test-shamir 5 2 $KEY32

KEY8=$(./glite-ssss-generate-key 8)
./test-shamir 7 3 $KEY8

