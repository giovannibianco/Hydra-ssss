#!/bin/bash

#export GLITE_SSSS_LOG_LEVEL=DEBUG

# exit after the first problem
set -e

#KEY32=$(./glite-ssss-generate-key 32)
# Need a not hex test. overriding:
KEY32="abcdefghijklmnopqrstuvwxyz#+&/()"
./test-shamir-ascii 5 2  $KEY32

KEY8=$(./glite-ssss-generate-key 8)
./test-shamir-ascii 7 3 $KEY8

echo ""
echo "Testing glite-ssss-split-passwd and glite-ssss-join-passwd"
cmd="./glite-ssss-split-passwd -q 5 2 $KEY32"
echo $cmd
SPLIT32=$($cmd)
cmd="./glite-ssss-join-passwd -q $SPLIT32"
echo $cmd
JOIN32=$($cmd)
echo "Joined shares: $JOIN32"
if [ "$KEY32" != "$JOIN32" ]; then
    echo "Error: split-join failed!"
    exit -1
fi

