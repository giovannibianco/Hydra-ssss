#!/bin/bash

#export GLITE_SSSS_LOG_LEVEL=DEBUG

# exit after the first problem
set -e

KEY32=$(./glite-ssss-generate-key 32)
./test-shamir 5 2 $KEY32

KEY8=$(./glite-ssss-generate-key 8)
./test-shamir 7 3 $KEY8

echo ""
echo "Testing glite-ssss-split-key and glite-ssss-join-key"
cmd="./glite-ssss-split-key -q 5 2 $KEY32"
echo $cmd
SPLIT32=$($cmd)
cmd="./glite-ssss-join-key -q $SPLIT32"
echo $cmd
JOIN32=$($cmd)
echo "Joined shares: $JOIN32"
if [ "$KEY32" != "$JOIN32" ]; then
    echo "Error: split-join failed!"
    exit -1
fi

