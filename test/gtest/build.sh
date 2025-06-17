#!/bin/bash

ENABLE_WORM=0
AUTO_TEST=0

for arg in "$@"; do
    if [ "$arg" == "-w" ]; then
        ENABLE_WORM=1
    elif [ "$arg" == "-t" ]; then
        AUTO_TEST=1
    fi
done

cmake -DENABLE_WORM=${ENABLE_WORM} -DAUTO_TEST=${AUTO_TEST} .
make