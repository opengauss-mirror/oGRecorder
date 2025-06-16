#!/bin/bash
if [ "$1" == "-w" ]; then
    cmake -DENABLE_WORM=1 .
else
    cmake .
fi
make