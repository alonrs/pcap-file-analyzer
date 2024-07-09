#!/bin/bash

mkdir build 2>/dev/null
cd build
cmake -S .. -B .
cmake --build . -j

