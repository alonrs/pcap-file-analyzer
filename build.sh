#!/bin/bash
dir=$(dirname $(readlink -f $0))
build_dir=$dir/build
mkdir $build_dir 2>/dev/null
cd $build_dir
cmake -S .. -B .
cmake --build . -j

