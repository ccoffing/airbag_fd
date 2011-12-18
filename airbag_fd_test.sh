#!/bin/sh

for n in -1 0 1 2 3 4 ; do
    ./airbag_fd_test $n
    echo
    echo
done
