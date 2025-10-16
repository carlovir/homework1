#!/bin/bash
# Test creating multiple processes and killing one

./procman <<EOF
create sleep 30
create sleep 30
list
kill $(pidof sleep | awk '{print $1}') 0
list
wait
quit
EOF
