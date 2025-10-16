#!/bin/bash
# Test creating a sleep process and listing it

./procman <<EOF
create sleep 5
list
wait
quit
EOF
