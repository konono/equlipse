#!/bin/bash

APPLIST=$1
MACHINES=$2

for i in $(echo ${MACHINES})
do
  echo "=== $i ==="
  read 
  cat ${APPLIST}| xargs -I% -t juju add-unit % --to lxd:${i} 
done 
