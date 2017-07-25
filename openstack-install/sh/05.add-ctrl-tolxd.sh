#!/bin/bash

#!/bin/bash
sed -i "s/^TAG=.*/TAG=$2/g" inventory.sh
TARGETS=$(./inventory.sh --list|jq .sys.hosts[] -r)

MACHINES=$2
APPLIST=$1

for i in $(echo ${MACHINES})
do
  echo "=== $i ==="
  read 
  cat ${APPLIST}| xargs -I% -t juju add-unit % --to lxd:${i} 
done 
