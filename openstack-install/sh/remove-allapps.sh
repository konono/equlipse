#!/bin/bash


APPLIST=$(juju status |grep App -A 100 |grep -n "^$"|head -n1 |awk -F':' '{print ($1 - 2 )}'|xargs -I% sh -c "juju status|grep App -A %|tail -n%" |awk '{print $1}')

for i in $APPLIST
do
  echo "== remove ${i} application == "
  juju remove-application ${i}
done
