#/bin/bash

SV=$1
TAG=$2

maas maas tag update-nodes ${TAG} add=$(maas maas nodes read hostname=${SV}|jq -r ".[].system_id") 
