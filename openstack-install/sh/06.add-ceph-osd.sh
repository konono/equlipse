#!/bin/bash

TAGS=$1

juju model-config disable-network-management=true
MACHINE="$(juju add-machine --constraints tags=${TAGS} 2>&1 >/dev/null |grep -o -E "[0-9]+")"

echo "== add-unit ceph-osd to ${MACHINE} =="
juju add-unit ceph-osd --to ${MACHINE}

