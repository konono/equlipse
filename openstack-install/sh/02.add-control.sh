#!/bin/bash

TAGS=$1

juju model-config disable-network-management=false
juju add-machine --constraints tags=${TAGS} 


