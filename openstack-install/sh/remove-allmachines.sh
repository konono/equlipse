#!/bin/bash

#remove machines
juju machines|grep started |awk '{print $1}'|xargs -I% juju remove-machine % --force
