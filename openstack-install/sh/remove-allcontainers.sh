#!/bin/bash

#remove machines
juju machines|grep started |grep lxd |awk '{print $1}'|xargs -I% -t juju remove-machine % --force
