#!/bin/bash
sed -i "s/^TAG=.*/TAG=$1/g" inventory.sh

ANSIBLE_DIR=../ansible-playbooks/playbooks/setup_lxc_image

echo "Provide Lxc Container image"
ansible-playbook -i inventory.sh $ANSIBLE_DIR/step2.yml
