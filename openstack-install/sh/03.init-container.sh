#!/bin/bash
sed -i "s/^TAG=.*/TAG=$1/g" inventory.sh

sudo pip install ansible

ANSIBLE_DIR=../ansible-playbooks/playbooks/setup_lxc_image
MACHINE_IPS=$(./inventory.sh --list|jq -r '.sys.hosts[]'|awk -v ORS='' 'NR==1 { print "("$1} NR!=1 { print "|"$1 } END{print ")"}')
MACHINES=$(juju status |grep -E "${MACHINE_IPS}"| awk '{print $1}')
echo "Add Lxd Network configutation"

## Xenial の場合は 00.~ で python 2.7をインストールした後、interpreter の指定が必要
ansible-playbook -i inventory.sh  -e ansible_python_interpreter=/usr/bin/python2.7 $ANSIBLE_DIR/step1.yml

juju model-config apt-mirror=http://10.0.10.10/ubuntu

echo "containue container deploy?"
echo "y or n"
read input

if [ "$input" = "y" ]; then
  for i in ${MACHINES}
  do
    juju add-machine lxd:${i}
  done
else
  echo "...canceled"
fi
