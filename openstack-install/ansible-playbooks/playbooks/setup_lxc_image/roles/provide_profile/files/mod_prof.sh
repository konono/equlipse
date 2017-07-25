cat <<EOF | lxc profile edit default
name: default
config:
description: Default LXD profile
devices:
  eth0:
    name: eth0
    nictype: bridged
    parent: br-ens2f0
    type: nic
  eth1:
    name: eth1
    nictype: bridged
    parent: br-ens3
    type: nic
EOF
