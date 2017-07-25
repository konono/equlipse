vMX getting started
---

### Requirements

- ubuntu 16.04.2がインストールされていること
  - Ubuntu 16.04.2 serverをインストール
  - memoryが最低8GBあること
  - 17.1R2.7までは検証済み

### 1. Download vMX image for KVM

Download Home dir
```
tar zxvf vmx-bundle-17.xRx.x.tgz

```

### 2. Copy scripts and Execute

```
cp -p ./vmx-install/pre_install.sh  $HOME/vmx-xx.xRx.x/
cp -p ./vmx-install/vmx_preinstall_checks.patch  $HOME/vmx-xx.xRx.x/
sudo chown -R youruser. $HOME/vmx-xx.xRx.x/
cd $HOME/vmx-xx.xRx.x
chmod +x ./pre_install.sh
./pre_install.sh
```

### 3. Configure vMX 

cat config/vmx.conf 
```
##############################################################
#
#  vmx.conf
#  Config file for vmx on the hypervisor.
#  Uses YAML syntax. 
#  Leave a space after ":" to specify the parameter value.
#
##############################################################
--- 
#Configuration on the host side - management interface, VM images etc.
HOST:
    identifier                : vmx1   # Maximum 6 characters
    host-management-interface : eno1   # Management interface
    routing-engine-image      : "/home/ubuntu/vmx/vmx-17.1R1.8/images/junos-vmx-x86-64-17.1R1.8.qcow2"
    routing-engine-hdd        : "/home/ubuntu/vmx/vmx-17.1R1.8/images/vmxhdd.img"
    forwarding-engine-image   : "/home/ubuntu/vmx/vmx-17.1R1.8/images/vFPC-20170216.img"
---
#External bridge configuration
BRIDGES:
    - type  : external
      name  : br-ext                  # Max 10 characters
--- 
#vRE VM parameters
CONTROL_PLANE:
    vcpus       : 1
    memory-mb   : 1024 
    console_port: 8601
    interfaces  :
      - type      : static
        ipaddr    : 10.102.144.94
        macaddr   : "0A:00:DD:C0:DE:0E"
--- 
#vPFE VM parameters
FORWARDING_PLANE:
    memory-mb   : 6144 
    vcpus       : 3
    console_port: 8602
    device-type : virtio 
    interfaces  :
      - type      : static
        ipaddr    : 10.102.144.98
        macaddr   : "0A:00:DD:C0:DE:10"
--- 
#Interfaces
JUNOS_DEVICES:
   - interface            : ge-0/0/0
     mac-address          : "02:06:0A:0E:FF:F0"
     description          : "ge-0/0/0 interface"

   - interface            : ge-0/0/1
     mac-address          : "02:06:0A:0E:FF:F1"
     description          : "ge-0/0/1 interface"

   - interface            : ge-0/0/2
     mac-address          : "02:06:0A:0E:FF:F2"
     description          : "ge-0/0/2 interface"

   - interface            : ge-0/0/3
     mac-address          : "02:06:0A:0E:FF:F3"
     description          : "ge-0/0/0 interface"
```

### 4. vMX bootstrap

```
sudo ./vmx.sh --install -lv
./vmx.sh: 460: [: ubuntu: unexpected operator
==================================================
    Welcome to VMX
==================================================
Date..............................................03/12/17 11:51:39
VMX Identifier....................................vmx1
Config file......................................./home/ubuntu/vmx/vmx-17.1R1.8/config/vmx.conf
Build Directory.................................../home/ubuntu/vmx/vmx-17.1R1.8/build/vmx1
Assuming kvm hypervisor...........................
Virtualization type...............................kvm
Junos Device type.................................virtio
Environment file................................../home/ubuntu/vmx/vmx-17.1R1.8/env/ubuntu_virtio.env
Junos Device Type.................................virtio
Initialize scripts................................[OK]
[OK]
[OK]
==================================================
    VMX Environment Setup Completed
==================================================
==================================================
    VMX Install & Start
==================================================
Linux distribution................................ubuntu
Check GRUB........................................[Disabled]
Installation status of qemu-kvm...................[OK]
Installation status of libvirt-bin................[OK]
Installation status of bridge-utils...............[OK]
Installation status of python.....................[OK]
Installation status of libyaml-dev................[OK]
Installation status of python-yaml................[OK]
Installation status of numactl....................[OK]
Installation status of libnuma-dev................[OK]
Installation status of libparted0-dev.............[OK]
Installation status of libpciaccess-dev...........[OK]
Installation status of libyajl-dev................[OK]
Installation status of libxml2-dev................[OK]
Installation status of libglib2.0-dev.............[OK]
Installation status of libnl-dev..................[OK]
Check Kernel Version..............................[Disabled]
Check Qemu Version................................[Disabled]
Check libvirt Version.............................[Disabled]
Check virsh connectivity..........................[OK]
IXGBE Enabled.....................................[Disabled]
./vmx.sh: 396: [: -eq: unexpected operator
Check I40E drivers................................[OK]
==================================================
    Pre-Install Checks Completed
==================================================
Check RE state....................................[Not Running]
[OK]
Check for VM vfp-vmx1.............................[Not Running]
[OK]
Check if bridge br-mgmt exists....................[No]
Cleanup VM bridge br-mgmt.........................[OK]
Cleanup VM bridge br-int-vmx1.....................[OK]
Cleanup VM bridge br-fab-vmx1.....................[OK]
==================================================
    VMX Stop Completed
==================================================
Check VCP image...................................[OK]
Check VFP image...................................[OK]
Check VCP Config image............................[OK]
Check management interface........................[OK]
Setup huge pages to 16384.........................[OK]
Attempt to kill libvirtd..........................[OK]
Attempt to start libvirt-bin......................[OK]
Sleep 2 secs......................................[OK]
Check libvirt support for hugepages...............[OK]
==================================================
    System Setup Completed
==================================================
Get Management Address of eno1....................[OK]
Generate libvirt files............................[OK]
Sleep 2 secs......................................[OK]
Find configured management interface..............eno1
Find existing management gateway..................eno1
Check if eno1 is already enslaved to br-mgmt......[No]
Gateway interface needs change....................[Yes]
Create br-mgmt....................................[OK]
Get Management Gateway............................10.0.11.254
Flush eno1........................................[OK]
Start br-mgmt.....................................[OK]
Bind eno1 to br-mgmt..............................[OK]
Get Management MAC................................00:26:b9:66:b4:9a
Assign Management MAC 00:26:b9:66:b4:9a...........[OK]
Add default gw 10.0.11.254........................[OK]
Create br-int-vmx1................................[OK]
Start br-int-vmx1.................................[OK]
[OK]
Define vcp-vmx1...................................[OK]
Start vcp-vmx1....................................[OK]
Define vfp-vmx1...................................[OK]
Wait 2 secs.......................................[OK]
Start vfp-vmx1....................................[OK]
Wait 2 secs.......................................[OK]
==================================================
    VMX Bringup Completed
==================================================
Check if br-mgmt is created.......................[Created]
Check if br-int-vmx1 is created...................[Created]
Check if VM vcp-vmx1 is running...................[Running]
Check if VM vfp-vmx1 is running...................[Running]
Check if tap interface vcp-ext-vmx1 exists........[OK]
Check if tap interface vcp-int-vmx1 exists........[OK]
Check if tap interface vfp-ext-vmx1 exists........[OK]
Check if tap interface vfp-int-vmx1 exists........[OK]
==================================================
    VMX Status Verification Completed.
==================================================
Log file..........................................
    /home/ubuntu/vmx/vmx-17.1R1.8/build/vmx1/logs/vmx_1489333899.log
==================================================
    Thank you for using VMX
==================================================
```

### 5. vMX initial configuration

```
sudo ./vmx.sh --console vcp vmx1
root
cli
set version 16.2R1.6
set system root-authentication encrypted-password "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
set system services ssh
set system services netconf ssh                                   #Contrail use netconf/ssh access
set system syslog user * any emergency
set system syslog file messages any notice
set system syslog file messages authorization info
set system syslog file interactive-commands interactive-commands any
set chassis network-services enhanced-ip
set chassis fpc 0 pic 0 tunnel-services
set interfaces ge-0/0/0 unit 0 family inet address 10.0.11.201/23 #Contrail use netconf access to this ip.
set routing-options static route 0.0.0.0/0 next-hop 10.0.11.254

root> request system license add terminal
[Type ^D at a new line to end input,
 enter blank line between each license key]
 [Your license]
^@
XXXXXXX: successfully added
add license complete (no errors)

root> show system license
License usage:
                                 Licenses     Licenses    Licenses    Expiry
  Feature name                       used    installed      needed
  scale-subscriber                      0           10           0    permanent
  scale-l2tp                            0         1000           0    permanent
  scale-mobile-ip                       0         1000           0    permanent
  VMX-BANDWIDTH                        50           50           0    59 days
  VMX-SCALE                             3            3           0    59 days
  vmx-subscriber-accounting             0            1           0    60 days
  vmx-subscriber-authentication         0            1           0    60 days
  vmx-subscriber-address-assignment        0         1           0    60 days
  vmx-service-dc                        0            1           0    60 days
  vmx-service-accounting                0            1           0    60 days
  vmx-subscriber-secure-policy          0            1           0    60 days
  vmx-pcrf-subscriber-provisioning        0          1           0    60 days
  vmx-ocs-charging                      0            1           0    60 days
  vmx-nasreq-auth-authorization         0            1           0    60 days
  vmx-service-qos                       0            1           0    60 days
  vmx-service-ancp                      0            1           0    60 days
  vmx-service-cbsp                      0            1           0    60 days

Licenses installed:
  License identifier: E421992502
  License version: 4
  Software Serial Number: 20151020
  Customer ID: vMX-JuniperEval
  Features:
    vmx-bandwidth-50m - vmx-bandwidth-50m
      count-down, Original validity: 60 days
    vmx-feature-premium - vmx-feature-premium
      count-down, Original validity: 60 days

root> show chassis network-services
Network Services Mode: Enhanced-IP

root> show chassis network-services
```

### 6 Configure interface

![nw_configuration](https://raw.githubusercontent.com/konono/equilipse/images/nw_configuration_v2.PNG 'nw_configuration')
![vmx_host_interface_configration](https://raw.githubusercontent.com/konono/equilipse/images/vmx_host_interface_configuration_v2.PNG 'vmx_host_interface_configration')

```
cat vmx-junosdev.conf 
##############################################################
#
#  vmx-junos-dev.conf
#  - Config file for junos device bindings.
#  - Uses YAML syntax. 
#  - Leave a space after ":" to specify the parameter value.
#  - For physical NIC, set the 'type' as 'host_dev'
#  - For junos devices, set the 'type' as 'junos_dev' and
#    set the mandatory parameter 'vm-name' to the name of
#    the vPFE where the device exists
#  - For bridge devices, set the 'type' as 'bridge_dev'
#
##############################################################
interfaces :

     - link_name  : vmx_link1
       mtu        : 1500
       endpoint_1 : 
         - type        : junos_dev
           vm_name     : vmx1 
           dev_name    : ge-0/0/0
       endpoint_2 :
         - type        : bridge_dev
           dev_name    : br-v10

     - link_name  : vmx_link2
       endpoint_1 : 
         - type        : junos_dev
           vm_name     : vmx1
           dev_name    : ge-0/0/1
       endpoint_2 :
         - type        : host_dev
           dev_name    : bond0
```

For example
```
# use netconf ssh 
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.11.200/23;
            }
        }
    }
# use underlay
    ge-0/0/1 {
        flexible-vlan-tagging;
        unit 0 {
            vlan-id 110;
            family inet {
                address 10.0.110.252/24;
            }
        }
# use floating ip
        unit 1 {
            vlan-id 250;
            family inet {
                address 10.0.250.251/29;
            }
        }
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 10.0.250.252;
    }
}
```

### Trouble shooting

#### 1. Can not booting vcp

You may try change <cpu mode> setting in the vCP XML file (scripts/templates/_vRE-ref.xml), from host-model to host-passthrough, then reinstall with vmx.sh.

```
cat /home/ubuntu/vmx-17.1R2.7/scripts/templates/_vRE-ref.xml |grep -A2 "cpu mode"
<cpu mode='host-passthrough'> <--- from host-model to host-passthrough
<topology sockets='1' cores='X' threads='1'/>
</cpu><Paste>
```

[参考URL](http://forums.juniper.net/t5/vMX/vMX-cannot-boot-up-staying-at-db-gt/td-p/305658 '参考URL')
