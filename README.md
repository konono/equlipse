# equlipse
 This project aims to deploy OpenStack Mitaka using MAAS / Juju and relate OpenContrail

## Hardware requirements

### Management node group

* 1 Client node (physical or vm)
  * os: ubuntu 16.04
  * cpu: 1 core
  * mem: 4GB
  * interface: 1 port
  * ipmi port
  * disk: 1disk, 50GB

* 1 MAAS node (physical or vm)
  * os: ubuntu 16.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 1disk, 100GB
  
* 1 Juju node (physical or vm)
  * os: ubuntu 16.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 1disk, 300GB
  
* 1 Local repository node (physical or vm)
  * os: ubuntu 16.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 1disk, 500GB~
  
### OpenStack node group

* 3 Controller node (pysical or vm)
  * os: ubuntu 14.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 1disk, 100GB
  
* 1 Compute node (pysical)
  * os: ubuntu 14.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 1disk, 100GB

* 3 Ceph storage node (physical or vm)
  * os: ubuntu 16.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 3disk, 500GB~ (require osd disk sdb and sdc)

### virtual router node group
  
* 1 vMX node (physical)
  * os: ubuntu 16.04
  * cpu: 4 core
  * mem: 16GB
  * interface: 4 port
  * ipmi port
  * disk: 1disk, 100GB
  
## Network requirements
* 6 network segment
  * openstack internal api and MAAS deploy segment
    * In the sample `vlan 10(untag)`  `10.0.10.0/23`
  * mgmt and ssh login segment
    * In the sample `vlan 20(untag)`  `10.0.20.0/23`
  * openstack service segment
    * In the sample `vlan 110(tag)` `10.0.110.0/24`
  * ceph service and replication segment
    * In the sample `vlan 120(tag)` `10.0.120.0/24`
  * vMX to InternetGW segment
    * In the sample `vlan 250(tag)` `10.0.250.0/24`
  * floating ip segment
    * In the sample `vlan 301` `175.111.74.0/24`
* Preparing reachability of vlan 10 and vlan 20, vlan 110, vlan 120
* Preparing reachability among the above vlans.

## Software requirements
* OpenStack Mitaka
* Juju 2.0~
* MAAS 2.0~
* vMX 17.2~
* Contrail package 3.2~

### *To get contrail package, Please contact Juniper K.K.*

## Install procedure
[OpenStack install procedure](https://github.com/konono/equlipse/blob/master/how-to-install.md)
