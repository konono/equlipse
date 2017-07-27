# How to install openstack

## 事前準備

Local repositoryを構築しておいた方が何かと楽です。
私たちはaptlyと言うツールを使っており、aptlyの構築手順、Ubuntu OpenStackを構築する際に必要なレポジトリは下記URLにまとめてあります。

[aptly install procedure](https://github.com/konono/aptly-toolset)

## 1. Install MAAS

![MAAS install procedure](https://github.com/konono/equlipse/blob/master/maas-install/how-to-install-maas.md 'MAAS install')

※ MAASのプロファイルはmと言う名前で作ってください。

`maas login m http://[MAAS_server]/MAAS/api/2.0 [apikey]`

### 1.1 10.0.10.0/23のセグメントに認識させるマシンを繋いだ状態で、電源をONにすることで、MAASにマシンを登録していく

![MAAS add node docs](https://docs.ubuntu.com/maas/2.1/en/nodes-add 'MAAS add node')

### 1.2 各マシンにホストをつけていく

`./maas-install/sh/hostname-config.sh 44:1e:a1:44:14:8a sv45`

※もし、Macアドレスを収集するのが大変であれば、iLO用のツールがあります。

```
./tool/collect-macaddr4ilo.py -u ilouser -p password 172.16.101.45
Port1NIC_MACAddress=44:1e:a1:44:14:88
Port2NIC_MACAddress=44:1e:a1:44:14:8a
Port3NIC_MACAddress=44:1e:a1:44:14:78
Port4NIC_MACAddress=44:1e:a1:44:14:7a
```

### 1.3 マシンがnew状態で認識されたら、それぞれ電源管理(IPMI)の設定を投入する

`./maas-install/sh/power-config [Host名] [IP address] [user] [password]`

for example> `./power-config.sh sv45 172.16.101.45 user password`

### 1.4 各ノードに対してtagをつけていく

必要になるtagは下記のとおりです。
* bootstrap
  * juju-bootstrapノード用のタグです。
* control
  * OpenStack controllerノード用のタグです。
* ceph
  * Ceph osdノード用のタグです。
* compute
  * computeノード用のタグです。

```
maas m tags create name=[tag名]
maas m tag update-nodes [tag名] add=$(maas m nodes read hostname=[host名]|jq -r ".[].system_id") 
```

### 1.5 MAASにネットワークとサブネットを登録する

設定例

![maas_network_config](https://raw.githubusercontent.com/konono/equlipse/images/maas_network_config.PNG 'maas_network_config')

### 1.6 各ノードのNW設定を行う



### Juju bootstrap 例

![juju_if_config](https://raw.githubusercontent.com/konono/equlipse/images/juju-if.PNG)

![juju_nw_config](https://raw.githubusercontent.com/konono/equlipse/images/juju-nw-config.PNG)



### Controller 例

![control_if_config](https://raw.githubusercontent.com/konono/equlipse/images/control-if.PNG)
※今回ドキュメントにある通りに作るのであれば、cephのservice segmentを食わせる必要があるので、vlan 100ではなくvlan 120をつけてください。

![control_nw_config](https://raw.githubusercontent.com/konono/equlipse/images/control-nw-config.PNG)



### Compute 例

![compute_if_config](https://raw.githubusercontent.com/konono/equlipse/images/compute-if.PNG)
※今回ドキュメントにある通りに作るのであれば、vlan 100はいらないです。

![compute_nw_config](https://raw.githubusercontent.com/konono/equlipse/images/compute-nw-config.PNG)



### Ceph osd 例

CephはMAASの画像を添付していませんが、Controller,Computeと同じようにMAASからconfigurationすると楽です。
![ceph_nw_config](https://raw.githubusercontent.com/konono/equlipse/images/ceph-nw-config.PNG)



## 2. Install Juju

![juju install procedure](https://github.com/konono/equlipse/blob/master/juju-install/how-to-install-juju.md)

## 3. Install OpenStack

