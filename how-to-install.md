# How to install openstack

## 1. Install MAAS

[MAAS install procedure](https://github.com/konono/equlipse/blob/master/maas-install/how-to-install-maas.md 'MAAS install')

※ MAASのプロファイルはmと言う名前で作ってください。

`maas login m http://[MAAS_server]/MAAS/api/2.0 [apikey]`

### 1.1 Register machines

#### 1.1.1 10.0.10.0/23のセグメントに認識させるマシンを繋いだ状態で、電源をONにすることで、MAASにマシンを登録していく

[MAAS add node docs](https://docs.ubuntu.com/maas/2.1/en/nodes-add 'MAAS add node')

#### 1.1.2 各マシンにホストをつけていく

`.maas-install/sh/hostname-config.sh 44:1e:a1:44:14:8a sv45`

※もし、Macアドレスを収集するのが大変であれば、iLO用のツールがあります。

```
tool/collect-macaddr4ilo.py -u ilouser -p password 172.16.101.45
Port1NIC_MACAddress=44:1e:a1:44:14:88
Port2NIC_MACAddress=44:1e:a1:44:14:8a
Port3NIC_MACAddress=44:1e:a1:44:14:78
Port4NIC_MACAddress=44:1e:a1:44:14:7a
```

#### 1.1.3 マシンがnew状態で認識されたら、それぞれ電源管理(IPMI)の設定を投入する

`./maas-install/sh/power-config [Host名] [IP address] [user] [password]`

for example> `./power-config.sh sv45 172.16.101.45 user password`

#### 1.1.4 各ノードに対してtagをつけていく

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

#### 1.1.5 MAASにネットワークとサブネットを登録する

設定例

[maas_network_config](https://raw.githubusercontent.com/konono/equlipse/images/maas_network_config.PNG 'maas_network_config')


