## MAASのインストール

```
sudo apt-get install software-properties-common

# ローカルレポジトリを使っている場合は下記手順は飛ばす
sudo add-apt-repository ppa:maas/stable

sudo apt-get install maas
sudo apt-get install jq
```

### MAASのadmin userセットアップ

```
sudo maas-region-admin createadmin

ubuntu@maas-n:~$ sudo maas-region-admin createadmin                                            
[sudo] password for ubuntu:                                                                    
WARNING: The maas-region-admin command is deprecated and will be removed in a future version. 
From now on please use 'maas-region' instead.                                                   
Username: maas                                                                                 
Password:
Again:
Email: [your mail account]
Import SSH keys [] (lp:user-id or gh:user-id):
```
#### ここでSSH keyを求められるのだが、ここではlp=launch padもしくはgh=githubの鍵しか食わせられないのでスルーしましょう
#### エラーが出てもちゃんとユーザーは作られています

### MAASコマンドのセットアップ

```
sudo maas-region-admin apikey --username=xxxxx | xargs maas login m http://localhost/MAAS/api/2.0

※MAASノード以外でセットアップする時はコマンドを下記
sudo apt-get install maas-cli
maas login m http://[MAAS_server]/MAAS/api/2.0 [apikey]

コマンドのテスト
maas m nodes read
```

### GUIからのセットアップ
最近のMAASはインストールした後最初のアクセスはsetup画面に飛ばされるようになったので、GUIからセットアップします。

![maas-setup1](https://raw.githubusercontent.com/konono/equlipse/images/maas-setup01.PNG 'maas-setup1')

![maas-setup2](https://raw.githubusercontent.com/konono/equlipse/images/maas-setup02.PNG 'maas-setup2')

### MAASイメージのインポート

```
maas m boot-source-selections create 1 os="ubuntu" release="trusty" arches="amd64" subarches="*" labels="*" 
maas m boot-source-selections create 1 os="ubuntu" release="xenial" arches="amd64" subarches="*" labels="*" 
maas m boot-resources import
```

### MAASのSSH-KEYのセットアップ

```
ssh-keygen
mv ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys
sudo chmod 600 ~/.ssh/authorized_keys
sudo chmod 600 ~/.ssh/id_rsa
cat ~/.ssh/authorized_keys |xargs -I% maas m sshkeys create key="%" 
scp ~/.ssh/id_rsa ubuntu@maas:~/.ssh/
```

### MAAS-dhcpdのセットアップ

```
maas m ipranges create type=dynamic start_ip=10.0.10.50 end_ip=10.0.10.255
maas m vlan update fabric-0 untagged dhcp_on=True primary_rack=[デフォルトではMAASのhost名]

※Gatewayが設定されていなければ下記で設定
maas m subnet update 10.0.10.0/23 gateway_ip=10.0.11.254
```

## MAAS TIPS

### MAASのホストネームをmacアドレスから設定

```
maas m nodes read mac_address="44:1e:a1:44:14:88"|jq -r ".[].hostname"|sed -e "s/.maas//g"|xargs -t -I% maas m nodes read hostname=%|jq -r ".[].system_id"|xargs -I% -t  maas m machine update % hostname=sv45
```
### 仮想マシンをMAASから電源管理

```
kvmの場合KVMのノードに対してvirshコマンドが実行できるようにしておく
MAASサーバ上で下記手順を実行
sudo apt-get install libvirt-bin
sudo mkdir -p ~maas/.ssh/
sudo cp -p ~/.ssh/id_rsa ~maas/.ssh/
sudo chown maas. ~maas/.ssh/id_rsa
sudo -u maas virsh -c qemu+ssh://[ユーザ@KVMサーバのIP]/system list

maas m machine update $(maas m nodes read hostname=[hostname]|jq -r ".[].system_id") power_type=virsh power_parameters_power_address="qemu+ssh://ubuntu@192.168.122.1/system" power_parameters_power_id=[kvmでのゲスト名]

maas m machine update $(maas m nodes read hostname=[hostname]|jq -r ".[].system_id") power_type=ipmi power_parameters_power_driver=LAN_2_0 power_parameters_power_address=172.16.101.4[x] power_parameters_power_user=dcmuser power_parameters_power_pass=y7u8i9YUI power_parameters_mac_address=
```

### Textconsoleでコンソールを見られるようにするためのconfig

```
maas m maas set-config name=kernel_opts value="console=tty0 console=ttyS0,115200n8"
```

### Local repositoryの設定

```
maas m package-repository update 1 url="http://xxx.xxx.xxx.xxx/ubuntu20170404/"

maas m package-repository update 1 key="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: keyserver.ubuntu.com

mQENBFgi978BCADMZcsKv+/RWrOp5iIT+/nmvko+wAGgiPmkspoB4YW6ZEgNqsODGoGQkmyq
fzx0Yx5TkIPYH+mKiMR9HkHzRhttzK7OPQxuEhfKvAQwSN4vVQFXuvWJHA1Q6UUwHiWbLZpC
sYZtYTqjo9Mkh2wxdXqdh4cBQ0BrsKpwFZNkjJjhZplvf2vDQ3CMFzUYR21okEwFNkVrJYLE
ENuHrEAn1sKwKHY7qpMnZfZCIcoYyZ6OmdYcyg1tqva/52qga/zbvYpOcWCR+UlwddJ/q00J
0V1Komp2EJ3gexI03O90oqx7fNQfzvx97hmnCCzqnoAjt83/a4Pw3OajiXvWJlxQaRAJABEB
AAG0QG9zcyB0ZWFtIChsb2NhbCByZXBvc2l0b3J5IHNpZ24ga2V5KSA8eXlhbWFzaGl0YUBh
cC5lcXVpbml4LmNvbT6JATgEEwECACIFAlgi978CGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4B
AheAAAoJEOXcMWkwD5xYH5wH/2rwzfVPnR8ijMqs1PFqOVqdt9QjfwkAIoGZu2iAntNgHBbg
n7i7peEu88Iwu9u8TsxpFsV/jcYI8+GdZAJjA5NJrGmoRkDnseG0b1nrajtw8O4XJt1r65jm
IBbo74EiMSC2L6l8n5s86Fy+3/zXaihZL5cVhU86PlVQvPbIzNgoT1AGeQdi7wOqk6vjMvbz
LdlrSB3iF/AuHGarpUO1neu0NWSGwR2RY01r3o+HcgPkSFK03Fony2qJC5UtIUJGFJoHeCAF
BI3xrz1JCz4d3EdWHzwHxkf6X6ToqwmCOpQqiEoLzkwi0nACRBgtUB/1grqMPXlxt9NrWsEc
6ptCt/e5AQ0EWCL3vwEIALXtcatK0rQvE/kDI0tPl+kjI8XCCjYjFzzAm8j6aBBP3uopzQD8
gekzJ/zy3SCCM/GHQosxs2xvKu+ZO6aXtMQgrZ8tkpQ1fl3JVLeHKG+ZiBh8Qmsl0C9ycrF5
acVlCERW/mDp0+XzNarXv7uM8T9YM2pLM1VaDQRWZ/5ZcDeH9PFlylTLDX2gGQALQCtaxMUB
JLHQ2UBduCa5MXNdJaBvfrC0FnjUdI+5IiVoyRjOQUahprFFZGzgWRqVGO3azyNfnLrStGxE
AVsyi7u6EnLvM0R7vqRVrlvtXwb81KvA5mg4XZhfNTDZgPKpNqBIFKbo6YBbVVY+qPzf4+O5
NQkAEQEAAYkBHwQYAQIACQUCWCL3vwIbDAAKCRDl3DFpMA+cWLAACAC2I8OfXqsKP13+9NBS
vFlQOy3VYYaLXM9ovHdOrGoXq5Kvpn4cdjTWNpyMeOMt1e4qQS+JNgffrJV/TL7T/jV6i0P9
DyuZ3XfwYfV60H+N6W4qsQ7HxMZ9Px2xALFvCP89ELYgiLcVY1sl2xwieshgKmIziLTjWjXK
41kH743+28d/gh0cAkclBruYE2R6lwQZx6K0XpevvVnpJVLNBD1CVNot8T7Sm9Oe9F2/MLns
iuKQWK3rO7U+tWhmDRBJNxbAriDV1aPG2+jqLp9lU/jmXM3ctPEuAsmLW3+2+OohyRcqDOj0
6rkCIKT/RflBmKOq1rOi41mRqZMN6sACc2Qd
=IJ0H
-----END PGP PUBLIC KEY BLOCK-----"

```


### Machineのcommissioning

```
maas m machine commission $(maas m nodes read hostname=sv11|jq -r ".[].system_id") enable_ssh=1
```

### Machineのリリース

```
maas m node release -d $(maas m nodes read hostname=[hostname]|jq -r ".[].system_id")
```

### MAASでtag付け

```
maas m tags create name=compute
maas m tag update-nodes  compute add=$(maas m nodes read hostname=sv11|jq -r ".[].system_id") 
```

### MachineのIPアドレス固定

```
maas m interface unlink-subnet $(maas m nodes read hostname=sv11|jq -r ".[].system_id") enp3s0f0 id=$(maas m interfaces read $(maas m nodes read hostname=sv11|jq -r ".[].system_id")|jq ".[].links"|jq -r ".[].id")

maas m interface link-subnet $(maas m nodes read hostname=sv11|jq -r ".[].system_id") enp3s0f0 subnet=10.0.10.0/23 mode=static ip_address=10.0.10.200
maas m interface link-subnet $(maas m nodes read hostname=sv22|jq -r ".[].system_id") bond0 subnet=10.0.110.0/24 mode=auto
```

### bonding interface の作り方
```
$ maas m interfaces create-bond 4rb47y name=bond0 parents=132 parents=133
```

### MAASのconfiguration一覧表示

```
maas m maas get-config -h|grep ^:|sed -e "s/:\(.*\):/\1/g"|awk '{print $1}'|grep -v param|xargs -I% -t maas m maas get-config name=%
```

### jqを使った様々なデータの取得
 * system_idとmacの取得

```
maas m nodes read|jq .[]|jq ".system_id, .boot_interface.mac_address"
```
* ipmi のipアドレス取得
```
maas m nodes read|jq .[]|jq -c -r ".system_id"|xargs -I% -t maas maas node power-parameters %|jq -r .power_address
```

### curtin configの変更及び確認

```
Per node curtin config
cat /etc/maas/preseeds/curtin_userdata_ubuntu_amd64_generic_trusty_[hostname]
#cloud-config
early_commands:
  chghost1: ["sh", "-c", "hostname deploy"]
  apt_key: apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 55EDFF7B
  puppet_00_get: ["curtin", "in-target", "--", "sh", "-c", "wget -O /tmp/puppetlabs-release-trusty.deb https://apt.puppetlabs.com/puppetlabs-release-trusty.deb && dpkg -i /tmp/puppetlabs-release-trusty.deb"]
  puppet_01_install: ["curtin", "in-target", "--", "sh", "-c", "apt-get update && apt-get -y install puppet"]
  puppet_02_onboot: ["curtin", "in-target", "--", "sh", "-c", "sed -i /etc/default/puppet -e 's/START=no/START=yes/'"]

Show curtin config
maas m machine get-curtin-config $(maas m nodes read hostname=[hostname]|jq -r ".[].system_id")
```

### Customize MAAS Image for ephemeral v2

```
# Login to MAAS node
mkdir maas-image
cd maas-image
wget http://images.maas.io/ephemeral-v2/releases/trusty/amd64/20150727/root-image.gz
※｢20150727｣を[release]として今後の手順を読み替えてください
mkdir [relase]
mv root-image.gz [relase]
cd [relase]
gzip -d ./root-image.gz
sudo mount -o loop -t ext4 ./root-image /mnt/
sudo chroot /mnt/
"""""" 
好きな手順を実行
今回はrootのパスワードを入力

passwd root
"""""" 
exit
cd /mnt/
sudo tar zcvf /home/ubuntu/maas-image/[relase]/root-tgz_YYYYMMDD ./*
cd
sudo umount /mnt
sudo cp -p /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/trusty/release/root-tgz /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/trusty/release/root-tgz.bak_YYYYMMDD
sudo cp /home/ubuntu/maas-image/[relase]/root-tgz_YYYYMMDD /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/trusty/release/
sudo chown maas. /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/trusty/release/root-tgz

maas m boot-resources create name="custom/16.04-$(date)" kflavor="generic" architecture="amd64/generic" filetype=tgz title="ubuntu16.04-20170117" content@=/home/ubuntu/maas-image-custom_20170117/20160420.3/root-tgz_20170117
```


### Customize MAAS Image for ephemeral v3

```
# Login to MAAS node
mkdir maas-image
cd maas-image
wget http://images.maas.io/ephemeral-v3/daily/xenial/amd64/20170330.1/squashfs
※｢20170330.1｣を[release]として今後の手順を読み替えてください
mkdir [relase]
mv squashfs [relase]
cd [relase]
sudo apt install squashfs-tools
sudo unsquashfs squashfs
cd squashfs-root/
sudo chroot ./
"""""" 
好きな手順を実行
今回はrootのパスワードを入力

passwd root
"""""" 
exit
sudo sudo mksquashfs ./* /home/ubuntu/maas-image/[relase]/squashfs_YYYYMMDD
sudo cp -p /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/xenial/release/root-tgz /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/xenial/release/root-tgz.bak_YYYYMMDD
sudo cp /home/ubuntu/maas-image/[relase]/squashfs_YYYYMMDD /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/xenial/release/squashfs
sudo chown maas. /var/lib/maas/boot-resources/current/ubuntu/amd64/generic/xenial/release/squashfs

maas m boot-resources create name="custom/16.04-$(date)" kflavor="generic" architecture="amd64/generic" filetype=squashfs title="ubuntu16.04-20170117" content@=/home/ubuntu/maas-image-custom_20170117/20160420.3/squashfs_20170117
```


### MAASのアンインストール

```
sudo apt-get purge maas maas-cli maas-cluster-controller  maas-common maas-dhcp maas-dns maas-region-controller python-django-maas python-maas-client python-maas-provisioningserver ;sudo apt-get autoremove
```

### MAAS image local image mirror 
https://docs.ubuntu.com/maas/2.1/en/installconfig-images-mirror

```
sudo apt install simplestreams
./sstream.sh
```

[参考URL](https://docs.ubuntu.com/maas/2.1/en/installconfig-images-mirror)
