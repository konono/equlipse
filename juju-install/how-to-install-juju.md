Juju getting started
---

### 1. Create Cloudtype

```
ubuntu@deploy:~$ cat maas.yaml
clouds:
        c1:
            type: maas
            auth-types: [oauth1]
            endpoint: http://192.168.150.2/MAAS

```

### 2. Add Cloud

MAASをjujuが使えるcloudとして登録してあげる
```
juju add-cloud c1 maas.yaml

ubuntu@deploy:~$ juju list-clouds
CLOUD        TYPE        REGIONS
aws          ec2         us-east-1, us-west-1, us-west-2, eu-west-1, eu-central-1, ap-southeast-1, ap-southeast-2 ...
aws-china    ec2         cn-north-1
aws-gov      ec2         us-gov-west-1
azure        azure       centralus, eastus, eastus2, northcentralus, southcentralus, westus, northeurope ...
azure-china  azure       chinaeast, chinanorth
cloudsigma   cloudsigma  hnl, mia, sjc, wdc, zrh
google       gce         us-east1, us-central1, europe-west1, asia-east1
joyent       joyent      eu-ams-1, us-sw-1, us-east-1, us-east-2, us-east-3, us-west-1
rackspace    rackspace   dfw, ord, iad, lon, syd, hkg
localhost    lxd         localhost
local:c1     maas
```

### 3. Add Credential

MAASのクレデンシャル情報を追加する
```
ubuntu@deploy:~$ juju add-credential c1
  credential name: <maasのユーザ>
  auth-type: oauth1
  maas-oauth: <MAASのAPIキーを入力>
credentials added for cloud c1
```

APIキーの取得
![maas_api_key](https://raw.githubusercontent.com/konono/equlipse/images/maas-api-key.PNG)

### 4. MAAS configuration

Jujuをインストールするサーバを明示的に選択するために、タグを付けておく
```
maas m tags create name=bootstrap
maas m tag update-nodes bootstrap add=$(maas m nodes read hostname=[対象サーバのホスト名]|jq -r ".[].system_id") 
```

### 5. Juju bootstrap

juju-bootstrapのタグがついているNodeにjuju serverをデプロイ
```
juju bootstrap --constraints tags=bootstrap --debug c1 juju01
```

