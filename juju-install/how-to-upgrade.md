## How to upgrade juju

### The following is steps to upgrade juju v2.0 to v2.1.
It sounds like Bootstrap node that you said means controller model.
You can upgrade controller model and service model separately but we recommend you to install/use the same version between controller model and service model.

Before upgrading juju, Backup is strongly recommended. Please see this page for details about backup and restore[1].
Also, testing it on your test/staging environment first would be good before you apply it to production environment.

### 1. on juju client,

```
$sudo add-apt-repository -u ppa:juju/stable
$sudo apt-get update
$sudo apt-get install juju
#check if juju v2.1 is properly installed.
$juju --version
2.1.1-xenial-amd64
```

### 2. Upgrading juju must be done on controller model first. Please run the following command on juju client.

```
$juju upgrade-juju -m controller
#check if upgrading juju is done successfully. You would see like an example below if it gets success.
$juju status -m controller
Model Controller Cloud/Region Version
controller maas-hw maas-hw 2.1.1.1
```

### 3. Now, you upgrade other models.

```
$juju upgrade-juju -m $YOUR_SERVICE_MODEL
#check if it's successfully done.
$juju status -m $YOUR_SERVICE_MODEL
```

### 4. check if your services are running without any issues.
Upgrading juju will restart juju agents. Please check if there are any hooking error or errors like that occur.

Thank you.

[1]
[controllers-backup](https://jujucharms.com/docs/2.0/controllers-backup)
