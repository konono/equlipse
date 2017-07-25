sudo apt-get install -y bridge-utils qemu-kvm libvirt-bin
sudo apt-get install -y libyaml-dev python-yaml numactl libparted0-dev libpciaccess-dev
sudo apt-get install -y libnuma-dev libyajl-dev libxml2-dev libglib2.0-dev
sudo apt-get install -y python-pip python-dev libxml2-dev libxslt-dev libnl-3-dev
sudo apt-get install -y python python-netifaces vnc4server
patch -u ./scripts/common/vmx_preinstall_checks.sh < ./vmx_preinstall_checks.patch
wget https://downloads.sourceforge.net/project/e1000/i40evf%20stable/1.4.15/i40evf-1.4.15.tar.gz
mkdir -p drivers
mv ./i40evf-1.4.15.tar.gz ./drivers
cd ./drivers/
tar zxvf i40evf-1.4.15.tar.gz
rm -rf i40evf-1.4.15.tar.gz
