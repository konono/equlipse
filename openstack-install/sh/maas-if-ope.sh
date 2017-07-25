#!/bin/bash

NODE_NAME=
INTERFACE_NAME1=
SUBNET=
TGT_IF1=
MAAS_PROFILE=


usage(){
  echo "$0 [--add|--remove|--if|--subnets|--param] machine_name interface_name subnet"
  echo "###  requirements env : MAAS_PROFILE ###"
  echo 
  echo "  --add     : allocate subnet to interface  "
  echo "  ex) $0 --add svXX enp3s0f0 10.0.10.0/24"
  echo  ""
  echo "  --remove  : unallocate subnet to interface  "
  echo "  ex) $0 --remove svXX enp3s0f0"
  echo 
  echo "  --if      : show all interfaces on a machine  "
  echo "  ex) $0 --if svXX "
  echo 
  echo "  --subnets : show all subnets on this maas"
  echo "  ex) $0 --subnets"
}       

setparam(){
  NODE_NAME=$1
  INTERFACE_NAME1=$2
  SUBNET=$3

  setnode ${NODE_NAME}
  TGT_IF1=$(maas ${MAAS_PROFILE} interfaces read ${NODE} |jq ".[]|select (.name|test(\"${INTERFACE_NAME1}\"))|.id") 
}

setnode(){
  NODE_NAME=$1
  NODE=$(maas ${MAAS_PROFILE} nodes read hostname=${NODE_NAME}|jq -r ".[].system_id")
}

subnets(){
  maas ${MAAS_PROFILE} subnets read|jq -r '.[]|"\(.vlan.fabric)\t  \(.name):\t\(.cidr)"'
}

interfaces(){
  maas ${MAAS_PROFILE} interfaces read ${NODE} |jq -r '.[]|"\(.id)\t :\(.name) \t:\(.vlan.fabric) \t:\(.links)"'  
}

allocate(){
  maas ${MAAS_PROFILE} interface link-subnet ${NODE} ${INTERFACE_NAME1} subnet=${SUBNET} mode=AUTO
}

unallocate(){
  maas ${MAAS_PROFILE} interface update ${NODE} ${INTERFACE_NAME1} vlan=
}


set_vlan(){
  
  maas ${MAAS_PROFILE} interfaces create-vlan ${NODE}  vlan=${5} parent=${INTERFACE_NAME1}
}





# set maas profile
if type maas >/dev/null 2>&1 ;then
   MAAS_PROFILE=$(maas list|awk '{print $1}')
else
   echo 'maas command not found'
   echo 'plese following command'
   echo 'sudo apt-get install maas-cli'
   echo 'maas login m http://[MAAS_server]/MAAS/api/2.0 [apikey]'
fi



case $1 in 
  "--param")
     setparam $2 $3 $4
     echo ${TGT_IF1}
     ;;

  "--add")
     setparam $2 $3 $4
     allocate
     ;;

  "--remove")
     setparam $2 $3 $4
     unallocate
     ;;
  "--if")
     setnode $2
     interfaces 
     ;;
  "--subnets")
     subnets
     ;;
  "--add-vlan")
     setparam $2 $3 $4
     set_vlan $5
     ;;

  *)
     usage 
     ;;

esac

