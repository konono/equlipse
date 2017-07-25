#!/bin/bash

NODE_NAME=
INTERFACE_NAME1=
INTERFACE_NAME2=
TGT_IF1=
TGT_IF2=

usage(){
  echo 'available option'
  echo '--param or --bond'
  echo '--param machine_name interface_name1 interface_name2'
  echo '--bond machine_name interface_name1 interface_name2 bonding_dev'
  echo '--unbond machine_name bonding_dev '
  echo "ex) $0 --bond sv22 enp4s0f0 enp4s0f1 bond0"
}

setparam(){
  NODE_NAME=$1
  INTERFACE_NAME1=$2
  INTERFACE_NAME2=$3
  BONDING_DEV=$4
  
  # set maas profile
  if type maas >/dev/null 2>&1 ;then
     MAAS_PROFILE=$(maas list|awk '{print $1}')
  else
     echo 'maas command not found'
     echo 'plese following command'
     echo 'sudo apt-get install maas-cli'
     echo 'maas login m http://[MAAS_server]/MAAS/api/2.0 [apikey]'
  fi

  NODE=$(maas ${MAAS_PROFILE} nodes read hostname=${1}|jq -r ".[].system_id")
  TGT_IF1=$(maas ${MAAS_PROFILE} interfaces read ${NODE} |jq ".[]|select (.name|test(\"${2}\"))|.id") 
  TGT_IF2=$(maas ${MAAS_PROFILE} interfaces read ${NODE} |jq ".[]|select (.name|test(\"${3}\"))|.id")
}

bond(){
  maas $MAAS_PROFILE interfaces create-bond ${NODE} name=${BONDING_DEV} parents=${TGT_IF1} parents=${TGT_IF2} bond_mode=active-backup
}

unbond(){
  maas $MAAS_PROFILE interface delete ${NODE} ${TGT_IF1} 
}



case $1 in 
  "--param")
     setparam $2 $3 $4
     echo "${INTERFACE_NAME1}:${TGT_IF1} "
     echo "${INTERFACE_NAME2}:${TGT_IF2} "
     ;;

  "--bond")
     setparam $2 $3 $4 $5
     bond $2 $3 $4 $5
     ;;
  "--unbond")
     setparam $2 $3 $4 $5
     unbond $2 $3 $4 $5
     ;;
  *)
     usage 
     ;;

esac

