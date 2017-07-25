#!/bin/bash
TAG=amqp

dpkg -l |grep jq >/dev/null 2>&1
if [ $? = 1 ]; then
  sudo apt-get install jq
fi



usage(){

  echo "for ${TAG} only"
  echo "usage: $0 --list|--host hostname"


}


get_tag_hostlist(){
  juju machines --format json |jq ".machines[]| select(.hardware|test(\"${TAG}\"))|.[\"dns-name\"]"| tr '\n' ',' |sed s/,$//
}


get_tag_machinelist(){
  juju machines --format json |jq ".machines[]| select(.hardware|test(\"${TAG}\"))|.[\"dns-name\"]"| tr '\n
' ',' |sed s/,$//
}

case $1 in 
  "--list")
     if [ "$2" != "" ];then 
        TAG=$2
     fi
     echo -n '{"sys":{"hosts":['
     echo -n "$(get_tag_hostlist)"
     echo -n ']}}'
     ;;

  "--host")
     if [ "x"$2 == "x" ] || [ $# -ne 2 ];then
       usage
     fi
     
     echo "{}"

     ;;
  ## for juju use only
  "--mlist")
     get_tag_machinelist
     
     ;;
  *)
     usage 
     ;;

esac

