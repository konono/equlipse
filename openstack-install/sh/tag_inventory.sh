#!/bin/bash

TAG=$1


usage(){

  echo "usage: $0 [TAG] --list|--host hostname"


}


get_tag_hostlist(){
  juju machines --format json |jq ".machines[]| select(.hardware|test(\"${TAG}\"))|.[\"dns-name\"]"| tr '\n' ',' |sed s/,$//
}


case $2 in 
  "--list")
     echo -n '{"sys":{"hosts":['
     echo -n "$(get_tag_hostlist)"
     echo -n ']}}'
     ;;

  "--host")
     if [ "x"$3 == "x" ] || [ $# -ne 3 ];then
       usage
     fi
     
     echo "{}"

     ;;
  *)
     usage 
     ;;

esac

