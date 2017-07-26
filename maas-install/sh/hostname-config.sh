#!/bin/bash

maas m nodes read mac_address="$1"|jq -r ".[].hostname"|sed -e "s/.maas//g"|xargs -I% maas m nodes read hostname=%|jq -r ".[].system_id"|xargs -I% maas m machine update % hostname=$2
