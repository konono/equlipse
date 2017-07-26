#!/bin/bash

maas m machine update $(maas m nodes read hostname=$1|jq -r ".[].system_id") power_type=ipmi power_parameters_power_driver=LAN_2_0 power_parameters_power_address=$2 power_parameters_power_user=$3 power_parameters_power_pass=$4 power_parameters_mac_address=
