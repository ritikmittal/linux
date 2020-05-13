#!/bin/bash
if [[ $1 != "" ]]; then
	if [[ $USER == "ArmyGeneral" ]]; then
		cat /home/ArmyGeneral/Previous_week/$1
	elif [[ $USER == "AirForceChief" ]]; then
		cat /home/AirForceChief/Previous_week/$1
	elif [[ $USER == "NavyGeneral" ]]; then
		cat /home/NavyGeneral/Previous_week/$1
	else
		echo "permission denied : Only Troop Chiefs can access to this command"
	fi
fi
