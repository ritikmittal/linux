#!/bin/bash
useradd -m ChiefCommander
echo "ChiefCommander:ChiefCommander" | chpasswd

useradd -m ArmyGeneral
echo "ArmyGeneral:ArmyGeneral" | chpasswd

useradd -m NavyMarshal
echo "NavyMarshal:NavyMarshal" | chpasswd

useradd -m AirForceChief
echo "AirForceChief:AirForceChief" | chpasswd

count=1

while [ $count -lt 51 ]; do
	name=Army$count
	useradd -m $name
	echo "$name:$name" | chpasswd

	name=Navy$count
	useradd -m $name
	echo "$name:$name" | chpasswd

	name=AirForce$count
	useradd -m $name
	echo "$name:$name" | chpasswd

	count=$((count+1))

done

