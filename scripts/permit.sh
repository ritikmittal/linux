#!/bin/bash
chmod 770 /home/ChiefCommander/
chmod 770 /home/AirForceChief/
chmod 770 /home/NavyMarshal/
chmod 770 /home/ArmyGeneral/

usermod -a -G ArmyGeneral,AirForceChief,NavyMarshal ChiefCommander

count=1

while [ $count -lt 51 ]; do

name1=Army$count
name2=Navy$count
name3=AirForce$count
chmod 770 /home/$name1/
chmod 770 /home/$name2/
chmod 770 /home/$name3/

usermod -a -G $name1 ArmyGeneral
usermod -a -G $name2 NavyMarshal
usermod -a -G $name3 AirForceChief
usermod -a -G $name1,$name2,$name3 ChiefCommander

count=$((count+1))
done

