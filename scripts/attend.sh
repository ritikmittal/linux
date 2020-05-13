#!/bin/bash

FILE=/usr/local/attendance.log

if [[ $1 == "" ]]; then
	dat="$(date +'%Y-%m-%d')"
else
	dat=$1
fi

dy=$(date -d "$dat" +"%u")

if [[ ! -d /home/AirForceChief/Current_week/ ]]; then
	mkdir /home/AirForceChief/Current_week/ /home/ArmyGeneral/Current_week/ /home/NavyMarshal/Current_week/
	mkdir /home/AirForceChief/Previous_week/ /home/ArmyGeneral/Previous_week/ /home/NavyMarshal/Previous_week/
fi

func () {
	while read tim user north east ; do
		tm=${tim:1:10}
		if [[ $tm == $1 ]] && [[ $user == $2 ]]; then
			echo "$stm	$name	$north	$east" >> /home/$3/attendance_record.txt
			break;
		fi
	done < /home/$3/post_assigned.txt
}

while read stm name val ; do
	tn=${stm:1:10}
	if [[ $tn == $dat ]] && [[ $val == "YES" ]]; then

			if [[ "$name" =~ Air ]]; then
				chief=AirForceChief
				echo "$stm	$name" >>/home/AirForceChief/Current_week/$dy 
			elif [[ "$name" =~ Army ]]; then
				chief=ArmyGeneral
				echo "$stm	$name" >>/home/ArmyGeneral/Current_week/$dy
        		else
				chief=NavyMarshal
				echo "$stm	$name" >>/home/NavyMarshal/Current_week/$dy
			fi
			func $tn $name $chief
	fi


done < $FILE

if [[ $dy -eq "7" ]]; then
	if [[ -d /home/AirForceChief/Previous_week/* ]]; then
        	rm /home/AirForceChief/Previous_week/*
        	rm /home/NavyMarshal/Previous_week/*
	       	rm /home/ArmyGeneral/Previous_week/*
	fi
        mv /home/AirForceChief/Current_week/* /home/AirForceChief/Previous_week/
	mv /home/NavyMarshal/Current_week/* /home/NavyMarshal/Previous_week/
       	mv /home/ArmyGeneral/Current_week/* /home/ArmyGeneral/Previous_week/
fi

