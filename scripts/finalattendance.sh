#!/bin/bash

while read stm name north east; do
	echo "$stm      $name	$north	$east">> /home/ChiefCommander/attendance_report.txt
done < /home/AirForceChief/attendance_record.txt

while read stm name ; do
	echo "$stm      $name	$north	$east">> /home/ChiefCommander/attendance_report.txt
done < /home/ArmyGeneral/attendance_record.txt

while read stm name ; do
	echo "$stm      $name	$north	$east">> /home/ChiefCommander/attendance_report.txt
done < /home/NavyMarshal/attendance_record.txt

