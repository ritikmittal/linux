#!/bin/bash

touch /home/ChiefCommander/near_troop

awk '{
	LONG=77.1025/57.29578
	LAT=28.7041/57.29578
	lon1=substr($4,4,8)
	lon=lon1/57.29578
	lat1=substr($3,4,8)
	lat=lat1/57.29578
	fo=sin(lat)*sin(LAT)
	go=cos(lat)*cos(LAT)*cos(LONG-lon)
	go+=fo
	dist=6356*atan2(sqrt(1-(go*go)),go)
	printf("%s	%s	%s	%s	%.5f km\n",$1,$2,$3,$4,dist) >> "/home/ChiefCommander/near_troop"
}' /home/ChiefCommander/attendance_report.txt

sort -k 5n /home/ChiefCommander/near_troop | head >> /home/ChiefCommander/nearest10
rm /home/ChiefCommander/near_troop
