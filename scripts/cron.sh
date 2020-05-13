#!/bin/bash
crontab -l > mycron
echo "0 0 * * * /usr/local/scripts/Schedule.sh" >> mycron
echo "0 6 * * * /usr/local/scripts/attend.sh" >> mycron
crontab mycron
rm mycron
