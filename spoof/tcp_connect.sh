#!/bin/bash

win=65535
sport=12345
host="141.212.120.74"

#SYN
ack=`hping3 -c 1 -M 123456000 -S -s $sport -p 80 $host -Q -w $win | awk -F' ' '{print $1}' | tail -1`
resp=$(($ack + 1))


#ACK
hping3 -c 1 -A -M 123456001 -L $resp -s $sport -p 80 $host -w $win

exit

#GET / HTTP/1.1
hping3 -c 1 -d 51 -E http_get -M 123456001 -s $sport -A -L 0 -p 80 -w $win $host
hping3 -c 1 -d 51 -E http_get -M 123456001 -s $sport -A -L 2147483649 -p 80 -w $win $host

echo ""
echo $resp

sleep 5


# "guess" the ack
hping3 -c 1 -M 123456052 -s $sport -A -L 0 -p 80 -w $win $host
hping3 -c 1 -M 123456052 -s $sport -A -L 5000 -p 80 -w $win $host
hping3 -c 1 -M 123456052 -s $sport -A -L 10000 -p 80 -w $win $host
hping3 -c 1 -M 123456052 -s $sport -A -L 15000 -p 80 -w $win $host
hping3 -c 1 -M 123456052 -s $sport -A -L 20000 -p 80 -w $win $host

# correct "guess"
guess_ack=$resp
for i in `seq 1 1024`
do
    guess_ack=$(($guess_ack + 1024))
    hping3 -c 1 -M 123456052 -s $sport -A -L $guess_ack -p 80 -w $win $host
done
