#!/bin/bash

# watches pcaps, and tells if we are close to actually winning yet

iface_acks="lo"
iface_syn_acks="eth0"
spoof_host="1.1.1.1"

while [ 1 ];
do
    # wait for an infrequent syn-ack
    syn_ack_seq=`tcpdump -n -i $iface_syn_acks "tcp[13]==18 and host ${spoof_host}" -S -c 1 2>/dev/null| \
        awk -F'seq' '{print $2}' | awk -F',' '{print $1}'`

    cur_ack=`tcpdump -n -i $iface_acks "host ${spoof_host} and tcp[13]==16" -S -c 1 2>/dev/null | \
        awk -F'ack' '{print $2}' | awk -F',' '{print $1}'`
    d=`date`

    diff=$(($cur_ack - $syn_ack_seq)) 
    absdiff=`python -c "print ${diff} % 2**32"`
    if [[ $absdiff -lt 10000000 ]]; then
        p=" ### "
        if [[ $absdiff -lt 500000 ]]; then
            p=" #!#!#!#!#!# "
        fi
    else
        p=""
    fi
    echo "${p}${d} waiting for ack $syn_ack_seq, sending ack $cur_ack ($absdiff)"
done
