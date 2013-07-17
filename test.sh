#!/bin/bash

google-chrome --user-data-dir=/home/ewust/research/tcp_bf/.google-chrome-config/ --temp-profile --incognito --disable-sync "http://bank2.hobocomp.com/" &
chrome_pid=$!

sleep 1

google-chrome --user-data-dir=/home/ewust/research/tcp_bf/.google-chrome-config/ --incognito --disable-sync "http://141.212.109.58:8181/page.html" &
chrome_pid2=$! # not needed

echo -n 'start: ' >> test.log
date >> test.log

nc -l 8945 -v 2>&1 | head -2 >> test.log

echo -n 'end: ' >> test.log
date >> test.log

kill $chrome_pid
