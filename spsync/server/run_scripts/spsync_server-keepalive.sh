#!/bin/bash

while [ -x "./spsync_server" ] ; do
	"./spsync_server" &
	pid=$!
	echo $pid > "./spsync_server.pid"
	wait $pid
	timestamp=$(date '+%F %T')
	ret=$?
	echo "spsync_server exited with ${ret} [pid=${pid}, time=${timestamp}]" >> "./exit.log"
	sleep 10
done
