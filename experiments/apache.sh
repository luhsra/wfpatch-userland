#!/bin/bash

NUM_CONNECTIONS=$1||10
NUM_REQUESTS=$2||50000

rm -rf /home/user/osdi-code-patching/apache/data/global
rm -rf /home/user/osdi-code-patching/apache/data/local

echo "Starting benchmark with $NUM_CONNECTIONS and $NUM_REQUESTS requests in total."
echo "Measuring request latencies for Apache with local quiescence. Every 1.5 seconds a patch request is sent."
WF_CYCLIC=1.5 WF_CYCLIC_BOOT=3 WF_GLOBAL=0 WF_LOGFILE=apache_server_local.txt /home/user/apache/usr/sbin/apachectl -k start -X &
sleep 2
/home/user/apache/usr/bin/ab -c $NUM_CONNECTIONS -n $NUM_REQUESTS -g ab.out.local http://localhost:8080/sample
sleep 2
/home/user/apache/usr/sbin/apachectl -k stop

sleep 3
echo "Measuring request latencies for Apache with global quiescence. Every 1.5 seconds a patch request is sent."
WF_CYCLIC=1.5 WF_CYCLIC_BOOT=3 WF_GLOBAL=1 WF_LOGFILE=apache_server_global.txt /home/user/apache/usr/sbin/apachectl -k start -X &
sleep 2
/home/user/apache/usr/bin/ab -c $NUM_CONNECTIONS -n $NUM_REQUESTS -g ab.out.global http://localhost:8080/sample
sleep 2
/home/user/apache/usr/sbin/apachectl -k stop

echo "Generating plots ..."
mkdir -p /home/user/osdi-code-patching/data/apache/global
mkdir -p /home/user/osdi-code-patching/data/apache/global/ab_output
mkdir -p /home/user/osdi-code-patching/data/apache/local
mkdir -p /home/user/osdi-code-patching/data/apache/local/ab_output

cp apache_server_local.txt /home/user/osdi-code-patching/data/apache/local/apache_server_local.txt
cp apache_server_global.txt /home/user/osdi-code-patching/data/apache/global/apache_server_global.txt
cp ab.out.local /home/user/osdi-code-patching/data/apache/local/ab_output/apache_local_ab_output.txt
cp ab.out.global /home/user/osdi-code-patching/data/apache/global/ab_output/apache_global_ab_output.txt

cd /home/user/osdi-code-patching/data/apache
cd global/ab_output
cat apache_global_ab_output.txt | cut -f2,5 | sed 's/\t/,/g' | tail -n +2 > ../apache_global_requests.txt
cd ..
gzip apache_global_requests.txt
gzip apache_server_global.txt
cd ../local/ab_output
cat apache_local_ab_output.txt | cut -f2,5 | sed 's/\t/,/g' | tail -n +2 > ../apache_local_requests.txt
cd ..
gzip apache_local_requests.txt
gzip apache_server_local.txt
cd ../..
./update.py

echo "The graphs for apache can be found in /home/user/osdi-code-patching/data/graphs."
echo "The corresponding plot files for fig. 5 are named latency-<benchmark>.pdf, e.g. latency-apache.pdf for Apache."
