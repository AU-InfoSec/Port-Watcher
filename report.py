#!/usr/bin/python

import datetime
import file_managment

# Print report header
print "Open Ports Report"
print "Report date: " + str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
print "--------------------------------"
print ""
print ""

# Load all hosts
hosts_obj = file_managment.host_list()
all_hosts = hosts_obj.hosts_list

#Get all ports open on last scan
for host_ip in all_hosts:
    print host_ip
    host_obj = file_managment.get_host(host_ip, "ipv4")
    scan_timestamp = datetime.datetime.fromtimestamp(host_obj.get_latest_scans()[0].unix_time).strftime('%Y-%m-%d %H:%M:%S')
    print "Last Scan at " + str(scan_timestamp)
    print "Open Ports:"
    print host_obj.get_latest_scans()[0].open_ports
    print "--------------------------------"
    print ""
