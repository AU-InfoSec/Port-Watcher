#!/usr/bin/python

import datetime
import ipaddr
import json
import os
import sys
import time

from sys import platform as _platform

class host_list:
    hosts_list = []

    def __init__(self):
        self.open_hosts_list()

    def add_host(self, host_ip_string, debug=False):
        if any(host_ip_string in s for s in self.hosts_list):
            #host already exists, do nothing
            if debug == True: print host_ip_string + " host already exists in host list."
        else:
            self.hosts_list.append(host_ip_string)
            self.write_host_list()
            
    def open_hosts_list(self):
        file_path = hosts_directory + "all_hosts.json"
        
        if os.path.exists(file_path):
            json_file = open(file_path)
            json_data = json.load(json_file)
            
            self.hosts_list = json_data["hosts"]; 
        else:
            # File does not exist create a blank one.
            self.hosts_list = []
            self.write_host_list();
            
    def write_host_list(self):
        file_path = hosts_directory + "all_hosts.json"
        list_obj  = {}
        list_obj["hosts"] = self.hosts_list

        with open(file_path, 'w') as outfile:
            json.dump(list_obj, outfile)

class scan_host:
    host_ip     = None
    host_names  = []
    scans       = []
    latest_scan = None
    is_new      = False
    
    def __init__(self, host_ip_string, ip_version, is_new, host_names=[]):
        self.scans  = []
        self.is_new = is_new
        self.host_names = host_names 
        
        if ip_version == "ipv4":
            self.host_ip = ipaddr.IPv4Address(host_ip_string)
        elif ip_version == "ipv6":
            self.host_ip = ipaddr.IPv6Address(host_ip_string)
        else:
            raise AssertionError("Error creating host IP")

    def __str__(self):
        port_changes = str(self.find_port_changes)
        str_result = str(self.host_ip) + " " + port_changes
        return str_result

    def add_open_port_to_latest_scan(self, port_number):
        self.latest_scan.add_open_port(port_number)

    def add_scan(self, new_scan):
        self.scans.append(new_scan)

    def find_newly_closed_ports(self):
        """Returns a list of ports no longer open in latest scan that were not open in previous scans."""
        if len(self.scans) > 1:
            latest_scans = self.get_latest_scans();
            scan0 = set(latest_scans[0].open_ports)
            scan1 = set(latest_scans[1].open_ports)
            changes = list(scan1 - scan0)

            return changes
        else:
            return []
        
    def find_newly_open_ports(self):
        """Returns a list of ports open in latest scan that were not open in previous scans."""
        if len(self.scans) > 1:
            latest_scans = self.get_latest_scans();
            
            if latest_scans[0] == None:
                scan0 = set([])
            else:
                scan0 = set(latest_scans[0].open_ports)

            if latest_scans[1] == None:
                scan1 = set([])
            else:
                scan1 = set(latest_scans[1].open_ports)
               
            changes = list(scan0 - scan1)
            
            return changes
        elif len(self.scans) == 1:
            return self.scans[0].open_ports
        else:
            return []

    def find_port_changes(self):
        open_ports   = self.find_newly_open_ports()
        closed_ports = self.find_newly_closed_ports()

        return {'New Open Ports' : open_ports, 'New Closed Ports' : closed_ports}

    def get_latest_scans(self):
        latest_time = 0
        latest_scan = None
        second_latest_scan = None
        
        for scan in self.scans:
            if scan.unix_time > latest_time:
                second_latest_scan = latest_scan
                latest_time = scan.unix_time
                latest_scan = scan

        return [latest_scan, second_latest_scan]
    
    def open_new_scan(self, unix_time):
        self.latest_scan = scan_instance(unix_time, [])
        self.scans.append(self.latest_scan)
        
    def write_json(self):
        scans_list = []
        for scan in self.scans:
            scan_obj = {}
            scan_obj["unix_time"]  = int(scan.unix_time)
            scan_obj["open_ports"] = scan.open_ports            
            scans_list.append(scan_obj)
            
        json_data = {}
        json_data["host_ip"] = str(self.host_ip)
        json_data["host_names"] = self.host_names
        json_data["scans"] = scans_list

        json_file = hosts_directory + str(self.host_ip) + ".json"
        with open(json_file, 'w') as outfile:
            json.dump(json_data, outfile)
        
class scan_instance:
    unix_time = 0;
    open_ports = []

    def __init__(self, unix_time, open_ports=[]):
        self.open_ports = open_ports
        self.unix_time  = unix_time
    
    def __str__(self):
        return str(self.open_ports)

    def add_open_port(self, port_number):
        self.open_ports.append(int(port_number))

class schedule:
    file_name = "schedule.csv"
    entries   = []
    
    def __init__(self, file_name):
        self.file_name = file_name
        self.load_schedule_file();
        
    def get_next_schedule_entry(self, debug=False):
        """Returns the next schedule entry that needs to run, returns None if there are no entries to run."""
        longest_time      = 0
        next_entry_to_run = None
        scan_count        = 0
        
        for entry in self.entries:
            time_since_last_run = (int(time.time()) - int(entry.last_scan))
            
            if (time_since_last_run > (int(entry.min_hours) * 3600)):
                if time_since_last_run > longest_time:
                    scan_count = scan_count + 1
                    longest_time = time_since_last_run
                    next_entry_to_run = entry

        if debug == True: print 'Found ' + str(scan_count) + " scan(s) pending."
	logger("Found " + str(scan_count) + " scan(s) pending.")

        return next_entry_to_run;
        
    def load_schedule_file(self):
        first_line = True
    
        with open(self.file_name, 'rb') as f:
            reader = csv.reader(f)

            for row in reader:
                if (first_line == False):
                    task_name     = row[0].strip()
                    group         = row[1].strip()
                    minimum_hours = row[3].strip()
                    last_scan     = row[4].strip()

                    if len(row[2].strip()) > 0:
                        tags = row[2].strip().split()
                    else:
                        tags = []

                    self.entries.append(schedule_entry(task_name, group, tags, minimum_hours, last_scan))
                else:
                    #Skip first line because it is documentation
                    first_line = False

    def write_schedule(self):
        csv_file = open(self.file_name, 'w')
        csv_file.write('task name, group, tags, minimum hours between scans, last scan time\n')

        for entry in self.entries:
            tags_str = ""
            for tag in entry.tags:
                tags_str = tags_str + tag + " "
                
            csv_file.write(entry.name + ", " + entry.group + ", " + tags_str + ", " + str(entry.min_hours) + ", " + str(entry.last_scan) + '\n')
                
        csv_file.close()

class schedule_entry:
    name = ""
    group = ""
    tags  = ""
    min_hours = 24
    last_scan = 0
    
    def __init__(self, name, group, tags, min_hours, last_scan):
        self.name = name
        self.group = group
        self.tags  = tags
        self.min_hours = min_hours
        self.last_scan = last_scan

    def __str__(self):
        return "Name: " + self.name + " - Group: " + self.group + " - Tags: " + str(self.tags) + " - Frequency: " + self.min_hours + "h"
    
class subnets_data:
    subnets = []

    def __init__(self):
        self.subnets = []

    def __str__(self):
        return_val = ""

        for subnet in self.subnets:
            c_subnet = subnet.subnet + ", " + subnet.group + ", " + subnet.tag + ", " + subnet.comment
            return_val = return_val + c_subnet + "\n"

        return return_val

    def append(self, subnet_info):
        self.subnets.append(subnet_info)

    def get_ips(self):
        ips = []
        
        for subnet in self.subnets:
            ips.extend(subnet.get_ips())

        return ips
    
    def get_subnets_by_group(self, group):
        subnets_in_group = []
        
        for subnet in self.subnets:
            if subnet.group == group:
                subnets_in_group.append(subnet)
                
        return subnets_in_group

    def get_subnets_by_tag(self, tag):
        subnets_with_tag = []

        for subnet in self.subnets:
            if tag.lower() != 'none':
                if tag.lower() in subnet.tag.lower():
                    subnets_with_tag.append(subnet)

        return subnets_with_tag
        
class subnet_info:
    subnet  = '127.0.0.0/32' 
    group   = 'local hosts'
    tag     = 'local'
    comment = 'local machine'

    def __init__(self, subnet, group, tag, comment):
        self.subnet  = subnet
        self.group   = group 
        self.tag     = tag
        self.comment = comment
        
    def __str__(self):
        return self.subnet + ", " + self.group + ", " + self.tag + ", " + self.comment

    def get_ips(self):
        ips = []
        for ip in ipaddr.IPv4Network(self.subnet).iterhosts():
            ips.append(str(ip))
            
        return ips

def get_host(ip_str, ip_ver):
    host_filename = hosts_directory + ip_str + ".json"
    
    if os.path.isfile(host_filename):
        file_data = open(host_filename)
        json_data = json.load(file_data)

        host_ip    = json_data['host_ip']
        scans      = json_data['scans']
        host_names = json_data['host_names']
        host_obj   = scan_host(host_ip, ip_ver, False, host_names)

        for scan in scans:
            unix_time  = scan['unix_time']
            open_ports = scan['open_ports']
            new_scan   = scan_instance(unix_time, open_ports)
            host_obj.add_scan(new_scan)
    else:
        host_obj = scan_host(ip_str, ip_ver, True)

    return host_obj

def load_subnets_file():
    first_line   = True
    subnets_file = "/root/port-watcher/subnets.csv"
    subnets_db   = subnets_data()
    
    with open(subnets_file, 'rb') as f:
        reader = csv.reader(f)

        for row in reader:
            if (first_line == False):
                subnet   = row[0].strip()
                group    = row[1].strip()
                tag      = row[2].strip()
                comment  = row[3].strip()
                c_subnet = subnet_info(subnet, group, tag, comment)
                
                subnets_db.append(c_subnet)
            else:
                #Skip first line because it is documentation
                first_line = False

    return subnets_db

def logger(log_text):
    log_entry = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S') + "\t" + log_text

    with open("/root/port-watcher/pw.log", "a") as myfile:
        myfile.write(log_entry)
	myfile.write('\n')

#######################

#Script start
if (len(sys.argv[0]) < 1):
    script_dir = "/root/port-watcher"
else:
    script_dir = "/root/port-watcher"

scan_directory = script_dir + "/scans/"
hosts_directory = script_dir + "/hosts/"
schedule_file = script_dir +  "/schedule.csv"

print hosts_directory
