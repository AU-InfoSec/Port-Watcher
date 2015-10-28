#!/usr/bin/python

import au_email
import csv
import datetime
import ipaddr
import file_managment
import json
import os
import socket
import subprocess
import sys
import time
import traceback

from random import randint
from sys import platform as _platform
from xml.dom import minidom


def load_config_file(file_location):
    config_file = open(file_location)
    json_data   = json.load(config_file)

    global debug_script
    global send_email
    global email_form
    global email_pass
    global imap_username 

    debug_script = json_data['debug_script']
    send_email = json_data['send_email']
    email_form = json_data['from_email']
    email_pass = json_data['email_password']
    imap_username = json_data['email_username']

    logger("Config loaded")

def parse_nmap_xml_for_hosts(xml_doc):
    hosts_array = []
    doc = minidom.parse(xml_doc)
    nmaprun_tag = doc.getElementsByTagName("nmaprun")[0]

    # Find all hosts from scan
    for host in doc.getElementsByTagName("host"):
        addr_element = host.getElementsByTagName("address")[0]
        ip = addr_element.getAttribute("addr")
        
	try:
		ip_ver = addr_element.getAttribute("addrtype")
        except Exception as e:
		ip_ver = "IPv4"

	hosts_array.append([ip, ip_ver])

    return hosts_array

def parse_nmap_xml(xml_doc):
    scan_results = []
    
    # Parse Scan Information
    try:
    	doc = minidom.parse(xml_doc)
    	for nmaprun_tag in doc.getElementsByTagName("nmaprun"):
    	    try:
		run_time_unix = int(nmaprun_tag.getAttribute("start"))
	    except Exception as e:
		run_time_unix = int(time.time())    
	
    	    # Find all hosts from scan
    	    for host in doc.getElementsByTagName("host"):
      		logger("Getting address tag.")
	  	addr_element = host.getElementsByTagName("address")[0]
        	ip     = addr_element.getAttribute("addr")
        	ip_ver = addr_element.getAttribute("addrtype")
		
        	#see if host exists, create a new one if it does not
        	new_host = get_host(str(ip), ip_ver)
		
        	#Open a new scan for the host
        	new_host.open_new_scan(run_time_unix)
        	
        	#Parse ports from scan
		logger("Getting ports tag.")
        	ports_tag = host.getElementsByTagName("ports")[0]
   		port_tags = ports_tag.getElementsByTagName("port")
 
		#Debug info for ports
		logger("Scan found " + str(len(port_tags)) + " ports.")    
	
        	for port in port_tags:
            		port_number = int(port.getAttribute("portid"))
            		state_tag   = port.getElementsByTagName("state")[0]
            		port_status = state_tag.getAttribute("state")
            		
    	        	if port_status == "open":
        	        	new_host.add_open_port_to_latest_scan(port_number)
				logger("Port " + str(port_number) + " found to be open.")

        	#Record if new host, or new ports are found
        	port_changes = new_host.find_port_changes()
		
        	if new_host.is_new == True:
            		#Newly found host
            		scan_results.append(["New Host", new_host.host_ip, port_changes])
            		all_hosts.add_host(str(new_host.host_ip))
        	else:
            		#Port Changes found
            		scan_results.append(["Port Changes", new_host.host_ip, port_changes])

        	#Ports loaded, save updates
        	new_host.write_json()
		logger("Host " + str(new_host.host_ip) + " JSON updated.")

        #Return results of this scan
        return scan_results

    except Exception as e:
	#Error parsing xml
	logger("Error in script: " + str(e))
	logger("XML File: " + xml_doc)
	
	with open(xml_doc, 'r') as content_file:
    		logger("XML File: " + content_file.read())

	return scan_results
	
def run_group_scan(subnets_info, group_id, debug=False):
    #Get a list of subnets to scan
    subnets = subnets_info.get_subnets_by_group(group_id) 
    if debug == True: print "Subnets to scan: " + str(len(subnets))
    logger("Subnets to scan: " + str(len(subnets)))

    results = run_scan(subnets, debug)

    return results

def run_next_scan(subnets_info, schedule_obj, send_email=True, debug=False):
    scanned_ips = []
    host_count  = 0
    
    #get next scan and run it
    next_scan = schedule_obj.get_next_schedule_entry(debug)

    if (next_scan != None):
        #record the start time
        scan_start_time = datetime.datetime.now()

        if debug == True: print str(next_scan)

        if (len(next_scan.group) > 0):
            if debug == True: print "Scanning Group: " + next_scan.group
	    logger("Scanning Group: " + next_scan.group)

            for subnet in subnets_info.get_subnets_by_group(next_scan.group):
                scanned_ips.extend(subnet.get_ips())

            group_results = run_group_scan(subnets_info, next_scan.group, debug)
        else:
	    group_results = []
 
        if (len(next_scan.tags) > 0):
            if debug == True: print "Scanning Tags: " + str(next_scan.tags)
	    logger("Scanning Tags: " + str(next_scan.tags))

            for tag in next_scan.tags:
                for subnet in subnets_info.get_subnets_by_tag(tag):
                    scanned_ips.extend(subnet.get_ips())
                
            tag_results = run_scan_on_tags(subnets_info, next_scan.tags, debug)
	else:
            tag_results = []

        #record the end time
        scan_end_time = datetime.datetime.now()
        time_delta = (str(scan_end_time - scan_start_time).split('.'))[0]
        if debug == True: print "Scanning completed, total time: " + str(time_delta)
	logger("Scanning completed, total time: " + str(time_delta))
        
        #update schedule entry last run time
        if debug == True: print "Updating scan schedule..."
	logger("Updating scan schedule...")

        next_scan.last_scan =  int(time.time())
        schedule_obj.write_schedule()
        if debug == True: print "Scan schedule updated"
	logger("Scan schedule updated")
        
        #Check for mising hosts
        if debug == True: print "Finding missing hosts..."
	logger("Finding missing hosts...")

        existing_hosts = []
        
	for scanned_ip in scanned_ips:
            json_file = hosts_directory + str(scanned_ip) + ".json"
            
            if os.path.exists(json_file):
                existing_hosts.append(str(scanned_ip))
                try:
			temp_host = scan_host(str(scanned_ip), "IPv4", false)
			temp_host.write_json(); 		
 		except Exception: 
			logger("Error creating blank scan for missing host.")	

        if (send_email == True):
            # send_email    = False
            email_subject = "Port Watcher Scan For: " +  next_scan.name
            email_body    = email_subject + "\n"
            email_body   += "Time elapsed: " + time_delta + "\n\n"
            
	    if len(group_results) == 0 and len(tag_results[0]) == 0:
		email_body += "No changed found."

            for result in group_results: 
                for host in result:
                    if (host[0] == "New Host"):
                        host_status = "New Host"
                    else:
                        host_status = ""

		    host_name = socket.gethostbyaddr(str(host[1]))
		    host_info = str(host[1]) + " " + host_name + " " + host_status + "\n\t"
                    if str(host[1]) in existing_hosts: existing_hosts.remove(str(host[1]))

                    if (len(host[2]["New Open Ports"]) > 0 or len(host[2]["New Closed Ports"]) > 0):
                        host_info  += "New Open Ports: " + str(host[2]["New Open Ports"]) + "\n\t"
                        host_info  += "New Closed Ports: " + str(host[2]["New Closed Ports"]) + "\n"
                        email_body += host_info
                        send_email  = True
		        host_count += 1
		    else:
			host_info  += "No changes"
			send_email  = True

            for result in tag_results[0]:
                for host in result:
                    if (host[0] == "New Host"):
                        host_status = "New Host"
                    else:
                        host_status = ""

		    host_info = str(host[1]) + " " + host_status + "\n\t"
		    if str(host[1]) in existing_hosts: existing_hosts.remove(str(host[1]))

                    if (len(host[2]["New Open Ports"]) > 0 or len(host[2]["New Closed Ports"]) > 0):
                        host_info  += "New Open Ports: " + str(host[2]["New Open Ports"]) + "\n\t"
                        host_info  += "New Closed Ports: " + str(host[2]["New Closed Ports"]) + "\n"
                        email_body += host_info
                        send_email  = True
			host_count += 1
                    else:
                        host_info  += "No changes"
                        send_email  = True

            # Output host found in previous scans, but not in latest
            if (len(existing_hosts) > 0):
                email_body += "Missing Hosts:\n\t"
                send_email  = True
                
                for host_ip in existing_hosts:
                    email_body += host_ip + "\n\t"

	    if (host_count == 0):
		email_body += "No changes found.\n"
                
            #Send Email
            if (send_email == True):
                au_email.send_email('mailout.american.edu', email_form, imap_username, email_pass, 'security@american.edu', email_subject, email_body)
                if debug == True: print "Email Sent."
		logger("Email Sent.")
            else:
                if debug == True: print "No changes, not sending email."
		logger("No changes.")            	

    else:
        if debug == True: print "No scans pending."
        logger("No scans pending.")

def run_scan(subnets, debug=False):
    hosts_arr = []
    results = []
    
    for subnet in subnets:
        #Detect hosts for subnets in group
        run_scan_for_hosts(subnet.subnet) 
    
        #parse the hosts scan results
        hosts_arr.extend(parse_nmap_xml_for_hosts(scan_directory + "latest_hosts_scan.xml"))

    #Scan every port of detected hosts
    for host_entry in hosts_arr:
	logger("Running scan on host: " + host_entry[0])
        run_scan_on_host(host_entry[0])
        
	logger("Parsing scan for host: " + host_entry[0])
	scan_results = parse_nmap_xml(scan_directory + "latest_scan." + str(instance_number) + ".xml")
        results.append(scan_results)
        
	try:
	    os.remove(scan_directory + "latest_scan." + str(instance_number) + ".xml")
	except Exception, e:
            if debug == True: print "Error deleting latest_scan.xml" + str(e)
            logger("Error deleting latest_scan.xml" + str(e))

        if debug == True:
            print scan_results
        
    #remove hosts scan file
    try:
        os.remove(scan_directory + "latest_hosts_scan.xml")
    except Exception, e:
        if debug == True: print "Error deleting latest_hosts_scan.xml" + str(e)
	logger("Error deleting latest_hosts_scan.xml" + str(e))
        
    return results

def run_scan_for_hosts(network):
    scan_file = scan_directory + "latest_hosts_scan.xml"
    
    nmap_command = str(nmap_location + " -sP " + network + " -oX " + scan_file)
    p = subprocess.Popen(nmap_command, shell=True)
    p.communicate() #wait for scan to finish

def run_scan_on_host(host_ip):
    scan_file = scan_directory + "latest_scan." + str(instance_number) + ".xml"
    nmap_command = str(nmap_location + " -sS -p 1-65535 " + host_ip + " -oX " + scan_file)
    # nmap_command = str(nmap_location + " --top-ports 25 " + host_ip + " -oX " + scan_file)

    p = subprocess.Popen(nmap_command, shell=True)
    p.communicate() #wait for scan to finish

def run_scan_on_tags(subnets_info, tags, debug=False):
    subnets = []
    results = []
    
    #Get a list of subnets to scan
    for tag in tags:
        subnets.append(subnets_info.get_subnets_by_tag(tag))   

    if debug == True: print "Subnets to scan: " + str(subnets)
    logger("Subnets to scan: " + str(subnets))

    if len(subnets) > 0:
        for subnet in subnets:
            if debug == True: print "Scanning: " + str(subnet)
	    logger("Scanning: " + str(subnet))
            scan_results = run_scan(subnet, debug)
            results.append(scan_results)

    return results

#######################

logger("Script started.")

#NMAP Locations
nmap_osx      = "/usr/local/bin/nmap"
nmap_ubuntu   = "/usr/bin/nmap"
nmap_windows  = ""
nmap_location = ""

#Script start
load_config_file("/root/port-watcher/config.json")
scan_directory = "/root/port-watcher/scans/"
hosts_directory = "/root/port-watcher/hosts/"
schedule_file = "/root/port-watcher/schedule.csv"
instance_number = randint(1000,99999)

# Determin OS
if _platform == "linux" or _platform == "linux2":
    # linux
    nmap_location = nmap_ubuntu
elif _platform == "darwin":
    # OS X
    nmap_location = nmap_osx
elif _platform == "win32":
    # Windows
    nmap_location = nmap_windows

try:
	#Load config and data files    
	schedule_obj = schedule(schedule_file) 
	subnets_info = load_subnets_file()
	all_hosts    = host_list()

	run_next_scan(subnets_info, schedule_obj, send_email, debug_script)
	if debug_script == True: print "Scans Completed"
	logger("Pending scans completed.")
	logger("Script complete.")
except Exception, e: 
	logger("Error running script: " + str(e))
	logger("Traceback: " + str(traceback.format_exc()))
