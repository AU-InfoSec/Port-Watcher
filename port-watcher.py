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
    global debug_script
    global send_email
    global email_form
    global email_pass
    global imap_username
    global nmap_location

    try:
    	config_file = open(file_location)
    	json_data   = json.load(config_file)

    	debug_script = json_data['debug_script']
    	send_email = json_data['send_email']
    	email_form = json_data['from_email']
    	email_pass = json_data['email_password']
    	imap_username = json_data['email_username']
    	nmap_location = json_data['nmap_location']

    	file_managment.logger("Config loaded.")

    	if (debug_script == True): print "Config loaded."

    except:
	file_managment.logger("Error loading config.")
	print "Error loading config."

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

def parse_nmap_xml(xml_doc, debug=False):
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
      		if debug == True:
			file_managment.logger("Getting address tag.")

	  	addr_element = host.getElementsByTagName("address")[0]
        	ip     = addr_element.getAttribute("addr")
        	ip_ver = addr_element.getAttribute("addrtype")

        	#see if host exists, create a new one if it does not
        	new_host = file_managment.get_host(str(ip), ip_ver)

        	#Open a new scan for the host
        	new_host.open_new_scan(run_time_unix, True)

        	#Parse ports from scan
		if debug == True:
			file_managment.logger("Getting ports tag.")

        	ports_tag = host.getElementsByTagName("ports")[0]
   		port_tags = ports_tag.getElementsByTagName("port")

		#Debug info for ports
		file_managment.logger("Scan found " + str(len(port_tags)) + " ports.")

        	for port in port_tags:
            		port_number = int(port.getAttribute("portid"))
            		state_tag   = port.getElementsByTagName("state")[0]
            		port_status = state_tag.getAttribute("state")

    	        	if port_status == "open":
        	        	new_host.add_open_port_to_latest_scan(port_number)
				if debug == True:
					file_managment.logger("Port " + str(port_number) + " found to be open.")

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
		file_managment.logger("Host " + str(new_host.host_ip) + " JSON updated.")

        #Return results of this scan
        return scan_results

    except Exception as e:
	#Error parsing xml
	file_managment.logger("Error in script: " + str(e))
	file_managment.logger("XML File: " + xml_doc)

	with open(xml_doc, 'r') as content_file:
    		file_managment.logger("XML File: " + content_file.read())

	return scan_results

def run_group_scan(subnets_info, group_id, full_scan=True, debug=False):
    # Get a list of subnets to scan
    subnets = subnets_info.get_subnets_by_group(group_id)

    # Compile a String list of subnets
    subnet_str_list = ""
    for subnet in subnets:
	 subnet_str_list = subnet_str_list + str(subnet.subnet) + " "

    #create log text
    if full_scan == True:
	log_text = "Group ID: " + group_id + " Full scan of subnets: " + str(subnet_str_list)
    else:
	log_text = "Group ID: " + group_id + " Top ports scan of subnets: " + str(subnet_str_list)

    if debug == True: print log_text
    file_managment.logger(log_text)

    results = run_scan(subnets, full_scan, debug)

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
	    file_managment.logger("Scanning Group: " + next_scan.group)

            for subnet in subnets_info.get_subnets_by_group(next_scan.group):
                scanned_ips.extend(subnet.get_ips())

            group_results = run_group_scan(subnets_info, next_scan.group, next_scan.full_scan, debug)
        else:
	    group_results = []

        if (len(next_scan.tags) > 0):
            if debug == True: print "Scanning Tags: " + str(next_scan.tags)
	    file_managment.logger("Scanning Tags: " + str(next_scan.tags))

            for tag in next_scan.tags:
                for subnet in subnets_info.get_subnets_by_tag(tag):
                    scanned_ips.extend(subnet.get_ips())

            tag_results = run_scan_on_tags(subnets_info, next_scan.tags, next_scan.full_scan, debug)
	else:
            tag_results = []

        #record the end time
        scan_end_time = datetime.datetime.now()
        time_delta = (str(scan_end_time - scan_start_time).split('.'))[0]
        if debug == True: print "Scanning completed, total time: " + str(time_delta)
	file_managment.logger("Scanning completed, total time: " + str(time_delta))

        #update schedule entry last run time
        if debug == True: print "Updating scan schedule..."
	file_managment.logger("Updating scan schedule...")

        next_scan.last_scan =  int(time.time())
        schedule_obj.write_schedule()
        if debug == True: print "Scan schedule updated"
	file_managment.logger("Scan schedule updated")

        #Check for mising hosts
        if debug == True: print "Finding missing hosts..."
	file_managment.logger("Finding missing hosts...")

        existing_hosts = []

	for scanned_ip in scanned_ips:
            json_file = hosts_directory + str(scanned_ip) + ".json"

            if os.path.exists(json_file):
                existing_hosts.append(str(scanned_ip))

                try:
			# Get host object
			new_host = file_managment.get_host(str(scanned_ip), "IPv4")

			# Check to see if the last scan was blank
			latest_scans = new_host.get_latest_scans()

			if latest_scans[0] is None:
				existing_hosts.remove(str(scanned_ip))
				file_managment.logger("Removing missing host: " + str(scanned_ip) + " from list, because last scan did not exist.")
			else:
				if len(latest_scans[0].open_ports) == 0:
					existing_hosts.remove(str(scanned_ip))
					file_managment.logger("Removing missing host: " + str(scanned_ip) + " from list, because last scan was empty.")

					# Open a new scan, recording that the host was not found.
					new_host.open_new_scan(str(int(time.time())), False)

					# Record new scan, with host not being found.
                			new_host.write_json()
                			file_managment.logger("Host " + str(new_host.host_ip) + " JSON updated - Host Not Found.")

		except Exception, e:
			file_managment.logger("Error creating blank scan for missing host. " + str(e))

        if (send_email == True):
            send_email    = False
            email_subject = "Port Watcher Scan For: " +  next_scan.name
            email_body    = email_subject + "\n"

	    if next_scan.full_scan == True:
		email_body += "Type: Full port scan.\n"
	    else:
		email_body += "Type: Top ports scan.\n"

            email_body   += "Time elapsed: " + time_delta + "\n\n"

	    if len(group_results) == 0 and len(tag_results[0]) == 0:
		email_body += "No changed found."
		# record no changes scan
		history_line = next_scan.name + " detected no changes and completed on " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		scan_history.append_entry(history_line)
		send_email = False

            for result in group_results:
                for host in result:
                    if (host[0] == "New Host"):
                        host_status = "New Host"
                    else:
                        host_status = ""

	            try:
		    	host_name = str(socket.gethostbyaddr(str(host[1]))[0])
		    except Exception:
			host_name = ""

                    host_info = str(host[1]) + " " + str(host_name) + " " + str(host_status) + "\n\t"
                    if str(host[1]) in existing_hosts: existing_hosts.remove(str(host[1]))

                    if (len(host[2]["New Open Ports"]) > 0 or len(host[2]["New Closed Ports"]) > 0):
                        host_info  += "New Open Ports: " + str(host[2]["New Open Ports"]) + "\n\t"
                        host_info  += "New Closed Ports: " + str(host[2]["New Closed Ports"]) + "\n"
                        email_body += host_info
                        send_email  = True
		        host_count += 1
		    else:
			host_info  += "No changes"

            for result in tag_results[0]:
                for host in result:
                    if (host[0] == "New Host"):
                        host_status = "New Host"
                    else:
                        host_status = ""

                    try:
                        host_name = str(socket.gethostbyaddr(str(host[1]))[0])
                    except Exception:
                        host_name = ""

		    host_info = str(host[1]) + " " + str(host_name) + " " + str(host_status) + "\n\t"
		    if str(host[1]) in existing_hosts: existing_hosts.remove(str(host[1]))

                    if (len(host[2]["New Open Ports"]) > 0 or len(host[2]["New Closed Ports"]) > 0):
                        host_info  += "New Open Ports: " + str(host[2]["New Open Ports"]) + "\n\t"
                        host_info  += "New Closed Ports: " + str(host[2]["New Closed Ports"]) + "\n"
                        email_body += host_info
                        send_email  = True
			host_count += 1
                    else:
                        host_info  += "No changes"

            # Output host found in previous scans, but not in latest
            if (len(existing_hosts) > 0):
                email_body += "Missing Hosts:\n\t"
                send_email  = True

                for host_ip in existing_hosts:
                    email_body += host_ip + "\n\t"

		    # Record a new blank scan since the host was not found
		    new_missing_host = file_managment.get_host(str(host_ip), "IPv4")
		    new_missing_host.open_new_scan(str(int(time.time())), False)
		    new_missing_host.write_json()
		    file_managment.logger("Host " + str(new_missing_host.host_ip) + " JSON updated - Recorded blank scan for missing host.")

	    if (host_count == 0):
		email_body += "No changes found.\n"

            #Send Email
            if (send_email == True):
                au_email.send_email('mailout.american.edu', email_form, imap_username, email_pass, 'email@domain.com', email_subject, email_body)
                if debug == True: print "Email Sent."
		file_managment.logger("Email Sent.")
            else:
                if debug == True: print "No changes, not sending email."
		file_managment.logger("No changes.")

    else:
        if debug == True: print "No scans pending."
        file_managment.logger("No scans pending.")

def run_scan(subnets, full_scan=True, debug=False):
    hosts_arr = []
    results = []

    for subnet in subnets:
        #Detect hosts for subnets in group
        run_scan_for_hosts(subnet.subnet)

        #parse the hosts scan results
        hosts_arr.extend(parse_nmap_xml_for_hosts(scan_directory + "latest_hosts_scan.xml"))

    #Scan every port of detected hosts
    for host_entry in hosts_arr:
        if full_scan == True:
                log_text = "Running full scan on host: " + host_entry[0]
        else:
                log_text = "Running top ports scan on host: " + host_entry[0]

        file_managment.logger(log_text)
        run_scan_on_host(host_entry[0])

	file_managment.logger("Parsing scan for host: " + host_entry[0])
	scan_results = parse_nmap_xml(scan_directory + "latest_scan." + str(instance_number) + ".xml")
        results.append(scan_results)

	try:
	    os.remove(scan_directory + "latest_scan." + str(instance_number) + ".xml")
	except Exception, e:
            if debug == True: print "Error deleting latest_scan.xml" + str(e)
            file_managment.logger("Error deleting latest_scan.xml" + str(e))

        if debug == True:
            print scan_results

    #remove hosts scan file
    try:
        os.remove(scan_directory + "latest_hosts_scan.xml")
    except Exception, e:
        if debug == True: print "Error deleting latest_hosts_scan.xml" + str(e)
	file_managment.logger("Error deleting latest_hosts_scan.xml" + str(e))

    return results

def run_scan_for_hosts(network):
    scan_file = scan_directory + "latest_hosts_scan.xml"

    nmap_command = str(nmap_location + " -sP " + network + " -oX " + scan_file)
    p = subprocess.Popen(nmap_command, shell=True)
    p.communicate() #wait for scan to finish

def run_scan_on_host(host_ip, full_scan=True):
    scan_file = scan_directory + "latest_scan." + str(instance_number) + ".xml"

    if full_scan == True:
	# Run the full port scan
    	#nmap_command = str(nmap_location + " -sS -p 1-65535 " + host_ip + " -oX " + scan_file)
    	nmap_command = str(nmap_location + " --top-ports 400 " + host_ip + " -oX " + scan_file)
    else:
	# Run top ports scan only
	nmap_command = str(nmap_location + " --top-ports 1000 " + host_ip + " -oX " + scan_file)

    p = subprocess.Popen(nmap_command, shell=True)
    p.communicate() #wait for scan to finish

def run_scan_on_tags(subnets_info, tags, full_scan=True, debug=False):
    subnets = []
    results = []

    #Get a list of subnets to scan
    for tag in tags:
        subnets.append(subnets_info.get_subnets_by_tag(tag))

    if debug == True: print "Subnets to scan: " + str(subnets)
    file_managment.logger("Subnets to scan: " + str(subnets))

    if len(subnets) > 0:
        for subnet in subnets:
	    if full_scan == True:
		log_text = "Full scan of " + str(subnet[0].subnet)
	    else:
		log_text = "Top ports scan of " + str(subnet[0].subnet)

            if debug == True: print log_text
	    file_managment.logger(log_text)

            scan_results = run_scan(subnet, full_scan, debug)
            results.append(scan_results)

    return results

#######################

instance_number = randint(1000,99999)
file_managment.logger("Script started, instance number: " + str(instance_number))

#Script start
script_directory = "/root/port-watcher/"
load_config_file(script_directory + "config.json")
scan_directory = script_directory + "scans/"
scan_history_file = script_directory + "scans/scan_history.txt"
hosts_directory = script_directory + "hosts/"
schedule_file = script_directory + "schedule.csv"

try:
	#Load config and data files
	schedule_obj = file_managment.schedule(schedule_file)
	subnets_info = file_managment.load_subnets_file()
	all_hosts    = file_managment.host_list()
	scan_history = file_managment.scan_history(scan_history_file)

	run_next_scan(subnets_info, schedule_obj, send_email, debug_script)
	if debug_script == True: print "Scans Completed"
	file_managment.logger("Pending scans completed.")
	file_managment.logger("Script complete.")
except Exception, e:
	file_managment.logger("Error running script: " + str(e))
	file_managment.logger("Traceback " + str(instance_number) + ": " + str(traceback.format_exc()))
