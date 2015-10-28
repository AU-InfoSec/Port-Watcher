# Port-Watcher
This script is a wrapper for NMAP, that manages a schedule and list of subnets to scan. Once a scan is complete an email is sent with a report of the latest scan.

## File Structure:

- **subnets.csv**
The list of subnets know to the script. Subnets are identified by a single group or multiple tags. 
Both group and tags must not contain spaces, tages are seperated by spaces.

- **schedule.csv**
The schedule of what subnets to scan. 
Each entry is a scan task.
A scan task can contain up to one group and zero or more tags. 
Time between scans is in hours

- **scans directory**
Directory to hold the XML output of NMAP scans. Scans are automaticaly dleted when the script is done parsing them.

- **hosts directory**
A list of JSON files, each file represents all scans performed on a host.

- **port-watcher.py**
The main script file call this file to start the next scan task.

- **report.py**
Outputs a report of all the currently open ports for all known hosts.

- **pw.log**
Logfile for script.
