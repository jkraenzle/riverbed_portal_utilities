# Python-wrapped REST API utilities for AppResponse 11

import os
import sys
import requests
import time
import argparse
import json
import getpass
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Avoid warnings for insecure certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

AR11_UTILITIES_ACTIONS = [ "list_backups", \
			   "pull_backup", \
			   "delete_backup", \
			   "upload_backup", \
			   "restore", \
			   "restore_status" ]

##### HELPER FUNCTIONS
### jkraenzle: Update to be used by each call
# Run REST APIs to appliance and return result
# Assume 'payload' is JSON formatted
def portal_rest_api (action, path, appliance, access_token, version, payload = None, data = None, additional_headers = None):

	url = "https://" + appliance + path 

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	if additional_headers != None:
		headers.update (additional_headers)

	if (action == "GET"):
		r = requests.get (url, headers=headers, verify=False)
	elif (action == "POST"):
		if payload != None:
			r = requests.post (url, headers=headers, data=json.dumps (payload), verify=False)
		else:
			r = requests.post (url, headers=headers, data=data, verify=False)
	elif (action == "PUT"):
		r = requests.put (url, headers=headers, data=json.dumps (payload), verify=False)
	elif (action == "DELETE"):
		r = requests.delete (url, headers=headers, verify=False)

	if (r.status_code not in [200, 201, 202, 204]):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
		result = None
	else:
		if (("Content-Type" in r.headers.keys ()) and ("application/json" in r.headers ["Content-Type"])):
			result = json.loads (r.content) 
		elif (("Content-Type" in r.headers.keys ()) and ("application/x-gzip" in r.headers ["Content-Type"])):
			result = r.content
		else:
			result = r.text

	return result 


##### BACKUP #####

def portal_backups_list (appliance, access_token, version):

	backup_list = portal_rest_api ("GET", "/api/npm.backup/1.0/backups", appliance, access_token, version)
	
	return backup_list ["items"]

# REST API Python wrapper to create backup on appliance
def portal_backup_create (appliance, access_token, version):

	# Kick off backup and give time to process
	payload = {"description": "Automated Backup"}

	backup_in_process = portal_rest_api ("POST", "/api/npm.backup/1.0/backups", appliance, access_token, version, payload)

	# If backup creation failed, return upstream showing the failure
	if (backup_in_process == None):
		return None

	# Get backup id and sleep so there's time for backup to initially create
	backup_id = backup_in_process ["id"]
	time.sleep (5)

	# Keep checking if backup has completed
	backup_complete = False
	while (backup_complete == False):
		backups = portal_backups_list (appliance, access_token, version)

		found = False
		for backup in backups:
			if (backup ["id"] == backup_id):
				found = True
				if (backup ["status"] == "completed"):
					backup_complete = True

		# If backup "id" is not found on appliance
		if (found == False):
			print ("Error starting backup on %s" % appliance)
			return None
		elif (backup_complete == False):
			time.sleep (2)

	return backup_id

def portal_backup_delete (appliance, access_token, version, backup_id):

	empty_result = portal_rest_api ("DELETE", "/api/npm.backup/1.0/backups/items/" + backup_id, appliance, access_token, version)

	return empty_result

# REST API Python wrapper to download and delete automated backup
def portal_backup_download_and_delete (appliance, access_token, version, backup_id):
	backup_file = portal_rest_api ("GET", "/api/npm.backup/1.0/backups/items/" + backup_id + "/file", appliance, access_token, version)

	if (backup_file != None):
		with open (appliance + ".backup.tgz", "wb") as backup_f:
			backup_f.write (backup_file)
	
	empty_result = portal_backup_delete (appliance, access_token, version, backup_id)

	return empty_result

# REST API Python wrapper to create and pull backup from appliance
def portal_backup_get (appliance, access_token, version):
	backup_id = portal_backup_create (appliance, access_token, version)

	if (backup_id != None):
		empty_result = portal_backup_download_and_delete (appliance, access_token, version, backup_id)
		print (empty_result)
		return True
	else:
		return False

def portal_backup_upload (appliance, access_token, version, backup_file):
	data = backup_file.read ()

	backup = portal_rest_api ("POST", "/api/npm.backup/1.0/backups/upload", appliance, access_token, version, additional_headers={'Content-Type': 'application/octet-stream'}, data=data)

	return backup

def portal_backup_restore (appliance, access_token, version, id):
	backup_restore_status = portal_rest_api ("POST", "/api/npm.backup/1.0/backups/items/" + id + "/restore", appliance, access_token, version)

	return backup_restore_status

def portal_backup_restore_status (appliance, access_token, version):
	backup_restore_status = portal_rest_api ("GET", "/api/npm.backup/1.0/restore_status", appliance, access_token, version)

	return backup_restore_status

##### GENERAL FUNCTIONS

# REST API Python wrapper to authenticate to the server (Login)
# URL: https://<appliance>/api/mgmt.aaa/1.0/token ; pre-version 11.6
# URL: https://<appliance>/api/mgmt.aaa/2.0/token ; version 11.6 or later
# Header: Content-Type:application/json
# Body: {"user_credentials":{"username":<username>, "password":<password>},"generate_refresh_token":"true"}
def portal_authenticate (appliance, username, password, version):

	if (version in ["11.4", "11.5"]):
		url = "https://" + appliance + "/api/mgmt.aaa/1.0/token"
	else:
		url = "https://" + appliance + "/api/mgmt.aaa/2.0/token"
	credentials = {"username":username, "password":password}
	payload = {"user_credentials":credentials, "generate_refresh_token":False}
	headers = {"Content-Type":"application/json"}

	r = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)

	if (r.status_code != 201):
		print ("Status code was %s" % r.status_code)
		print ("Error %s" % r.content)
		return None, None
	else:
		result = json.loads(r.content)

	return result["access_token"]

# Helper function to get list of hostnames from input
def hostnamelist_get (hostnamelist):
	hostnamelist_f = open (hostnamelist, 'r')

	output = []
	for row in hostnamelist_f:
		hostname = row.rstrip()
		output.append (hostname)

	hostnamelist_f.close ()

	return output

# REST API Python wrapper to request version information
# URL: https://<appliance>/api/common/1.0/info
# Header: AUthorization: Bearer <access_token>
def portal_version_get (appliance, access_token, version):
	url = "https://" + appliance + "/api/common/1.0/info"
	
	r = requests.get (url, verify=False)

	result = json.loads(r.content)

	version_str = result["sw_version"]
	
	if "11.4" in version_str:
		return "11.4"
	elif "11.5" in version_str:
		return "11.5"
	elif "11.6" in version_str:
		return "11.6"
	elif "11.7" in version_str:
		return "11.7"
	elif "11.8" in version_str:
		return "11.8"
	elif "11.9" in version_str:
		return "11.9"
	elif "11.10" in version_str:
		return "11.10"

	return "11.10"

def main():
	# set up arguments in appropriate variables
	parser = argparse.ArgumentParser (description="Python utilities to automate information collection or \
		 configuration tasks within AppResponse 11 environments")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse 11 appliance")
	parser.add_argument('--hostnamelist', help="File containing hostnames or IP addresses, one per line")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password for the username")
	parser.add_argument('--action', help="Action to perform: %s" % AR11_UTILITIES_ACTIONS)
	parser.add_argument('--actionfile', help="Settings file associated with action")
	args = parser.parse_args()

	# Check inputs for required data and prep variables
	if (args.hostname == None or args.hostname == "") and (args.hostnamelist == None or args.hostnamelist == ""):
		print ("Please specify a hostname using --hostname or a list of hostnames in a file using --hostnamelist")
		return
	if (args.username == None or args.username == ""):
		print ("Please specify a username using --username")
		return
	if (args.action == None or args.action == ""):
		print ("Please specify an action using --action")
		return

	# Use either hostname or hostname list; if both are accidentally specified, use hostname list
	if not(args.hostname == None or args.hostname == ""):
		hostnamelist = [args.hostname]
	elif not(args.hostnamelist == None or args.hostnamelist == ""):
		hostnamelist = hostnamelist_get (args.hostnamelist)

	# Check that action exist in set of known actions
	if not (args.action in AR11_UTILITIES_ACTIONS):
		print ("Action %s is unknown" % args.action)

	if (args.password == None or args.password == ""):
		print ("Please provide password for account %s" % args.username)
		password = getpass.getpass ()
	else:
		password = args.password

	# Loop through hosts, applying 'action'
	for hostname in hostnamelist:
		version = portal_version_get (hostname, args.username, password)

		access_token = portal_authenticate (hostname, args.username, password, version)

		if (access_token == None or access_token == ""):	
			print ("Failed to login to %s" % hostname)
			continue
	
		# ACTION - list_backups
		elif (args.action == "list_backups"):
			backups_list = portal_backups_list (hostname, access_token, version)
			print (backups_list)
	
		# ACTION - pull_backup
		elif (args.action == "pull_backup"):
			backup = portal_backup_get (hostname, access_token, version)

			if (backup == True):
				print ("Backup for %s was successful!" % (hostname))
			else:
				print ("Backup for %s was unsuccessful!" % (hostname))

		# ACTION - delete backup
		elif (args.action == "delete_backup"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify an ID for the filename on the appliance that you would like to restore in --actionfile parameter")
			else:
				id = args.actionfile
			backup = portal_backup_delete (hostname, access_token, version, id)

		# ACTION - upload_backup
		elif (args.action == "upload_backup"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify a filename for backup upload in --actionfile parameter")
			
			backup = None
			with open(args.actionfile, 'rb') as backup_file:
				backup = portal_backup_upload (hostname, access_token, version, backup_file)

			print (backup)

		elif (args.action == "restore"):
			if (args.actionfile == None or args.actionfile == ""):
				print ("Please specify an ID for the filename on the appliance that you would like to restore in --actionfile parameter")
			else:
				id = args.actionfile
			restore_status = portal_backup_restore (hostname, access_token, version, id)

			print(restore_status)
				
		elif (args.action == "restore_status"):
			
			status = portal_backup_restore_status (hostname, access_token, version)

			print (status)


if __name__ == "__main__":
	main()
