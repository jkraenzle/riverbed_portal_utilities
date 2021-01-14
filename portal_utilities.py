# Python-wrapped REST API utilities for AppResponse 11

from typing import Any, IO
import yaml
import os
import sys
import requests
import time
import argparse
import json
import getpass
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Avoid warnings for insecure certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

PORTAL_UTILITIES_ACTIONS = [ "list_backups", \
			   "pull_backup", \
			   "delete_backup", \
			   "upload_backup", \
			   "restore", \
			   "restore_status" ]
PORTAL_UTILITIES_SCRIPT_TIMEOUT = 60

# ---- YAML helper functions -----
# Define YAML Loader, as default Loader is not safe
class YAMLLoader(yaml.SafeLoader):
    """YAML Loader with `!include` constructor."""

    def __init__(self, stream: IO) -> None:
        """Initialise Loader."""

        try:
            self._root = os.path.split(stream.name)[0]
        except AttributeError:
            self._root = os.path.curdir

        super().__init__(stream)


def construct_include(loader: YAMLLoader, node: yaml.Node) -> Any:
    """Include file referenced at node."""

    filename = os.path.abspath(os.path.join(loader._root, loader.construct_scalar(node)))
    extension = os.path.splitext(filename)[1].lstrip('.')

    with open(filename, 'r') as f:
        if extension in ('yaml', 'yml'):
            return yaml.load(f, YAMLLoader)


yaml.add_constructor('!include', construct_include, YAMLLoader)

def yamlread (fn):
	try:
		if fn != None:
			with open(fn) as fh:
				yamlresult = yaml.load (fh, YAMLLoader)
		else:
			yamlresult = None
	except FileNotFoundError:
		yamlresult = None

	return yamlresult

# -----

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

	empty_result = portal_rest_api ("DELETE", "/api/npm.backup/1.0/backups/items/" + str(backup_id), appliance, access_token, version)

	return empty_result

# REST API Python wrapper to download and delete automated backup
def portal_backup_download_and_delete (appliance, access_token, version, backup_id):
	backup_file = portal_rest_api ("GET", "/api/npm.backup/1.0/backups/items/" + backup_id + "/file", appliance, access_token, version)

	filename = appliance + ".backup.tgz"
	if (backup_file != None):
		with open (filename, "wb") as backup_f:
			backup_f.write (backup_file)
	
	empty_result = portal_backup_delete (appliance, access_token, version, backup_id)

	return empty_result, filename

# REST API Python wrapper to create and pull backup from appliance
def portal_backup_get (appliance, access_token, version):
	backup_id = portal_backup_create (appliance, access_token, version)

	if (backup_id != None):
		empty_result,filename = portal_backup_download_and_delete (appliance, access_token, version, backup_id)
		return True,filename
	else:
		return False,filename

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
		return None
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
	
	return version_str


def run_action(hostname, username, password, action, actionfile):

	# Check inputs for required data and prep variables
	if (hostname == None or hostname == ""):
		print ("Please specify a hostname using --hostname")
		return
	if (username == None or username == ""):
		print ("Please specify a username using --username")
		return
	if (action == None or action == ""):
		print ("Please specify an action using --action")
		return

	# Check that action exist in set of known actions
	if not action in PORTAL_UTILITIES_ACTIONS:
		print ("Action %s is unknown" % action)

	if (password == None or password == ""):
		print ("Please provide password for account %s on %s" % username, hostname)
		password = getpass.getpass ()

	# Loop through hosts, applying 'action'
	version = portal_version_get (hostname, username, password)

	access_token = portal_authenticate (hostname, username, password, version)

	if (access_token == None or access_token == ""):	
		print ("Failed to login to %s. Terminating action ..." % hostname)
		return
	
	# ACTION - list_backups
	elif (action == "list_backups"):
		backups_list = portal_backups_list (hostname, access_token, version)
		print (backups_list)
	
	# ACTION - pull_backup
	elif (action == "pull_backup"):
		backup,filename = portal_backup_get (hostname, access_token, version)

		if (backup == True):
			print ("Backup for %s was successful!" % (hostname))
		else:
			print ("Backup for %s was unsuccessful!" % (hostname))

	# ACTION - delete backup
	elif (action == "delete_backup"):
		if (actionfile == None or actionfile == ""):
			print ("Please specify an ID for the filename on the appliance that you would like to restore in --actionfile parameter")
		else:
			id = actionfile
		backup = portal_backup_delete (hostname, access_token, version, id)

	# ACTION - upload_backup
	elif (action == "upload_backup"):
		if (actionfile == None or actionfile == ""):
			print ("Please specify a filename for backup upload in --actionfile parameter")
		
		backup = None
		with open(actionfile, 'rb') as backup_file:
			backup = portal_backup_upload (hostname, access_token, version, backup_file)

		print (backup)

	elif (action == "restore"):
		if (actionfile == None or actionfile == ""):
			print ("Please specify an ID for the filename on the appliance that you would like to restore in --actionfile parameter")
		else:
			id = actionfile
		restore_status = portal_backup_restore (hostname, access_token, version, id)

		print(restore_status)
				
	elif (action == "restore_status"):
			
		status = portal_backup_restore_status (hostname, access_token, version)

		print (status)

	return

def portal_credentials_get (filename):

	credentials = yamlread (filename)	
	
	src_hostname = None
	if 'src_hostname' in credentials:
		src_hostname = credentials['src_hostname'] 
	src_username = None
	if 'src_username' in credentials:
		src_username = credentials['src_username'] 
	dst_hostname = None
	if 'dst_hostname' in credentials:
		dst_hostname = credentials['dst_hostname'] 
	dst_username = None
	if 'dst_username' in credentials:
		dst_username = credentials['dst_username'] 

	# Allow for testing, but the expectation is that this is not included in YAML
	src_password = None
	if 'src_password' in credentials:
		src_password = credentials['src_password']
	dst_password = None
	if 'dst_password' in credentials:
		dst_password = credentials['dst_password']

	return src_hostname, src_username, src_password, dst_hostname, dst_username, dst_password

def run_from_yaml(config):

	src_hostname, src_username, src_password, dst_hostname, dst_username, dst_password = portal_credentials_get(config)

	# Login to source and destination Portals to confirm the passwords are correct before proceeding
	if src_password == None or src_password == "":
		print("Please provide password for account %s on %s" % (src_username, src_hostname))
		src_password = getpass.getpass()
	src_version = portal_version_get(src_hostname, src_username, src_password)
	src_access_token = portal_authenticate(src_hostname, src_username, src_password, src_version)
	if src_access_token == None:
		print("Authentication failed to Portal %s. Terminating script ..." % src_hostname)
		return

	if dst_password == None or dst_password == "":
		print("Please provide password for account %s on %s" % (dst_username, dst_hostname))
		dst_password = getpass.getpass()
	dst_version = portal_version_get (dst_hostname, dst_username, dst_password)
	if src_version != dst_version:
		print("Source version %s on Portal %s differs from destination version %s on Portal %s! Terminating script ..." % (src_version, src_hostname, dst_version, dst_hostname))
		return

	dst_access_token = portal_authenticate (dst_hostname, dst_username, dst_password, dst_version)
	if dst_access_token == None:
		print("Authentication failed to Portal %s. Terminating script ..." % dst_hostname)

	# Save the current timestamp for future comparison to restore time
	current_time = datetime.now().timestamp()

	print("Checking backup space availability on Portal %s." % src_hostname)
	# Check the current list of primary Portal backups (list_backups)
	backups_list = portal_backups_list (src_hostname, src_access_token, src_version)

	# If there are two, delete oldest as only allowed to store two at a time on the Portal appliance (delete_backup)
	if len(backups_list) > 0:
		if len(backups_list) == 2:
			# Get ID of oldest backup
			timestamp_0 = backups_list[0]['backup_time']
			timestamp_1 = backups_list[1]['backup_time']
			if timestamp_0 < timestamp_1:
				id = backups_list[0]['id']
			else:
				id = backups_list[1]['id']

			print("Deleting oldest backup to create available space on Portal %s." % src_hostname)
			delete_status = portal_backup_delete(src_hostname, src_access_token, src_version, id)

	# Create, download, and delete a backup of the Portal at a current time (pull_backup)
	backup_status,backup_filename = portal_backup_get(src_hostname, src_access_token, src_version)
	if backup_status == False:
		print("Portal %s backup failed. Terminating script ..." % src_hostname)
		return
	else:
		print("Backup file %s created and downloaded for Portal %s" % (backup_filename, src_hostname))

	# Check if there is available space on the secondary instance (list_backups)
	print("Checking space on Portal %s to upload backup." % dst_hostname)
	backups_list = portal_backups_list (dst_hostname, dst_access_token, dst_version)

	# If there are two, delete oldest as only allowed to store two at a time on the Portal appliance (delete_backup)
	if len(backups_list) > 0:
		if len(backups_list) == 2:
			# Get ID of oldest backup
			timestamp_0 = backups_list[0]['backup_time']
			timestamp_1 = backups_list[1]['backup_time']
			if timestamp_0 < timestamp_1:
				id = backups_list[0]['id']
			else:
				id = backups_list[1]['id']

			print("Deleting oldest backup to create available space on Portal %s." % dst_hostname)
			delete_status = portal_backup_delete(dst_hostname, dst_access_token, dst_version, id)
	
	# Upload the backup to the secondary instance (upload_backup)
	upload_status = None
	with open(backup_filename,'rb') as backup_file:
		upload_status = portal_backup_upload(dst_hostname, dst_access_token, dst_version, backup_file)
		if 'id' in upload_status:
			id = upload_status['id']
			print("Upload succeeded to Portal %s." % dst_hostname)
		else:
			print("Upload to Portal %s failed." % dst_hostname)
			return

	# Restore the uploaded backup on the secondary instance (restore)
	print("Beginning restore process on Portal %s." % dst_hostname)
	restore_result = portal_backup_restore(dst_hostname, dst_access_token, dst_version, id)

	# Use the restore_status to keep checking the status every minute, even if it times out and fails to return while rebooting, until the restore status shows as 'completed' (restore_status) and the 'last_restore_time' is past the start of the script; or you potentially hit a timeout in your script (30 minutes?)
	not_complete = True
	start_time = datetime.now()
	while not_complete:
		restore_status = portal_backup_restore_status (dst_hostname, dst_access_token, dst_version)
		if restore_status['status'] == 'completed':
			not_complete = False
			if restore_status['last_restore_time'] > current_time:
				print("Restore completed on Portal %s!" % dst_hostname)
		else:
			print("Restore on %s has been running for %d minutes. Status: %s" % (dst_hostname, (datetime.now()-start_time).seconds/60, restore_status['status_message']))
			time.sleep(60)

		if ((datetime.now() - start_time).seconds / 60) > PORTAL_UTILITIES_SCRIPT_TIMEOUT:
			print("Script has hit time limit without restore completion. Please check Portal console for restore status. Terminating script ...")
			return

	# Optionally, delete the uploaded backup from which you restored (delete_backup)
	print("Deleting backup %s from %s ..." % id, dst_hostname)
	delete_status = portal_backup_delete(dst_hostname, dst_access_token, dst_version, id)

	print("Backup from Portal %s has been restored to Portal %s. Success!" % src_hostname, dst_hostname)

	return

def main():

	# set up arguments in appropriate variables
	parser = argparse.ArgumentParser (description="Python utilities to automate information collection or \
		 configuration tasks within Portal environments")
	parser.add_argument('--hostname', help="Hostname or IP address of the Portal appliance")
	parser.add_argument('--hostnamelist', help="File containing hostnames or IP addresses, one per line")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password for the username")
	parser.add_argument('--action', help="Action to perform: %s" % PORTAL_UTILITIES_ACTIONS)
	parser.add_argument('--actionfile', help="Settings file associated with action")
	parser.add_argument('--fromconfig', help="Run full workflow from YAML config")
	args = parser.parse_args()

	if args.fromconfig != None:
		run_from_yaml(args.fromconfig)
	else:
		run_action(args.hostname, args.username, args.password, args.action, args.actionfile)


if __name__ == "__main__":
	main ()
