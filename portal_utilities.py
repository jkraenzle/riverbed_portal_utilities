# Python-wrapped REST API utilities for AppResponse 11

from typing import Any, IO
import yaml
import os
import glob
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

##### YAML FUNCTIONS #####
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
				yamlresult = yaml.load(fh, YAMLLoader)
		else:
			yamlresult = None
	except FileNotFoundError:
		yamlresult = None

	return yamlresult

# -----

##### REST API INTEGRATION #####
# Run REST APIs to appliance and return result
# Assume 'payload' is JSON formatted
def portal_rest_api (action, path, appliance, access_token, version, payload = None, data = None, additional_headers = None):

	url = "https://" + appliance + path 

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	if additional_headers != None:
		headers.update(additional_headers)

	if action == "GET":
		r = requests.get(url, headers=headers, verify=False)
	elif action == "POST":
		if payload != None:
			r = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
		else:
			r = requests.post(url, headers=headers, data=data, verify=False)
	elif action == "PUT":
		r = requests.put (url, headers=headers, data=json.dumps (payload), verify=False)
	elif action == "DELETE":
		r = requests.delete (url, headers=headers, verify=False)

	if r.status_code not in [200, 201, 202, 204]:
		print("Status code was %s" % r.status_code)
		print("Error: %s" % r.content)
		result = None
	else:
		if (("Content-Type" in r.headers.keys ()) and ("application/json" in r.headers ["Content-Type"])):
			result = json.loads (r.content) 
		elif (("Content-Type" in r.headers.keys ()) and ("application/x-gzip" in r.headers ["Content-Type"])):
			result = r.content
		else:
			result = r.text

	return result 


##### BACKUP & RESTORE #####

def portal_backups_list (appliance, access_token, version):

	backup_list = portal_rest_api("GET", "/api/npm.backup/1.0/backups", appliance, access_token, version)
	
	return backup_list["items"]

# REST API Python wrapper to create backup on appliance
def portal_backup_create (appliance, access_token, version):

	# Kick off backup and give time to process
	payload = {"description": "Automated Backup"}

	backup_in_process = portal_rest_api ("POST", "/api/npm.backup/1.0/backups", appliance, access_token, version, payload)

	# If backup creation failed, return upstream showing the failure
	if (backup_in_process == None):
		return None, None

	# Get backup id and sleep so there's time for backup to initially create
	backup_id = backup_in_process['id']
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
			return None, None
		elif (backup_complete == False):
			time.sleep (2)

	return backup_id, backup

def portal_backup_delete (appliance, access_token, version, backup):

	try:
		result = portal_rest_api("DELETE", "/api/npm.backup/1.0/backups/items/" + str(backup['id']), appliance, access_token, version)
	except:
		result = None

	return result

def portal_backup_download_and_store (appliance, access_token, version, backup, path=None):
	backup_file = portal_rest_api("GET", "/api/npm.backup/1.0/backups/items/" + backup['id'] + "/file", appliance, access_token, version)

	# Create folders and filenames for store
	backup_time_str = "Unknown"
	if 'backup_time' in backup:
		backup_timestamp = backup['backup_time']
		dt = datetime.fromtimestamp(backup_timestamp)
		backup_time_str = dt.strftime("%Y%m%d%H%M%S")

	backup_filename = appliance + '.' + backup_time_str + ".backup.tgz"
	if path != None:
		backup_filename = path + backup_filename
	
	if (backup_file != None):

		try:
			if not os.path.exists(path):
				os.mkdir(path)
			with open(backup_filename, "wb") as backup_f:
				backup_f.write (backup_file)
		except:
			return None
	
	return backup_filename

# REST API Python wrapper to download and delete automated backup
def portal_backup_download_and_delete (appliance, access_token, version, backup, path):

	backup_filename = portal_backup_download_and_store(appliance, access_token, version, backup, path)

	delete_status = portal_backup_delete(appliance, access_token, version, backup)

	return delete_status, backup_filename

# REST API Python wrapper to create and pull backup from appliance
def portal_backup_get (appliance, access_token, version, path):
	backup_id, backup = portal_backup_create (appliance, access_token, version)

	if (backup_id != None):
		empty_result,filename = portal_backup_download_and_delete(appliance, access_token, version, backup, path)
		return True,filename
	else:
		return False,filename

def portal_backup_upload (appliance, access_token, version, backup_file):
	data = backup_file.read ()

	backup = portal_rest_api("POST", "/api/npm.backup/1.0/backups/upload", appliance, access_token, version, additional_headers={'Content-Type': 'application/octet-stream'}, data=data)

	return backup

def portal_backup_restore (appliance, access_token, version, id):
	backup_restore_status = portal_rest_api("POST", "/api/npm.backup/1.0/backups/items/" + id + "/restore", appliance, access_token, version)

	return backup_restore_status

def portal_backup_restore_status (appliance, access_token, version):
	backup_restore_status = portal_rest_api("GET", "/api/npm.backup/1.0/restore_status", appliance, access_token, version)

	return backup_restore_status

def portal_backup_space_create (hostname, access_token, version, delete_options, store_options):

	# Set backup options related to locally storing and/or deleting existing backups; verify that they make sense
	download_and_store_existing_backups = store_options['download_and_store_existing_backups']

	delete_all_existing_backups_on_appliance = delete_options['delete_all_existing_backups_on_appliance']
	delete_oldest_backup = delete_options['delete_oldest_backup']
	do_not_delete_existing_backups = delete_options['do_not_delete_existing_backups']
	if do_not_delete_existing_backups == True and (delete_all_existing_backups_on_appliance == True or delete_oldest_backup == True):
		print("WARNING")
		print("Configuration file has conflicting settings, and is set to not delete any backups from appliance(s) and configured with deletion options.")
		print("Resulting configuration will not delete any files.")
		print("Please correct configuration file for subsequent runs.")
		delete_all_existing_backups_on_appliance = delete_oldest_backup = False
	elif delete_all_existing_backups_on_appliance == True and delete_oldest_backup == True:
		print("WARNING")
		print("Configuration file is set to delete all backups and oldest backups. Resulting configuration will delete only oldest files from appliance(s).")
		print("Please correct configuration file for subsequent runs.")
		delete_all_existing_backups_on_appliance = False

	print("Checking backup space availability on Portal %s." % hostname)

	# Check the current list of primary Portal backups (list_backups)
	backups_list = portal_backups_list (hostname, access_token, version)

	# If there are two, delete oldest as only allowed to store two at a time on the Portal appliance (delete_backup)
	if len(backups_list) > 0:

		if download_and_store_existing_backups == True:
			for backup in backups_list:
				filename = portal_backup_download_and_store(hostname, access_token, version, backup, store_options['path'])
				print("Downloaded %s from %s to store locally." % (filename, hostname))

		if delete_all_existing_backups_on_appliance == True:
			for backup in backups_list:
				delete_status = portal_backup_delete(hostname, access_token, version, backup)
				if delete_status != None and delete_status != "":
					print(delete_status)
					print("Deletion of backup %s from hostname %s failed." % (str(backup['id']), hostname))
					return False
		else:
			if delete_oldest_backup == True:
				if len(backups_list) == 2:	
					if do_not_delete_existing_backups == True:
						print("Portal %s has no available space and flag is set to not delete on-Portal backups." % hostname)
						return False
					else:
						# Get ID of oldest backup
						timestamp_0 = backups_list[0]['backup_time']
						timestamp_1 = backups_list[1]['backup_time']
						if timestamp_0 < timestamp_1:
							backup_to_delete = backups_list[0]
						else:
							backup_to_delete = backups_list[1]

						print("Deleting oldest backup to create available space on Portal %s." % hostname)
						delete_status = portal_backup_delete(hostname, access_token, version, backup_to_delete)
						if delete_status != None and delete_status != "":
							print(delete_status)
							return False

	return True

def portal_backup_clean_locally (store_options):

	if store_options['number_of_archived_backups'] != None:
		num_backups_to_keep = store_options['number_of_archived_backups']
		if not isinstance(num_backups_to_keep, int):
			print("WARNING")
			print("Configuration file has an invalid setting for the number of archived backups")
			print("Setting is %s." % str(num_backups_to_keep))
			return False
	else:
		num_backups_to_keep = 0

	backups_list = []
	if 'path' in store_options:
		backups_list = glob.glob(store_options['path'] + "*.backup.tgz")

	oldest_timestamp = None
	oldest_backup = None

	while len(backups_list) > num_backups_to_keep:
		for backup in backups_list:
			backup_timestamp = int(backup.rsplit('.', 3)[1]) 
			if oldest_timestamp == None or oldest_timestamp > backup_timestamp:
				oldest_timestamp = backup_timestamp
				oldest_backup = backup

		try:
			print("Removing backup %s." % oldest_backup)
			backups_list.remove(oldest_backup)
			os.remove (oldest_backup)
			oldest_timestamp = None
			oldest_backup = None
		except:
			print("Exception while removing backup %s from local disk" % oldest_backup)
			return False
	
	return True

##### CERTIFICATE FUNCTIONS #####

def portal_certificate_import(hostname, access_token, version, certificate):

	if certificate == None: 
		print("WARNING")
		print("Certificate options are not present in configuration file.")
		return None

	if 'file' in certificate:
		pemcertandkey = certificate_read(certificate['file'])
	else:
		print("WARNING")
		print("Certificate file was not specified in configuration settings. Web server certificate must be replaced manually.")
		return None

	if 'passphrase' in certificate:
		payload = { "pem": pemcertandkey, "passphrase": certificate['passphrase'] }
	else:
		payload = { "pem": pemcertandkey}

	certificate = portal_rest_api("POST", "/api/npm.https/1.0/certificate/import", hostname, access_token, version, payload=payload)

	return certificate

##### GENERAL FUNCTIONS #####

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

# REST API Python wrapper to request version information
# URL: https://<appliance>/api/common/1.0/info
# Header: AUthorization: Bearer <access_token>
def portal_version_get (appliance, access_token, version):
	url = "https://" + appliance + "/api/common/1.0/info"
	
	r = requests.get (url, verify=False)

	result = json.loads(r.content)

	version_str = result["sw_version"]
	
	return version_str

def portal_authentication_check(hostname, username, password):
	
	# Login to source and destination Portals to confirm the passwords are correct before proceeding
	if password == None or password == "":
		print("Please provide password for account %s on %s" % (username, hostname))
		password = getpass.getpass()
	version = portal_version_get(hostname, username, password)
	access_token = portal_authenticate(hostname, username, password, version)

	return access_token, version, password

##### HELPER FUNCTIONS #####

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
		print ("Please provide password for account %s on %s" % (username, hostname))
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
		backup,filename = portal_backup_get (hostname, access_token, version, None)

		if (backup == True):
			print ("Backup for %s was successful!" % (hostname))
		else:
			print ("Backup for %s was unsuccessful!" % (hostname))

	# ACTION - delete backup
	elif (action == "delete_backup"):
		if (actionfile == None or actionfile == ""):
			print ("Please specify an ID for the filename on the appliance that you would like to restore in --actionfile parameter")
		else:
			backup_to_delete = None
			backups_list = portal_backups_list (hostname, access_token, version)
			for backup in backups_list:
				if actionfile == backup['id']:
					backup_to_delete = backup

			backup = portal_backup_delete (hostname, access_token, version, backup_to_delete)

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

def certificate_read(filename):
	
	try:
		with open(filename, "r") as cert_f:
			pemcertandkey = cert_f.read()
	except:
		print("ERROR")
		print("Failed to open file" % filename)
		return None

	return pemcertandkey

def backup_credentials_get (filename):

	credentials = yamlread (filename)	
	
	hostname = None
	if 'hostname' in credentials:
		hostname = credentials['hostname'] 
	username = None
	if 'username' in credentials:
		username = credentials['username'] 

	# Allow for testing, but the expectation is that this is not included in YAML
	password = None
	if 'password' in credentials:
		password = credentials['password']

	# Include options to handle what to do with existing backups and how to store locally
	delete_options = None
	if 'delete_options' in credentials:
		delete_options = credentials['delete_options']
	store_options = None
	if 'store_options' in credentials:
		store_options = credentials['store_options']

	return hostname, username, password, delete_options, store_options

def backup_restore_credentials_get (filename):

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

	# Include options to handle what to do with existing backups and how to store locally
	delete_options = None
	if 'delete_options' in credentials:
		delete_options = credentials['delete_options']
	store_options = None
	if 'store_options' in credentials:
		store_options = credentials['store_options']

	certificate = None
	if 'certificate' in credentials:
		certificate = credentials['certificate']

	return src_hostname, src_username, src_password, dst_hostname, dst_username, dst_password, delete_options, store_options, certificate


def backup_from_yaml(config):
	print("------------------------------------------------------------------------")
	print("")
	print("Step 1 of 3: Confirming accounts and pre-requisites ...")
	print("")

	hostname, username, password, delete_options, store_options = backup_credentials_get(config)

	access_token, version, password = portal_authentication_check(hostname, username, password)
	if access_token == None:
		print("Authentication failed to Portal %s. Terminating script ..." % hostname)
		return

	print("")
	print("Step 2 of 3: Taking backup from Portal %s" % hostname)
	print("")

	status = portal_backup_space_create (hostname, access_token, version, delete_options, store_options)

	# Create, download, and delete a backup of the Portal at a current time (pull_backup)
	backup_status,backup_filename = portal_backup_get(hostname, access_token, version, store_options['path'])
	if backup_status == False:
		print("Portal %s backup failed. Terminating script ..." % hostname)
		return
	else:
		print("Backup file %s created and downloaded for Portal %s" % (backup_filename, hostname))

	print("")
	print("Step 3 of 3: Cleaning up after script execution.")
	print("")
	cleanup_status = portal_backup_clean_locally(store_options)
	if cleanup_status == False:
		print("Cleanup failed. Terminating script ...")
		return

	print("Backup from Portal %s has been completed. Success!" % (hostname))
	print("")
	print("------------------------------------------------------------------------")
	return

def backup_restore_from_yaml(config):
	print("------------------------------------------------------------------------")
	print("")
	print("Step 1 of 6: Confirming accounts and pre-requisites ...")
	print("")

	src_hostname, src_username, src_password, dst_hostname, dst_username, dst_password, delete_options, store_options, certificate = backup_restore_credentials_get(config)

	# Login to source and destination Portals to confirm the passwords are correct before proceeding
	src_access_token, src_version, src_password = portal_authentication_check(src_hostname, src_username, src_password)
	if src_access_token == None:
		print("Authentication failed to Portal %s. Terminating script ..." % src_hostname)
		return

	dst_access_token, dst_version, dst_password = portal_authentication_check(dst_hostname, dst_username, dst_password)
	if dst_access_token == None:
		print("Authentication failed to Portal %s. Terminating script ..." % dst_hostname)
		return

	# Versions are required to be the same in order to be able to restore from source to destination Portals
	if src_version != dst_version:
		print("Source version %s on Portal %s differs from destination version %s on Portal %s! Terminating script ..." % (src_version, src_hostname, dst_version, dst_hostname))
		return

	# Save the current timestamp for future comparison to restore time
	current_time = datetime.now().timestamp()

	print("")
	print("Step 2 of 6: Taking backup from source Portal %s" % src_hostname)
	print("")

	space_available = portal_backup_space_create(src_hostname, src_access_token, src_version, delete_options, store_options)
	if space_available == False:
		print("Failed to create space on Portal %s in order to create backup." % src_hostname)
		print("Terminating script ...")
		return

	# Create, download, and delete a backup of the Portal at a current time (pull_backup)
	backup_status,backup_filename = portal_backup_get(src_hostname, src_access_token, src_version, store_options['path'])
	if backup_status == False:
		print("Portal %s backup failed. Terminating script ..." % src_hostname)
		return
	else:
		print("Backup file %s created and downloaded for Portal %s" % (backup_filename, src_hostname))

	print("")
	print("Step 3 of 6: Uploading backup to destination Portal %s." % dst_hostname)
	print("")

	# Check if there is available space on the secondary instance (list_backups)
	print("Checking space on Portal %s to upload backup." % dst_hostname)
	space_available = portal_backup_space_create(dst_hostname, dst_access_token, dst_version, delete_options, store_options)
	if space_available == False:
		print("Failed to create space on Portal %s in order to be able to upload backup from source Portal." % dst_hostname)
		print("Terminating script ...")
		return

	# Upload the backup to the secondary instance (upload_backup)
	upload_status = None
	with open(backup_filename,'rb') as backup_file:
		upload_status = portal_backup_upload(dst_hostname, dst_access_token, dst_version, backup_file)
		if 'id' in upload_status:
			id = upload_status['id']
			print("Upload of file %s succeeded to Portal %s." % (backup_filename, dst_hostname))
		else:
			print("Upload to Portal %s failed." % dst_hostname)
			return

	print("")
	print("Step 4 of 6: Kicking off restore process on Portal %s." % dst_hostname)
	print("")

	# Restore the uploaded backup on the secondary instance (restore)
	print("Beginning restore process on Portal %s." % dst_hostname)
	restore_result = portal_backup_restore(dst_hostname, dst_access_token, dst_version, id)

	# Use the restore_status to keep checking the status every minute, even if it times out and fails to return while rebooting
	# Check until the restore status shows as 'completed' (restore_status) and the 'last_restore_time' is past the start of the script; or you potentially hit a timeout in your script
	not_complete = True
	rebooting = False
	start_time = datetime.now()
	while not_complete:
		time.sleep(15)
		try:
			if rebooting:
				dst_access_token = portal_authenticate(dst_hostname, dst_username, dst_password, dst_version)
				if dst_access_token == None:
					print("Authentication failed to Portal %s. Waiting for reboot to complete ..." % dst_hostname)
					continue
				else:
					rebooting = False
			restore_status = portal_backup_restore_status(dst_hostname, dst_access_token, dst_version)
			if restore_status['status'] == 'completed':
				not_complete = False
				if restore_status['last_restore_time'] > current_time:
					print("Restore completed on Portal %s!" % dst_hostname)
			else:
				print("Restore on %s has been running for %d minutes. Status: %s" % (dst_hostname, (datetime.now()-start_time).seconds/60, restore_status['status_message']))
		except:
			print("Portal %s is not responding. Waiting for reboot to complete ..." % dst_hostname)
			rebooting = True

		if ((datetime.now() - start_time).seconds / 60) > PORTAL_UTILITIES_SCRIPT_TIMEOUT:
			print("Script has hit time limit without restore completion. Please check Portal console for restore status. Terminating script ...")
			return

	print("")
	print("Step 5 of 6: Restoring HTTPS TLS/SSL certificate to destination Portal %s" % dst_hostname)
	print("")
	if certificate != None:
		print("Importing certificate into Portal ...")
		new_certificate = portal_certificate_import(dst_hostname, dst_access_token, dst_version, certificate)
		if 'fingerprint' in new_certificate:
			if 'value' in new_certificate['fingerprint']:
				print("Certificate with fingerprint %s imported into hostname %s" % (new_certificate['fingerprint']['value'], dst_hostname))
		else:
			print("WARNING")
			print("Certificate failed to be imported and will need to be installed manually.")

	print("")
	print("Step 6 of 6: Cleaning up after script execution.")
	print("")

	# Delete the created backup on the destination Portal that was used for the restore (delete_backup)
	print("Deleting uploaded backup %s (from filename %s) from Portal %s ..." % (id, backup_filename, dst_hostname))
	delete_status = portal_backup_delete(dst_hostname, dst_access_token, dst_version, id)

	# Optionally, delete the backups from the local file system
	cleanup_status = portal_backup_clean_locally(store_options)
	if cleanup_status == False:
		print("Cleanup failed. Terminating script ...")
		return

	print("")
	print("Backup from Portal %s has been restored to Portal %s. Success!" % (src_hostname, dst_hostname))
	print("------------------------------------------------------------------------")
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
	parser.add_argument('--backupfromconfig', help="Backup Portal from YAML config")
	parser.add_argument('--backuprestorefromconfig', help="Run full workflow from YAML config")
	args = parser.parse_args()

	if args.backupfromconfig != None:
		backup_from_yaml(args.backupfromconfig)
	elif args.backuprestorefromconfig != None:
		backup_restore_from_yaml(args.backuprestorefromconfig)
	else:
		run_action(args.hostname, args.username, args.password, args.action, args.actionfile)


if __name__ == "__main__":
	main()
