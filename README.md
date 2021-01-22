# portal_utilities

Currently, a set of utilities for Portal backup and restore. There are two ways to execute the utilities, either by running individual actions, or performing a complete backup/restore cycle.

<b>Backup/Restore Cycle</b>

python portal_utilities.py --fromconfig config.yaml

The config.yaml includes the ability to specify the source hostname and username and the destination hostname and username, along with backup storage and deletion options.

src_hostname: 10.1.150.224
src_username: admin
dst_hostname: 10.1.150.239
dst_username: admin
delete_options:
  delete_all_existing_backups_on_appliance: False
  delete_oldest_backup: True
  do_not_delete_existing_backups: False
store_options:
  download_and_store_existing_backups: False
  number_of_archived_backups: 1
  path: /Users/jkraenzle/Desktop/Riverbed/GitHub/portal_utilities/backups_for_restore/

For now, the path must include the trailing separator.

<b>Actions</b>

<b>List backups</b>

python portal_utilities.py --hostname <hostname> --username admin --action list_backups

Note, only two backups are permitted on Portal at one time. If two exist, one backup file needs to be deleted (using the ID), if there are already two existing and you want to pull (create) or upload a backup file.

<b>Delete backup</b>

  python portal_utilities.py --hostname <hostname> --username admin --action delete_backup --actionfile <ID_of_backup_file_on_appliance>

<b>Create, download and delete backup</b>

  python portal_utilities.py --hostname <hostname> --username admin --action pull_backup

<b>Upload backup</b>

  python portal_utilities.py --hostname <hostname> --username admin --action upload_backup --actionfile <backup_file.backup.tgz>

<b>Restore backup</b>

  python portal_utilities.py --hostname <hostname> --username admin --action restore --actionfile <ID_of_backup_file_on_appliance>

<b>Show restore status</b>
  
  python portal_utilities.py --hostname <hostname> --username admin --action restore_status

  Output example:
   {'last_restore_time': 1602540247, 'status': 'completed', 'status_message': ''}
