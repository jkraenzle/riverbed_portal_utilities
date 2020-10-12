# portal_utilities

Currently, a set of utilities for Portal backup and restore.

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
