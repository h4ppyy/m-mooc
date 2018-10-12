#sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings aws create_user -p edx -e mih5@mobis.co.kr -u mihnm5
sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings aws create_user -p $1 -e $2@mobis.co.kr -u $3
