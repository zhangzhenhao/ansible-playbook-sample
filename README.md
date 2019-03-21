Ansible Playbook Samples
1. create one hosts file and add some context as:

127.0.0.1 asible_user=root ansible_password="1qaz@WSX" host_id="hostname_or_id_from_cmdb"

2. use playbooks for test
#csv file name from inventory 
ansible-playbook -i hosts  hello_csv.yml -e "awx_job_id='job123'" -vv
#csv file name from args
ansible-playbook -i hosts  hello_csv.yml -e "awx_job_id='job123'" -e "host_id=cmdb_host_name_as_args" -vv

3. hello_weblogic.yml is same with csv
