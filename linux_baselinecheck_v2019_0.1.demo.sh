#!/bin/bash
#----------------------------------Basic Definition------------------------------------------
if [ $# -lt 1 ];then
    echo "should give report path as parameters."
    exit -1
fi
echo "report path" $1

CV=./itemvalue
# report=./Linux_Basheline_`hostname`_`date +%Y%m%d_%H%M`.csv
report=$1
# notinscope=./not_required_baselinescope.cfg
root_dir=./security_checkitem_catagory
#----------------------------------Build Report----------------------------------------------
echo "Num,Check Item,Audit Value,Configuration Value,Result">>$report
#2.1 Filesystem configuration
# echo "2.1 Filesystem configuration" >> $report
#2.1.1 Disable unused filesystems
for i in `cat $root_dir/2.1_Filesystem_Configuration/2.1.1_Disable_unused_filesystems`;do
	i1=`echo $i|cut -d ',' -f1`
	i2=`echo $i|cut -d ',' -f2`
	i3=`echo $i|cut -d ',' -f3`
	i4=`echo $i|cut -d ',' -f4`
	lsmod |grep $i4
	if [ $? == 0 ];then
		echo "$i1,$i2,$i3,Filesystem:$i4 module is not loaded,Compliance" >> $report
	else
		echo "$i1,$i2,$i3,Filesystem:$i4 module is loaded,Not Compliance" >> $report
	fi
done
#2.1.2-2.1.5 Ensure separate partition exists for /tmp
partition=/tmp
mount|grep $partition
        if [ `echo $?` == 1 ];then
                echo "2.1.2,Ensure separate partition exists for $partition,"mount | grep /tmp tmpfs"/n"on /tmp type tmpfs-rw,nosuid,nodev,noexec,relatime",No $partition separate partition be mounted,Not Compliance" >> $report
		k=0
        else
                echo "2.1.2,Ensure separate partition exists for $partition,"mount | grep /tmp tmpfs"/n"on /tmp type tmpfs-rw,nosuid,nodev,noexec,relatime",Found $partition separate partition,Compliance" >> $report
        	k=1
	fi
for i in `cat $root_dir/2.1_Filesystem_Configuration/2.1.3-5_tmp_partition_option`;do
	i1=`echo $i|cut -d ',' -f1`
	i2=`echo $i|cut -d ',' -f2`
	i3=`echo $i|cut -d ',' -f3`
	i4=`echo $i|cut -d ',' -f4`
        if [ $k == 0 ];then
		echo "$i1,$i2,$i3,No $partition separate partition be mounted,Not Compliance" >> $report
	else
		mount|grep $partition|grep $i4
	        if [ `echo $?` == 0 ];then
                	echo "$i1,$i2,$i3,$i4 Option is set,Compliance" >> $report
        	else
                	echo "$i1,$i2,$i3,$i4 Option is not set,Not Compliance" >> $report
        	fi
	fi
done
#2.1.6 Ensure separate partition exists for /var
partition=/var
mount|grep $partition
	if [ `echo $?` == 1 ];then
                echo "2.1.6,Ensure separate partition exists for $partition,mount | grep /var,No $partition separate partition be mounted,Not Compliance" >> $report
        else
                echo "2.1.6,Ensure separate partition exists for $partition,mount | grep /var,Found $partition separate partition,Compliance" >> $report
        fi
#2.1.7-10 Ensure separate partition exists for /var/tmp
partition=/var/tmp
mount|grep $partition
        if [ `echo $?` == 1 ];then
                echo "2.1.7,Ensure separate partition exists for $partition,mount | grep $partition,No $partition separate partition be mounted,Not Compliance" >> $report
                k=0
        else
                echo "2.1.7,Ensure separate partition exists for $partition,mount | grep $partition,Found $partition separate partition,Compliance" >> $report
                k=1
        fi
for i in `cat $root_dir/2.1_Filesystem_Configuration/2.1.8-10_var_tmp_partition_option`;do
        i1=`echo $i|cut -d ',' -f1`
        i2=`echo $i|cut -d ',' -f2`
        i3=`echo $i|cut -d ',' -f3`
        i4=`echo $i|cut -d ',' -f4`
        if [ $k == 0 ];then
                echo "$i1,$i2,$i3,No $partition separate partition be mounted,Not Compliance" >> $report
        else
                mount|grep $partition|grep $i4
                if [ `echo $?` == 0 ];then
                        echo "$i1,$i2,$i3,$i4 Option is set,Compliance" >> $report
                else
                        echo "$i1,$i2,$i3,$i4 Option is not set,Not Compliance" >> $report
                fi
        fi
done
#2.1.11	Ensure separate partition exists for /var/log
partition=/var/log
mount|grep $partition
        if [ `echo $?` == 1 ];then
                echo "2.1.11,Ensure separate partition exists for $partition,mount | grep $partition,No $partition separate partition be mounted,Not Compliance" >> $report
        else
                echo "2.1.11,Ensure separate partition exists for $partition,mount | grep $partition,Found $partition separate partition,Compliance" >> $report
        fi
#2.1.12	Ensure separate partition exists for /var/log/audit
partition=/var/log/audit
mount|grep $partition
        if [ `echo $?` == 1 ];then
                echo "2.1.12,Ensure separate partition exists for $partition,mount | grep $partition,No $partition separate partition be mounted,Not Compliance" >> $report
        else
                echo "2.1.12,Ensure separate partition exists for $partition,mount | grep $partition,Found $partition separate partition,Compliance" >> $report
        fi
#2.1.13-14 Ensure separate partition exists for /home
partition=/home
mount|grep $partition
        if [ `echo $?` == 1 ];then
                echo "2.1.13,Ensure separate partition exists for $partition,mount | grep $partition,No $partition separate partition be mounted,Not Compliance" >> $report
                k=0
        else
                echo "2.1.13,Ensure separate partition exists for $partition,mount | grep $partition,Found $partition separate partition,Compliance" >> $report
                k=1
        fi
for i in `cat $root_dir/2.1_Filesystem_Configuration/2.1.13-14_home_partition_option`;do
        i1=`echo $i|cut -d ',' -f1`
        i2=`echo $i|cut -d ',' -f2`
        i3=`echo $i|cut -d ',' -f3`
        i4=`echo $i|cut -d ',' -f4`
        if [ $k == 0 ];then
                echo "$i1,$i2,$i3,No $partition separate partition be mounted,Not Compliance" >> $report
        else
                mount|grep $partition|grep $i4
                if [ `echo $?` == 0 ];then
                        echo "$i1,$i2,$i3,$i4 Option is set,Compliance" >> $report
                else
                        echo "$i1,$i2,$i3,$i4 Option is not set,Not Compliance" >> $report
                fi
        fi
done
#2.1.15-17 Ensure the partition options for /dev/shm
partition=/dev/shm
mount|grep $partition
        if [ `echo $?` == 1 ];then
                #echo "2.1.13,Ensure separate partition exists for $partition,No $partition separate partition be mounted,Not Compliance" >> $report
                k=0
        else
                #echo "2.1.13,Ensure separate partition exists for $partition,Found $partition separate partition,Compliance" >> $report
                k=1
        fi
for i in `cat $root_dir/2.1_Filesystem_Configuration/2.1.15-17_dev_shm_partition_option`;do
        i1=`echo $i|cut -d ',' -f1`
        i2=`echo $i|cut -d ',' -f2`
        i3=`echo $i|cut -d ',' -f3`
        i4=`echo $i|cut -d ',' -f4`
        if [ $k == 0 ];then
                echo "$i1,$i2,$i3,No $partition separate partition be mounted,Not Compliance" >> $report
        else
                mount|grep $partition|grep $i4
                if [ `echo $?` == 0 ];then
                        echo "$i1,$i2,$i3,$i4 Option is set,Compliance" >> $report
                else
                        echo "$i1,$i2,$i3,$i4 Option is not set,Not Compliance" >> $report
                fi
        fi
done
#2.1.22	Disable Automounting
service=autofs
chkconfig --list $service > ./checkvalue_tmp
chkconfig --list $service|grep on
if [ `echo $?` == 0 ];then
                echo "2.1.22,Disable Automounting,$service 0:off 1:off 2:off 3:off 4:off 5:off 6:off,`cat ./checkvalue_tmp`,Not Compliance" >> $report
        else
                echo "2.1.22,Disable Automounting,$service 0:off 1:off 2:off 3:off 4:off 5:off 6:off,`cat ./checkvalue_tmp`,Compliance" >> $report
fi
#2.2 Configure Software Updates
#2.3 Filesystem Integrity Checking
# echo "2.3 Filesystem Integrity Checking" >> $report
#2.3.1 Ensure AIDE is installed
pkg=aide
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "2.3.1,Ensure AIDE is installed,"rpm -q aide"||"aide-version","`rpm -q $pkg`",Compliance" >> $report
        else
                echo "2.3.1,Ensure AIDE is installed,"rpm -q aide"||"aide-version",Package:$pkg is not installed,Not Compliance" >> $report
fi
#2.3.2 Ensure filesystem integrity is regularly checked
crontask=aide
task=`crontab -u root -l | grep $crontask`
if [ `echo $?` == 1 ];then
                echo "2.3.2,Ensure filesystem integrity is regularly checked,AIDE crontask should be setup,Crontask:$crontask is not setup,Not Compliance" >> $report
        else
                echo "2.3.2,Ensure filesystem integrity is regularly checked,AIDE crontask should be setup,Crontask:$task,Compliance" >> $report
fi
#2.4 Secure Boot Settings
# echo "2.4 Secure Boot Settings" >> $report
#2.4.1 Ensure permissions on bootloader config are configured
i=`ls -l /boot/grub/grub.conf|cut -d'.' -f1`
i3=`ls -l /boot/grub/grub.conf`
ls -n /boot/grub/grub.conf |grep '0 0'
if [[ $i == -rw------- && $? == 0 ]];then
		echo "2.4.1,Ensure permissions on bootloader config are configured,Access:(0600/-rw-------)Uid:( 0/ root)Gid:( 0/ root),$i3,Compliance" >> $report
	else
		echo "2.4.1,Ensure permissions on bootloader config are configured,Access:(0600/-rw-------)Uid:( 0/ root)Gid:( 0/ root),$i3,Not Compliance" >> $report
fi
#2.4.3 Ensure authentication required for single user mode
checkvalue=`cat /etc/sysconfig/init|grep SINGLE=/sbin/sulogin`
if [ `echo $?` == 1 ];then
                echo "2.4.3,Ensure authentication required for single user mode,/etc/sysconfig/init|set SINGLE to /sbin/sulogin,SINGLE=/sbin/sulogin is not setup in /etc/sysconfig/init,Not Compliance" >> $report
        else
                echo "2.4.3,Ensure authentication required for single user mode,/etc/sysconfig/init|set SINGLE to /sbin/sulogin,"$checkvalue",Compliance" >> $report
fi
#2.4.4 Ensure interactive boot is not enabled
checkvalue=`cat /etc/sysconfig/init|grep PROMPT`
cat /etc/sysconfig/init|grep PROMPT=no
if [ `echo $?` == 1 ];then
                echo "2.4.4,Ensure interactive boot is not enabled,PROMPT is set to 'no' in /etc/sysconfig/init,"$checkvalue",Not Compliance" >> $report
        else
                echo "2.4.4,Ensure interactive boot is not enabled,PROMPT is set to 'no' in /etc/sysconfig/init,"$checkvalue",Compliance" >> $report
fi
#2.5 Additional Process Hardening
# echo "2.5 Additional Process Hardening" >> $report
#2.5.1 Ensure core dumps are restricted
checkvalue=`sysctl fs.suid_dumpable`
checkvalue2=`cat /etc/security/limits.conf |grep "hard core"`
if [[ `echo $?` == 0 && $checkvalue == "fs.suid_dumpable = 0" ]];then
                echo "2.5.1,Ensure core dumps are restricted,Add '* hard core 0' to /etc/security/limits.conf&&setup sysctl.conf file--fs.suid_dumpable = 0,$checkvalue && $checkvalue2,Compliance" >> $report
        else
                echo "2.5.1,Ensure core dumps are restricted,Add '* hard core 0' to /etc/security/limits.conf&&setup sysctl.conf file--fs.suid_dumpable = 0,'hard core' is not add or sysctl -w fs.suid_dumpable=0 is not execution,Not Compliance" >> $report
fi

#2.5.3 Ensure address space layout randomization (ASLR) is enabled
checkvalue=`sysctl kernel.randomize_va_space`
if [[ $checkvalue == "kernel.randomize_va_space = 2" ]];then
                echo "2.5.3,Ensure address space layout randomization (ASLR) is enabled,kernel.randomize_va_space = 2,"$checkvalue",Compliance" >> $report
        else
                echo "2.5.3,Ensure address space layout randomization (ASLR) is enabled,kernel.randomize_va_space = 2,"$checkvalue",Compliance" >> $report
fi
#2.5.4 Ensure prelink is disabled
pkg=prelink
checkvalue=`rpm -q $pkg`
rpm -q $pkg
if [ `echo $?` == 1 ];then
                echo "2.5.4,Ensure prelink is disabled,'rpm -q $pkg'-->package $pkg is not installed,Package:$pkg is not installed,Compliance" >> $report
        else
                echo "2.5.4,Ensure prelink is disabled,'rpm -q $pkg'-->package $pkg is not installed,"$checkvalue",Not Compliance" >> $report
fi
#2.6 Mandatory Access Control
# echo "2.6 Mandatory Access Control" >> $report
#2.6.1 Configure SELinux
#Ensure SELinux is not disabled in bootloader configuration
checkvalue=`grep "kernel*" /boot/grub/grub.conf|grep -v "^#"`
grep "kernel*" /boot/grub/grub.conf|grep -v "^#"|grep "selinux=0"
condition1=`echo $?`
grep "kernel*" /boot/grub/grub.conf|grep -v "^#"|grep "enforcing=0"
condition2=`echo $?`
if [[ $condition1 == 0 && $condition2 == 0 ]];then
		echo "2.6.1,Ensure SELinux is not disabled in bootloader configuration,no kernel line has the selinux=0 or enforcing=0 parameters set,"$checkvalue",Not Compliance" >> $report
        else
		echo "2.6.1,Ensure SELinux is not disabled in bootloader configuration,no kernel line has the selinux=0 or enforcing=0 parameters set,"$checkvalue",Compliance" >> $report
fi
#Ensure the SELinux state is enforcing 
checkvalue=`sestatus`
grep "SELINUX=enforcing" /etc/selinux/config
if [ `echo $?` == 0 ];then
                echo "2.6.1,Ensure the SELinux state is enforcing,SELinux status: enabled && Current mode: enforcing && Mode from config file: enforcing,"$checkvalue",Compliance" >> $report
        else
                echo "2.6.1,Ensure the SELinux state is enforcing,SELinux status: enabled && Current mode: enforcing && Mode from config file: enforcing,"$checkvalue",Not Compliance" >> $report
fi
#Ensure SELinux policy is configured
checkvalue=`sestatus |grep "Policy from config file"`
grep "SELINUXTYPE=targeted" /etc/selinux/config
if [ `echo $?` == 0 ];then
                echo "2.6.1,Ensure SELinux policy is configured,Policy from config file: targeted,"$checkvalue",Compliance" >> $report
        else
                echo "2.6.1,Ensure SELinux policy is configured,Policy from config file: targeted,"$checkvalue",Not Compliance" >> $report
fi
#Ensure SETroubleshoot is not installed 
pkg=setroubleshoot
checkvalue=`rpm -q $pkg`
rpm -q $pkg
if [ `echo $?` == 1 ];then
                echo "2.6.1,Ensure SETroubleshoot is not installed,'rpm -q $pkg'-->package $pkg is not installed,$pkg is not installed,Compliance" >> $report
        else
                echo "2.6.1,Ensure SETroubleshoot is not installed,'rpm -q $pkg'-->package $pkg is not installed,"$checkvalue",Not Compliance" >> $report
fi
#Ensure the MCS Translation Service (mcstrans) is not installed
pkg=mcstrans
checkvalue=`rpm -q $pkg`
rpm -q $pkg
if [ `echo $?` == 1 ];then
                echo "2.6.1,Ensure the MCS Translation Service (mcstrans) is not installed,rpm -q $pkg'-->package $pkg is not installed,$pkg is not installed,Compliance" >> $report
        else
                echo "2.6.1,Ensure the MCS Translation Service (mcstrans) is not installed,rpm -q $pkg'-->package $pkg is not installed,"$checkvalue",Not Compliance" >> $report
fi
#2.6.2 Ensure SELinux is installed
pkg=libselinux
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
		echo "2.6.2,Ensure SELinux is installed,rpm -q $pkg --> libselinux-version,"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
		echo "2.6.2,Ensure SELinux is installed,rpm -q $pkg --> libselinux-version,$pkg is not installed,Not Compliance" >> $report
fi
#2.7 Warning Banners
# echo "2.7 Warning Banners" >> $report
#2.7.1 Command Line Warning Banners
#Ensure message of the day is configured properly 
egrep '(\\v|\\r|\\m|\\s)' /etc/motd > ./checkvalue_tmp
if [ `echo $?` == 1 ];then
                echo "2.7.1,Ensure message of the day is configured properly,Run 'egrep '(\\v|\\r|\\m|\\s)' /etc/motd' and no results are returned,"No results returned",Compliance" >> $report
        else
                echo "2.7.1,Ensure message of the day is configured properly,Run 'egrep '(\\v|\\r|\\m|\\s)' /etc/motd' and no results are returned,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi
#Ensure local login warning banner is configured properly 
checkvalue=`egrep '(\\v|\\r|\\m|\\s)' /etc/issue`
if [ `echo $?` == 1 ];then
                echo "2.7.1,Ensure local login warning banner is configured properly,Run 'egrep '(\\v|\\r|\\m|\\s)' /etc/issue' and no results are returned,"No results returned",Compliance" >> $report
        else
                echo "2.7.1,Ensure local login warning banner is configured properly,Run 'egrep '(\\v|\\r|\\m|\\s)' /etc/issue' and no results are returned,"$checkvalue",Not Compliance" >> $report
fi
#Ensure remote login warning banner is configured properly
checkvalue=`egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net`
if [ `echo $?` == 1 ];then
                echo "2.7.1,Ensure remote login warning banner is configured properly,Run 'egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net' and no results are returned,"No results returned",Compliance" >> $report
        else
                echo "2.7.1,Ensure remote login warning banner is configured properly,Run 'egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net' and no results are returned,"$checkvalue",Not Compliance" >> $report
fi
#Ensure permissions on /etc/motd are configured
dir=/etc/motd
condition=`ls -l $dir|cut -d'.' -f1`
checkvalue=`ls -l $dir`
ls -l $dir |grep 'root root'
if [[ $condition == -rw-r--r-- && $? == 0 ]];then
                echo "2.7.1,Ensure permissions on /etc/motd are configured,stat /etc/motd --> Access:(0644/-rw-r--r--) Uid:( 0/ root) Gid:( 0/ root),"$checkvalue",Compliance" >> $report
        else
                echo "2.7.1,Ensure permissions on /etc/motd are configured,stat /etc/motd --> Access:(0644/-rw-r--r--) Uid:( 0/ root) Gid:( 0/ root),"$checkvalue",Not Compliance" >> $report
fi
#Ensure permissions on /etc/issue are configured
dir=/etc/issue
condition=`ls -l $dir|cut -d'.' -f1`
checkvalue=`ls -l $dir`
ls -l $dir |grep 'root root'
if [[ $condition == -rw-r--r-- && $? == 0 ]];then
                echo "2.7.1,Ensure permissions on /etc/issue are configured,stat /etc/issue --> Access:(0644/-rw-r--r--) Uid:( 0/ root) Gid:( 0/ root),"$checkvalue",Compliance" >> $report
        else
                echo "2.7.1,Ensure permissions on /etc/issue are configured,stat /etc/issue --> Access:(0644/-rw-r--r--) Uid:( 0/ root) Gid:( 0/ root),"$checkvalue",Not Compliance" >> $report
fi
#Ensure permissions on /etc/issue are configured
dir=/etc/issue.net
condition=`ls -l $dir|cut -d'.' -f1`
checkvalue=`ls -l $dir`
ls -l $dir |grep 'root root'
if [[ $condition == -rw-r--r-- && $? == 0 ]];then
                echo "2.7.1,Ensure permissions on /etc/issue.net are configured,stat /etc/issue.net --> Access:(0644/-rw-r--r--) Uid:( 0/ root) Gid:( 0/ root),"$checkvalue",Compliance" >> $report
        else
                echo "2.7.1,Ensure permissions on /etc/issue.net are configured,stat /etc/issue.net --> Access:(0644/-rw-r--r--) Uid:( 0/ root) Gid:( 0/ root),"$checkvalue",Not Compliance" >> $report
fi

#3 Service
#3.1 inetd service
# echo "3.1 inetd service" >> $report
#Ensure chargen services are not enabled 
service=chargen-dgram
service1=chargen-stream
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure chargen services are not enabled,xinetd based services:chargen-dgram: off chargen-stream: off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure chargen services are not enabled,xinetd based services:chargen-dgram: off chargen-stream: off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure daytime services are not enabled
service=daytime-dgram
service1=daytime-stream
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure daytime services are not enabled,xinetd based services:daytime-dgram: off daytime-stream: off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure daytime services are not enabled,xinetd based services:daytime-dgram: off daytime-stream: off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure discard services are not enabled
service=discard-dgram
service1=discard-stream
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure discard services are not enabled,xinetd based services:discard-dgram: off discard-stream: off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure discard services are not enabled,xinetd based services:discard-dgram: off discard-stream: off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure echo services are not enabled 
service="echo-dgram"
service1="echo-stream"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure 'echo' services are not enabled,xinetd based services:'echo-dgram': off 'echo-stream': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure 'echo' services are not enabled,xinetd based services:'echo-dgram': off 'echo-stream': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure time services are not enabled
service="time-dgram"
service1="time-stream"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure time services are not enabled,xinetd based services:'time-dgram': off 'time-stream': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure time services are not enabled,xinetd based services:'time-dgram': off 'time-stream': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure rsh server are not enabled
service="rexec"
service1="rlogin"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure rsh server are not enabled,xinetd based services:'rexec': off 'rlogin': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure rsh server are not enabled,xinetd based services:'rexec': off 'rlogin': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure talk server are not enabled
service="talk"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure talk server are not enabled,xinetd based services:'talk': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure talk server are not enabled,xinetd based services:'talk': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure telnet server are not enabled
service="telnet"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure telnet server are not enabled,xinetd based services:'telnet': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure telnet server are not enabled,xinetd based services:'telnet': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure tftp server are not enabled
service="tftp"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure tftp server are not enabled,xinetd based services:'tftp': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure tftp server are not enabled,xinetd based services:'tftp': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure rsync service are not enabled
service="rsync"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure rsync serice are not enabled,xinetd based services:'rsync': off or missed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure rsync serice are not enabled,xinetd based services:'rsync': off or missed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#Ensure xinetd is not enabled
service="xinetd"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
		echo "3.1,Ensure xinetd is not enabled,verify all runlevels are listed as "off" or xinetd is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
		echo "3.1,Ensure xinetd is not enabled,verify all runlevels are listed as "off" or xinetd is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#3.2 Special Purpose Services
# echo "3.2 Special Purpose Services" >> $report
#3.2.1 Time Synchronization

#3.2.2 Ensure X Window System is not installed 
pkg='xorg-x11*'
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "3.2.2,Ensure X Window System is not installed,rpm -qa $pkg --> No output is returned,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.2,Ensure X Window System is not installed,rpm -qa $pkg --> No output is returned,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.3 Ensure Avahi Server is not enabled 
service="avahi-daemon"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.3,Ensure Avahi is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.3,Ensure Avahi is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.4 Ensure CUPS is not enabled 
service="cups"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.4,Ensure CUPS is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.4,Ensure CUPS is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.5 Ensure DHCP Server is not enabled
service="dhcpd"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.5,Ensure DHCP is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.5,Ensure DHCP is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.6 Ensure LDAP server is not enabled 
service="slapd"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.6,Ensure LDAP is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.6,Ensure LDAP is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#3.2.7 Ensure NFS and RPC are not enabled
service="nfs"
service1="rpcbind"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service1 >> ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on ||chkconfig --list $service1|grep on
if [ `echo $?` == 0 ];then
                echo "3.2.7,Ensure NFS and RPC is not enabled,verify NFS & RPC runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.7,Ensure NFS and RPC is not enabled,verify NFS & RPC  runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.7 Ensure DNS Server is not enabled
service="named"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.7,Ensure DNS Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.7,Ensure DNS Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.8 Ensure FTP Server is not enabled 
service="vsftpd"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.8,Ensure FTP Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.8,Ensure FTP Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#3.2.9	Ensure HTTP server is not enabled 
service="httpd"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.9,Ensure HTTP Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Manual Check" >> $report
        else
                echo "3.2.9,Ensure HTTP Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi
#3.2.10	Ensure IMAP and POP3 server is not enabled
service="dovecot"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.10,Ensure IMAP and POP3 Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.10,Ensure IMAP and POP3 Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.12	Ensure HTTP Proxy Server is not enabled
service="squid"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.12,Ensure HTTP Proxy Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.12,Ensure HTTP Proxy Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.2.14	Ensure mail transfer agent is configured for local-only mode

#3.2.15	Ensure NIS Server is not enabled 
service="ypserv"
chkconfig --list $service > ./checkvalue_tmp 2>&1
chkconfig --list $service |grep on
if [ `echo $?` == 0 ];then
                echo "3.2.15,Ensure NIS Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.2.15,Ensure NIS Server is not enabled,verify all runlevels are listed as "off" or $service is not available,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.3 Service Clients
# echo "3.3 Service Clients" >> $report
#3.3.1 Ensure NIS Client is not installed
pkg='ypbind'
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "3.3.1,Ensure NIS Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.3.1,Ensure NIS Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.3.2 Ensure rsh client is not installed 
pkg='rsh'
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "3.3.2,Ensure RSH Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.3.2,Ensure RSH Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.3.3 Ensure talk client is not installed
pkg='talk'
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "3.3.3,Ensure Talk Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.3.3,Ensure Talk Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.3.4 Ensure telnet client is not installed 
pkg='telnet'
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "3.3.4,Ensure Telnet Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.3.4,Ensure Telnet Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#3.3.5 Ensure LDAP client is not installed 
pkg='openldap-clients'
rpm -q $pkg > ./checkvalue_tmp 2>&1
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "3.3.5,Ensure LDAP Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
        else
                echo "3.3.5,Ensure LDAP Client is not installed,RUN rpm -q $pkg --> verify $pkg is not installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
fi

#4 Network Configuration
#4.1 Network Parameters
# echo "4.1 Network Parameters" >> $report
#4.1.1 Ensure IP forwarding is disabled 
checkitem="net.ipv4.ip_forward"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
if [ $itemvalue == 0 ];then
		echo "4.1.1,Ensure IP forwarding is disabled,Run sysctl $checkitem --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
	else
		echo "4.1.1,Ensure IP forwarding is disabled,Run sysctl $checkitem --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.1.2 Ensure packet redirect sending is disabled
checkitem="net.ipv4.conf.all.send_redirects"
checkitem1="net.ipv4.conf.default.send_redirects"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 0 && $itemvalue1 == 0 ]];then
                echo "4.1.2,Ensure packet redirect sending is disabled,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.1.2,Ensure packet redirect sending is disabled,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2 Network Parameters 
# echo "4.2 Network Parameters" >> $report
#4.2.1 Ensure source routed packets are not accepted 
checkitem="net.ipv4.conf.all.accept_source_route"
checkitem1="net.ipv4.conf.default.accept_source_route"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 0 && $itemvalue1 == 0 ]];then
                echo "4.2.1,Ensure source routed packets are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.1,Ensure source routed packets are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.2 Ensure ICMP redirects are not accepted 
checkitem="net.ipv4.conf.all.accept_redirects"
checkitem1="net.ipv4.conf.default.accept_redirects"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 0 && $itemvalue1 == 0 ]];then
                echo "4.2.2,Ensure ICMP redirects are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.2,Ensure ICMP redirects are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.3 Ensure secure ICMP redirects are not accepted
checkitem="net.ipv4.conf.all.secure_redirects"
checkitem1="net.ipv4.conf.default.secure_redirects"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 0 && $itemvalue1 == 0 ]];then
                echo "4.2.3,Ensure secure ICMP redirects are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.3,Ensure secure ICMP redirects are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.4 Ensure suspicious packets are logged
checkitem="net.ipv4.conf.all.log_martians"
checkitem1="net.ipv4.conf.default.log_martians"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 1 && $itemvalue1 == 1 ]];then
                echo "4.2.4,Ensure suspicious packets are logged,Run sysctl $checkitem|$checkitem1 --> Verify value is '1',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.4,Ensure suspicious packets are logged,Run sysctl $checkitem|$checkitem1 --> Verify value is '1',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.5 Ensure broadcast ICMP requests are ignored
checkitem="net.ipv4.icmp_echo_ignore_broadcasts"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
checkvalue=`sysctl $checkitem > ./checkvalue_tmp 2>&1`
if [ $itemvalue == 1 ];then
                echo "4.2.5,Ensure broadcast ICMP requests are ignored,Run sysctl $checkitem --> Verify value is '1',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.5,Ensure broadcast ICMP requests are ignored,Run sysctl $checkitem --> Verify value is '1',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.6 Ensure bogus ICMP responses are ignored
checkitem="net.ipv4.icmp_ignore_bogus_error_responses"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
checkvalue=`sysctl $checkitem > ./checkvalue_tmp 2>&1`
if [ $itemvalue == 1 ];then
                echo "4.2.6,Ensure bogus ICMP responses are ignored,Run sysctl $checkitem --> Verify value is '1',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.6,Ensure bogus ICMP responses are ignored,Run sysctl $checkitem --> Verify value is '1',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.7 Ensure Reverse Path Filtering is enabled
checkitem="net.ipv4.conf.all.rp_filter"
checkitem1="net.ipv4.conf.default.rp_filter"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 1 && $itemvalue1 == 1 ]];then
                echo "4.2.7,Ensure Reverse Path Filtering is enabled,Run sysctl $checkitem|$checkitem1 --> Verify value is '1',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.7,Ensure Reverse Path Filtering is enabled,Run sysctl $checkitem|$checkitem1 --> Verify value is '1',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.2.8 Ensure TCP SYN Cookies is enabled
checkitem="net.ipv4.tcp_syncookies"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
checkvalue=`sysctl $checkitem > ./checkvalue_tmp 2>&1`
if [ $itemvalue == 1 ];then
                echo "4.2.8,Ensure TCP SYN Cookies is enabled,Run sysctl $checkitem --> Verify value is '1',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.2.8,Ensure TCP SYN Cookies is enabled,Run sysctl $checkitem --> Verify value is '1',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.3 IPv6
# echo "4.3 IPv6" >> $report
#4.3.1 Ensure IPv6 router advertisements are not accepted
checkitem="net.ipv6.conf.all.accept_ra"
checkitem1="net.ipv6.conf.default.accept_ra"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 0 && $itemvalue1 == 0 ]];then
                echo "4.3.1,Ensure IPv6 router advertisements are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.3.1,Ensure IPv6 router advertisements are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.3.2 Ensure IPv6 redirects are not accepted 
checkitem="net.ipv6.conf.all.accept_redirects"
checkitem1="net.ipv6.conf.default.accept_redirects"
itemvalue=`sysctl $checkitem |cut -d '=' -f2|sed 's/ //g'`
itemvalue1=`sysctl $checkitem1 |cut -d '=' -f2|sed 's/ //g'`
sysctl $checkitem > ./checkvalue_tmp 2>&1
sysctl $checkitem1 >> ./checkvalue_tmp 2>&1
if [[ $itemvalue == 0 && $itemvalue1 == 0 ]];then
                echo "4.3.2,Ensure IPv6 redirects are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.3.2,Ensure IPv6 redirects are not accepted,Run sysctl $checkitem|$checkitem1 --> Verify value is '0',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.4 TCP Wrappers
# echo "4.4 TCP Wrappers" >> $report
#4.4.1 Ensure TCP Wrappers is installed
pkg='tcp_wrappers'
checkvalue=`rpm -q $pkg > ./checkvalue_tmp 2>&1`
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "4.4.1,Ensure TCP Wrappers is installed,RUN rpm -q $pkg --> verify $pkg is installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.4.1,Ensure TCP Wrappers is installed,RUN rpm -q $pkg --> verify $pkg is installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#4.5 Uncommon Network Protocols
# echo "4.5 Uncommon Network Protocols" >> $report
#4.5.1 Ensure DCCP is disabled 
module=dccp
checkvalue=`lsmod |grep $module`
lsmod |grep $module
if [ `echo $?` == 1 ];then
                echo "4.5.1,Ensure DCCP is disabled,Run lsmod|grep $module --> No output,$module is not enable,Compliance" >> $report
        else
                echo "4.5.1,Ensure DCCP is disabled,Run lsmod|grep $module --> No output,"$checkvalue",Not Compliance" >> $report
fi
#4.5.2 Ensure SCTP is disabled
module=sctp
checkvalue=`lsmod |grep $module`
lsmod |grep $module
if [ `echo $?` == 1 ];then
                echo "4.5.2,Ensure SCTP is disabled,Run lsmod|grep $module --> No output,$module is not enable,Compliance" >> $report
        else
                echo "4.5.2,Ensure SCTP is disabled,Run lsmod|grep $module --> No output,"$checkvalue",Not Compliance" >> $report
fi

#4.5.3 Ensure RDS is disabled
module=rds
checkvalue=`lsmod |grep $module`
lsmod |grep $module
if [ `echo $?` == 1 ];then
                echo "4.5.3,Ensure RDS is disabled,Run lsmod|grep $module --> No output,$module is not enable,Compliance" >> $report
        else
                echo "4.5.3,Ensure RDS is disabled,Run lsmod|grep $module --> No output,"$checkvalue",Not Compliance" >> $report
fi

#4.5.4 Ensure TIPC is disabled
module=tipc
checkvalue=`lsmod |grep $module`
lsmod |grep $module
if [ `echo $?` == 1 ];then
                echo "4.5.4,Ensure TIPC is disabled,Run lsmod|grep $module --> No output,$module is not enable,Compliance" >> $report
        else
                echo "4.5.4,Ensure TIPC is disabled,Run lsmod|grep $module --> No output,"$checkvalue",Not Compliance" >> $report
fi

#4.6 Firewall Configuration
# echo "4.6 Firewall Configuration" >> $report
#4.6.1 Ensure iptables is installed
pkg='iptables'
checkvalue=`rpm -q $pkg > ./checkvalue_tmp 2>&1`
rpm -q $pkg
if [ `echo $?` == 0 ];then
                echo "4.6.1,Ensure iptables is installed,Run rpm -q $pkg --> verify $pkg is installed,"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "4.6.1,Ensure iptables is installed,Run rpm -q $pkg --> verify $pkg is installed,"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#5 Logging and Auditing
#5.1 Configure System Accounting 
# echo "5.1 Configure System Accounting" >> $report
#5.1.1 Configure Data Retention
#5.1.1.1 Ensure audit log storage size is configured 
checkvalue=`grep "max_log_file =" /etc/audit/auditd.conf|cut -d '=' -f2 |sed 's/ //g'`
echo "5.1.1.1,Ensure audit log storage size is configured,Ensure audit log storage size is in compliance with site policy,"max_log_file is $checkvalue MB",Manual Check" >> $report 
#5.1.1.3 Ensure audit logs are not automatically deleted
checkvalue=`grep "^max_log_file_action" /etc/audit/auditd.conf|cut -d '=' -f2 |sed 's/ //g'`
cat /etc/audit/auditd.conf |grep max_log_file_action > ./checkvalue_tmp 2>&1
if [ $checkvalue == keep_logs ];then
		echo "5.1.1.3,Ensure audit logs are not automatically deleted,Check max_log_file_action configuration is 'keep_logs',"`cat ./checkvalue_tmp`",Compliance" >> $report
	else
		echo "5.1.1.3,Ensure audit logs are not automatically deleted,Check max_log_file_action configuration is 'keep_logs',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#5.1.2 Ensure auditd service is enabled 
service="auditd"
checkvalue=`chkconfig --list $service > ./checkvalue_tmp 2>&1`
chkconfig --list $service |awk -F' ' '{print $4,$5,$6,$7}'|grep "2:on 3:on 4:on 5:on"
if [ `echo $?` == 0 ];then
                echo "5.1.2,Ensure auditd service is enabled,Verify $service runlevels 2-5 are listed as 'on',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "5.1.2,Ensure auditd service is enabled,Verify $service runlevels 2-5 are listed as 'on',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#5.1.3	Ensure auditing for processes that start prior to auditd is enabled 
cat /boot/grub/grub.conf | grep "^\s*kernel" > ./checkvalue_tmp
grep "^\s*kernel" /boot/grub/grub.conf | grep "audit=1"
if [ `echo $?` == 0 ];then
                echo "5.1.3,Ensure auditing for processes that start prior to auditd is enabled,Verify each kernel line has the 'audit=1',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "5.1.3,Ensure auditing for processes that start prior to auditd is enabled,Verify each kernel line has the 'audit=1',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#5.1.4	Ensure events that modify date and time information are collected

#5.1.5	Ensure events that modify user/group information are collected

#5.1.6	Ensure events that modify the system's network environment are collected 

#5.1.7	Ensure events that modify the system's Mandatory Access Controls are collected 
cat /etc/audit/audit.rules |grep "\-w /etc/selinux/ -p wa -k MAC-policy" > ./checkvalue_tmp
cat /etc/audit/audit.rules |grep "\-w /etc/selinux/ -p wa -k MAC-policy"
if [ `echo $?` == 0 ];then
                echo "5.1.7,Ensure events that modify the system's Mandatory Access Controls are collected,Verify output matches '-w /etc/selinux/ -p wa -k MAC-policy',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "5.1.7,Ensure events that modify the system's Mandatory Access Controls are collected,Verify output matches '-w /etc/selinux/ -p wa -k MAC-policy',"Output is none or wrong "`cat ./checkvalue_tmp`"",Not Compliance" >> $report
fi

#5.1.8	Ensure login and logout events are collected 
cat /etc/audit/audit.rules |grep "\-w /var/log/lastlog -p wa -k logins" && cat /etc/audit/audit.rules |grep "\-w /var/run/faillock/ -p wa -k logins" > ./checkvalue_tmp
cat /etc/audit/audit.rules |grep "\-w /var/log/lastlog -p wa -k logins" && cat /etc/audit/audit.rules |grep "\-w /var/run/faillock/ -p wa -k logins"
if [ `echo $?` == 0 ];then
                echo "5.1.8,Ensure login and logout events are collected,Verify output matches '-w /var/log/lastlog -p wa -k logins' && '-w /var/run/faillock/ -p wa -k logins',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "5.1.8,Ensure login and logout events are collected,Verify output matches '-w /var/log/lastlog -p wa -k logins' && '-w /var/run/faillock/ -p wa -k logins',"Output is none or wrong"`cat ./checkvalue_tmp`"",Not Compliance" >> $report
fi

#5.1.9	Ensure session initiation information is collected
checkfile=/etc/audit/audit.rules
cat $checkfile |grep "\-w /var/run/utmp -p wa -k session" && cat $checkfile |grep "\-w /var/log/wtmp -p wa -k session" && cat $checkfile |grep "\-w /var/log/btmp -p wa -k session" > ./checkvalue_tmp
cat $checkfile |grep "\-w /var/run/utmp -p wa -k session" && cat $checkfile |grep "\-w /var/log/wtmp -p wa -k session" && cat $checkfile |grep "\-w /var/log/btmp -p wa -k session"
if [ `echo $?` == 0 ];then
                echo "5.1.9,Ensure session initiation information is collected,Verify output matches '-w /var/run/utmp -p wa -k session' && '-w /var/log/wtmp -p wa -k session' && '-w /var/log/btmp -p wa -k session',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "5.1.9,Ensure session initiation information is collected,Verify output matches '-w /var/run/utmp -p wa -k session' && '-w /var/log/wtmp -p wa -k session' && '-w /var/log/btmp -p wa -k session',"Output is none or wrong `cat ./checkvalue_tmp`",Not Compliance" >> $report
fi

#5.1.10	Ensure discretionary access control permission modification events are collected


#5.1.11	Ensure unsuccessful unauthorized file access attempts are collected


#5.1.12	Ensure use of privileged commands is collected


#5.1.13	Ensure successful file system mounts are collected


#5.1.14	Ensure file deletion events by users are collected


#5.1.15	Ensure changes to system administration scope (sudoers) is collected 


#5.1.16	Ensure system administrator actions (sudolog) are collected


#5.1.17	Ensure kernel module loading and unloading is collected


#5.1.18	Ensure the audit configuration is immutable


#5.2 Configure Logging
# echo "5.2 Configure Logging" >> $report
#5.2.1	Configure rsyslog
#5.2.1.1 Ensure rsyslog Service is enabled
service="rsyslog"
checkvalue=`chkconfig --list $service > ./checkvalue_tmp 2>&1`
chkconfig --list $service |awk -F' ' '{print $4,$5,$6,$7}'|grep "2:on 3:on 4:on 5:on"
if [ `echo $?` == 0 ];then
                echo "5.2.1.1,Ensure $service service is enabled,Verify $service runlevels 2-5 are listed as 'on',"`cat ./checkvalue_tmp`",Compliance" >> $report
        else
                echo "5.2.1.1,Ensure $service service is enabled,Verify $service runlevels 2-5 are listed as 'on',"`cat ./checkvalue_tmp`",Not Compliance" >> $report
fi
