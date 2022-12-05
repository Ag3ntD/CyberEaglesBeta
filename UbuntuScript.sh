#!/bin/bash

# Run chmod +x UbuntuScript.sh to make the file executable

startTime=$(date +"%s")
printTime()
{
	endTime=$(date +"%s")
	diffTime=$(($endTime-$startTime))
	if [ $(($diffTime / 60)) -lt 10 ]
	then
		if [ $(($diffTime % 60)) -lt 10 ]
		then
			echo -e "0$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		else
			echo -e "0$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		fi
	else
		if [ $(($diffTime % 60)) -lt 10 ]
		then
			echo -e "$(($diffTime / 60)):0$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		else
			echo -e "$(($diffTime / 60)):$(($diffTime % 60)) -- $1" >> ~/Desktop/Script.log
		fi
	fi
}

touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

if [[ $EUID -ne 0 ]]
then
  echo This script must be run as root
  exit
fi
printTime "Script is being run as root."

# Backups
mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
printTime "Backups folder created on the Desktop."

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

printTime "/etc/group and /etc/passwd files backed up."

# Change login chances/age
sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
apt-get install libpam-cracklib
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
apt-get install auditd && auditctl -e 1

#install firewall
apt-get install ufw -y -qq
ufw enable
ufw deny 1337
printTime "Firewall enabled."

chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic
printTime "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

# echo "Check to verify that all update settings are correct."
# update-manager
apt-get update -qq
apt-get upgrade -qq
apt-get dist-upgrade -qq
printTime "Ubuntu OS has checked for updates and has been upgraded."

apt-get purge netcat* ncat socat socket sbd -y -qq
#sock and pnetcat cannot be found and were removed from this line
rm /usr/bin/nc
printTime "Netcat and all other instances have been removed."

apt-get purge john john-data -y -qq
printTime "John the Ripper has been removed."

apt-get purge hydra hydra-gtk -y -qq
printTime "Hydra has been removed."

apt-get purge aircrack-ng -y -qq
printTime "Aircrack-NG has been removed."

apt-get purge fcrackzip -y -qq
printTime "FCrackZIP has been removed."

apt-get purge ophcrack ophcrack-cli -y -qq
printTime "OphCrack has been removed."

apt-get purge pdfcrack -y -qq
printTime "PDFCrack has been removed."

apt-get purge rarcrack -y -qq
printTime "RARCrack has been removed."

apt-get purge sipcrack -y -qq
printTime "SipCrack has been removed."

apt-get purge irpas -y -qq
printTime "IRPAS has been removed."

printTime 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
dpkg -l | egrep "crack|hack" >> ~/Desktop/Script.log

apt-get purge zeitgeist* rhythmbox-plugin-zeitgeist zeitgeist -y -qq
printTime "Zeitgeist has been removed."

apt-get purge nfs-kernel-server nfs-common portmap rpcbind autofs -y -qq
printTime "NFS has been removed."

apt-get purge nginx nginx-common -y -qq
printTime "NGINX has been removed."

apt-get purge inetd openbsd-inetd xinetd inetutils* -y -qq
printTime "Inetd (super-server) and all inet utilities have been removed."

apt-get purge vnc4server vncsnapshot vtgrab -y -qq
printTime "VNC has been removed."

apt-get purge snmp -y -qq
printTime "SNMP has been removed."

apt-get upgrade openssl libssl-dev
apt-cache policy openssl libssl-dev
printTime "OpenSSL heart bleed bug has been fixed."

apt-get purge ftp -y -qq
printTime "ftp was removed"

apt-get purge vsftpd -y -qq
printTime "vsftpd was removed"

apt-get purge samba -y -qq
printTime "samba was removed"

apt-get purge prelink -y -qq
printTime "prelink was removed"

apt-get purge bind9 -y -qq
printTime "bind9 was removed"

apt-get purge slapd -y -qq
printTime "slapd was removed"

apt-get purge isc-dhcp-server -y -qq
printTime "isc-dhcp-server was removed"

apt-get purge avahi-daemon -y -qq
printTime "avahi-daemon was removed"

apt-get purge xserver-xorg* -y -qq
printTime "xserver-xorg was removed"

apt-get purge ntp -y -qq
printTime "ntp was removed"

apt-get purge dovecot-imapd dovecot-pop3d -y -qq
printTime "dovecot was removed"

apt-get purge squid -y -qq
printTime "squid was removed"

apt-get purge rsync -y -qq
printTime "rsync was removed"

apt-get purge nis -y -qq
printTime "nis was removed"

apt-get purge rsh-client -y -qq
printTime "rsh-client was removed"

apt-get purge talk -y -qq
printTime "talk was removed"

apt-get purge ldap-utils -y -qq
printTime "ldap-utils was removed"

apt-get purge rpcbin -y -qq
printTime "rpcbin was removed"

apt-get install apparmor -y

apt-get install clamav -y
#run using clamscan -rbell -i > logs/clamav.txt

apt-get install rkhunter -y
#run using rkhunter -c --sk > logs/rkhunter.txt

apt-get install lynis -y 
#run using lynis -c --quick > logs/lynis.txt

git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
#run using ./privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh > logs/linpeas.txt

git clone https://github.com/rebootuser/LinEnum
#run using ./LinEnum/LinEnum.sh > logs/linenum.txt > logs/linenum.txt

apt-get install -y debsums
#run using debsums -cae > logs/debsums.txt


#autoremove
apt autoremove


touch ~/Desktop/logs/allusers.txt
uidMin=$(grep "^UID_MIN" /etc/login.defs)
uidMax=$(grep "^UID_MAX" /etc/login.defs)
echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
printTime "All users have been logged."
cp /etc/services ~/Desktop/logs/allports.log
printTime "All ports log has been created."
dpkg -l > ~/Desktop/logs/packages.log
printTime "All packages log has been created."
apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
printTime "All manually instealled packages log has been created."
service --status-all > ~/Desktop/logs/allservices.txt
printTime "All running services log has been created."
ps ax > ~/Desktop/logs/processes.log
printTime "All running processes log has been created."
ss -l > ~/Desktop/logs/socketconnections.log
printTime "All socket connections log has been created."
sudo netstat -tlnp > ~/Desktop/logs/listeningports.log
printTime "All listening ports log has been created."
cp /var/log/auth.log ~/Desktop/logs/auth.log
printTime "Auth log has been created."
cp /var/log/syslog ~/Desktop/logs/syslog.log
printTime "System log has been created."

printTime "Script is complete."

echo "all sudo users:"
mawk -F: '$1 == "sudo"' /etc/group
echo "--------------------------------------"
echo "all users:"
mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
echo "--------------------------------------"
echo "all empty passwords:"
mawk -F: '$2 == ""' /etc/passwd
echo "--------------------------------------"
echo "all non root uid 0 users:"
mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd
echo "--------------------------------------"

echo "installed stuff. remove anything suspicious"
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u)


