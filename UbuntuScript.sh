#!/bin/bash

# Run chmod +x UbuntuScript.sh to make the file executable



touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

if [[ $EUID -ne 0 ]]
then
  echo This script must be run as root
  exit
fi
echo "Script is being run as root."

# Backups
mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
echo "Backups folder created on the Desktop."

cp /etc/group ~/Desktop/backups/
cp /etc/passwd ~/Desktop/backups/

echo "/etc/group and /etc/passwd files backed up."

# Change login chances/age
sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
apt-get install libpam-cracklib -y -qq
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
apt-get install auditd && auditctl -e 1 -y -qq

#login.defs umask set to 027
sed -i 's/022/027/g' /etc/login.defs

#disable guest account
echo 'allow-guest=false' >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf

#install firewall
apt-get install ufw -y -qq
ufw enable
ufw allow https
ufw allow https
ufw deny 1337
ufw deny 23
ufw deny 2049
ufw deny 515
ufw deny 111
ufw logging high
ufw status verbose
echo "Firewall enabled."

chmod 777 /etc/apt/apt.conf.d/10periodic
cp /etc/apt/apt.conf.d/10periodic ~/Desktop/backups/
echo -e "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Download-Upgradeable-Packages \"1\";\nAPT::Periodic::AutocleanInterval \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";" > /etc/apt/apt.conf.d/10periodic
chmod 644 /etc/apt/apt.conf.d/10periodic
echo "Daily update checks, download upgradeable packages, autoclean interval, and unattended upgrade enabled."

# echo "Check to verify that all update settings are correct."
# update-manager
echo "This might take a while"
apt-get update -y -qq
apt-get upgrade -y -qq
apt-get dist-upgrade -y -qq
echo "Ubuntu OS has checked for updates and has been upgraded."

apt-get purge netcat* ncat socat socket sbd -y -qq
#sock and pnetcat cannot be found and were removed from this line
rm /usr/bin/nc
echo "Netcat and all other instances have been removed."

apt-get purge john john-data -y -qq
echo "John the Ripper has been removed."

apt-get purge hydra hydra-gtk -y -qq
echo "Hydra has been removed."

apt-get purge aircrack-ng -y -qq
echo "Aircrack-NG has been removed."

apt-get purge fcrackzip -y -qq
echo "FCrackZIP has been removed."

apt-get purge ophcrack ophcrack-cli -y -qq
echo "OphCrack has been removed."

apt-get purge pdfcrack -y -qq
echo "PDFCrack has been removed."

apt-get purge rarcrack -y -qq
echo "RARCrack has been removed."

apt-get purge sipcrack -y -qq
echo "SipCrack has been removed."

apt-get purge irpas -y -qq
echo "IRPAS has been removed."

echo 'Are there any hacking tools shown? (not counting libcrack2:amd64 or cracklib-runtime)'
dpkg -l | egrep "crack|hack" >> ~/Desktop/Script.log

apt-get purge zeitgeist* rhythmbox-plugin-zeitgeist zeitgeist -y -qq
echo "Zeitgeist has been removed."

apt-get purge nfs-kernel-server nfs-common portmap rpcbind autofs -y -qq
echo "NFS has been removed."

apt-get purge nginx nginx-common -y -qq
echo "NGINX has been removed."

apt-get purge inetd openbsd-inetd xinetd inetutils* -y -qq
echo "Inetd (super-server) and all inet utilities have been removed."

apt-get purge vnc4server vncsnapshot vtgrab -y -qq
echo "VNC has been removed."

apt-get purge snmp -y -qq
echo "SNMP has been removed."

apt-get upgrade openssl libssl-dev -y
apt-cache policy openssl libssl-dev -y
echo "OpenSSL heart bleed bug has been fixed."

apt-get purge ftp -y -qq
echo "ftp was removed"

apt-get purge vsftpd -y -qq
echo "vsftpd was removed"

apt-get purge samba -y -qq
echo "samba was removed"

apt-get purge prelink -y -qq
echo "prelink was removed"

apt-get purge bind9 -y -qq
echo "bind9 was removed"

apt-get purge slapd -y -qq
echo "slapd was removed"

apt-get purge isc-dhcp-server -y -qq
echo "isc-dhcp-server was removed"

apt-get purge avahi-daemon -y -qq
echo "avahi-daemon was removed"

apt-get purge xserver-xorg* -y -qq
echo "xserver-xorg was removed"

apt-get purge ntp -y -qq
echo "ntp was removed"

apt-get purge dovecot-imapd dovecot-pop3d -y -qq
echo "dovecot was removed"

apt-get purge squid -y -qq
echo "squid was removed"

apt-get purge rsync -y -qq
echo "rsync was removed"

apt-get purge nis -y -qq
echo "nis was removed"

apt-get purge rsh-client -y -qq
echo "rsh-client was removed"

apt-get purge talk -y -qq
echo "talk was removed"

apt-get purge ldap-utils -y -qq
echo "ldap-utils was removed"

apt-get purge rpcbin -y -qq
echo "rpcbin was removed"

apt-get purge cups -y -qq
echo "cups was removed"

sudo apt-get purge firefox -y -qq
sudo apt-get install firefox -y
echo "uninstalled and reinstalled firefox"

echo "creating logs directory"
mkdir -p logs/

apt-get install apparmor -y
apt-get install apparmor-profiles -y


apt-get install clamav -y
clamscan -r -o -i > logs/clamav.txt

apt-get install rkhunter -y
rkhunter -c --sk > logs/rkhunter.txt

apt-get install git -y

git clone https://github.com/CISOfy/lynis
cd lynis && ./lynis audit system
#apt-get install lynis -y
#lynis -c --quick > logs/lynis.txt

git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
./privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh > logs/linpeas.txt

git clone https://github.com/rebootuser/LinEnum
./LinEnum/LinEnum.sh > logs/linenum.txt > logs/linenum.txt

apt-get install debsums -y
debsums -cae > logs/debsums.txt

apt-get install npm -y
echo "scan for open ports"
nmap scanme.nmap.org

apt-get install policycoreutils selinux-basics selinux-utils -y
selinux-activate
echo "installed SELinux"

sudo apt-get install libpam-tmpdir -y 
echo "installed libpam-tmpdir"

sudo apt-get install apt-listbugs -y 
echo "installed apt-listbugs"

sudo apt-get install apt-listchanges -y 
echo "installed apt-listchanges"

sudo apt-get install fail2ban -y 
echo "installed fail2ban"

#sudo apt-get install needrestart -y 
#echo "installed needrestart"

sudo apt-get install debsecan -y 
echo "installed debsecan"

#autoremove
apt autoremove -y

#echo 'ExecStart=-/usr/sbin/sulogin'  >> /usr/lib/systemd/system/rescue.service

touch ~/Desktop/logs/allusers.txt
uidMin=$(grep "^UID_MIN" /etc/login.defs)
uidMax=$(grep "^UID_MAX" /etc/login.defs)
echo -e "User Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo -e "\nSystem Accounts:" >> ~/Desktop/logs/allusers.txt
awk -F':' -v "min=${uidMin##UID_MIN}" -v "max=${uidMax##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' /etc/passwd >> ~/Desktop/logs/allusers.txt
echo "All users have been logged."
cp /etc/services ~/Desktop/logs/allports.log
echo "All ports log has been created."
dpkg -l > ~/Desktop/logs/packages.log
echo "All packages log has been created."
apt-mark showmanual > ~/Desktop/logs/manuallyinstalled.log
echo "All manually instealled packages log has been created."
service --status-all > ~/Desktop/logs/allservices.txt
echo "All running services log has been created."
ps ax > ~/Desktop/logs/processes.log
echo "All running processes log has been created."
ss -l > ~/Desktop/logs/socketconnections.log
echo "All socket connections log has been created."
sudo netstat -tlnp > ~/Desktop/logs/listeningports.log
echo "All listening ports log has been created."
cp /var/log/auth.log ~/Desktop/logs/auth.log
echo "Auth log has been created."
cp /var/log/syslog ~/Desktop/logs/syslog.log
echo "System log has been created."

echo "Script is complete."

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

echo "installed stuff located at logs/apps.txt"
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) > logs/apps.txt

#nmap is a powerful tool look into it
echo "check log files for any warnings"



