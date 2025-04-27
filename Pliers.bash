#!/bin/bash


#Program: Pliers v1.0
#Author: Nima.H 
#OS Support : Ubuntu 22.0
#Description: I'm going to  provide a starting point for  Linux admins to build a secure server which meets the CIS standards.
#For more information please check : github.com/Nima-Hasanzadeh




clear

#check user
if [ "$EUID" -ne 0 ]
  then
echo -e "\n\n\e[47m\e[34mDear "$USER",Please run this script as a root user\e[0m\n"

  kill $$
fi





echo -e "\e[91m"
cat <<EOF



 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ████████╗███████╗ █████╗ ███╗N.H███╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝        ██║   █████╗  ███████║██╔████╔██║
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝         ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║          ██║   ███████╗██║  ██║██║ ╚═╝ ██║
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝          ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
 Pliers 1.0
 Hardening Ubuntu 22
 github.com/Nima-Hasanzadeh
 

EOF
echo -e "\e[49m"
. /etc/os-release
echo -e "You are running \e[43m\e[34m${PRETTY_NAME}\e[0m\n"
read -p "Press Enter to continue . . ."


 if echo ${PRETTY_NAME} | cut -f1 -d'.' | grep -q "Ubuntu 22"; then
  echo
    else
   echo -e "Your OS release is not supported! You are running \e[43m\e[31m${PRETTY_NAME}\e[0m ,Are you sure you want to proceed?"
  read -p "Do you want to continue? (y/n): " response
    if [ "$response" = "y" ]; then
     echo "Continuing..."
      elif [ "$response" = "n" ]; then
      echo "Exiting the script."
	   kill $$
      else
     echo "Invalid input. Please enter 'y' to continue or 'n' to exit."
	kill $$
   fi
 fi



# Read confirmation from user
Current_Date="$(date '+%Y-%m-%d')"
LOGFILE=hrdlog_$(date '+%Y%m%d.%H')

#confirm firewall setting
if systemctl is-enabled ufw | grep -q enabled;then ufw1="true";else ufw1="false";fi
  if ufw status| grep -q "\bactive\b";then ufw2="true";else ufw2="false";fi
   if [ "$ufw1" = true ] && [ "$ufw2" = true ];then 
   echo 
   else
  echo -e "\e[43m\e[30mThe firewall will be enabled. Are you in agreement with that? [ y or n ] \e[0m "
 read firewall_confirm
fi


#confirm authentication profile edit
echo -e "\e[43m\e[30m Authentication profile and pam configuration will be reset, Are you in agreement with that? [ y or n ] \e[0m "
read auth_confirm

#Confirm system date
echo -e "\e[43m\e[30m Ensure that the date and time are correct, is (${Current_Date}) has a correct value? [ y or n ] \e[0m "
read date_confirm


echo "User answer for date confirmation with tha value of (${Current_Date}) is ${date_confirm} " >> ./$LOGFILE

    if [ "$date_confirm" = "y" ]; then
     echo "Date confirmed. Continue hardening process . . ."
      elif [ "$date_confirm" = "n" ]; then
       echo "You did'nt confirm the date value, the process will be terminated."
        kill $$
      else
     echo "Invalid input entered for date confirmation. Please enter 'y' or 'n'."
    kill $$
   fi


# Configuration files
LOGFILE=hrdlog_$(date '+%Y%m%d.%H')
LOGDIR="./$(hostname -s)_logs"
TIME="$(date +%F_%T)"
MAIN_LOG=MainLog_$(date '+%Y%m%d.%H')
BACKUP_DIR="$LOGDIR/backup"
MANUAL_FIX="$LOGDIR/read_manual_fix.txt"
ASLR='/etc/sysctl.d/60-kernel_sysctl.conf'
SEC_LIMITS='/etc/security/limits.conf'
APPPORT='/etc/default/apport'
AIDE_CONF='/etc/aide.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
SYSCTL_CONF='/etc/sysctl.conf'
SYSCTL_CONFv4='/etc/sysctl.d/60-netipv4_sysctl.conf'
SYSCTL_CONFv6='/etc/sysctl.d/60-netipv6_sysctl.conf'
GRUB_DF='/etc/default/grub'
GRUB_CFG='/boot/grub/grub.cfg'
DUMP_DIR='/etc/systemd/coredump.conf'
NETWORK_V6='/etc/sysconfig/network'
AUDIT_TOOLS='/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules'
AUDIT_DIR='/etc/audit/'
JOURNAL_CONF='/etc/systemd/journald.conf'
RSYS_CONF='/etc/rsyslog.conf'
CRONTAB='/etc/crontab'
CRON_HOURLY='/etc/cron.hourly'
CRON_DAILY='/etc/cron.daily'
CRON_WEEKLY='/etc/cron.weekly'
CRON_MONTHLY='/etc/cron.monthly'
CRON_DIR='/etc/cron.d'
AT_ALLOW='/etc/at.allow'
AT_DENY='/etc/at.deny'
CRON_ALLOW='/etc/cron.allow'
CRON_DENY='/etc/cron.deny'
SSHD_CFG='/etc/ssh/sshd_config' 
SSHD_ALL='/etc/ssh/sshd_config.d/*.conf'
SUDO_CONF='/etc/sudoers'
SUDOERS='/etc/sudoers* /etc/sudoers.d/*'
PAM_SU='/etc/pam.d/su'
PWQUAL_CNF='/etc/security/pwquality.conf'
SYSTEM_AUTH='/etc/authselect/system-auth'
PASS_AUTH='/etc/authselect/password-auth'
LIB_USR='/etc/libuser.conf' 
LOGIN_DEFS='/etc/login.defs'
PASSWD='/etc/passwd'
PASSWD2='/etc/passwd-'
SHADOW='/etc/shadow'
SHADOW2='/etc/shadow-'
GSHADOW='/etc/gshadow'
GSHADOW2='/etc/gshadow-'
GROUP='/etc/group'
GROUP2='/etc/group-'
FAIL_CONF='/etc/security/faillock.conf'
PROFILE_D='/etc/profile.d/*'
PROFILE_BASH='/etc/profile.d/bash_completion.sh'
PROFILE_FILE='/etc/profile'
BASHRC='/etc/bash.bashrc'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
COMMONPASSWD='/etc/pam.d/common-password'
COMMONACCOUNT='/etc/pam.d/common-account'
TOTAL=0
PASS=0
FAILED=0
COMMONAUTH='/etc/pam.d/common-auth'
LOGIN_DEFS='/etc/login.defs'



##Functions

function echo_audit {
#  echo  -e "-----------------------------------------------------------" >> ./$LOGFILE
  echo_mag "Audit OK         $func_name  $args" >> ./$LOGFILE
}


function results {

create_bar() {
    local value=$1
    for ((i=1; i<=$value; i++)); do
        printf "#"
    done
    printf "\n"
}

# Display the bar chart
echo_bold "\nThe results are shown as below :"
echo_red "--------------------------------------------------------------------------------------------"
echo_bold    "Total Checks : $TOTAL $(create_bar $(($TOTAL / 10)))"
echo_green   "Applied Items : $PASS $(create_bar $(($PASS / 10)))"
echo_red     "NOT Applied   : $FAILED  $(create_bar $((($FAILED+9) / 10)))"
echo_yellow  "NOT Applied Percentage : $(expr $FAILED \* 100 / $TOTAL)%"

}



function echo_yellow {
  echo -e "\e[93m${@} \e[0m"
}


function echo_bold {
  echo -e "\e[1m${@} \e[0m"
}

function echo_mag {
  echo -e "\e[95m${@} \e[0m"
}

function echo_red {
  echo -e "\e[91m${@} \e[0m"
}

function echo_green {
  echo -e "\e[92m${@} \e[0m"
}

mkdir -p $LOGDIR/backup 
touch $MANUAL_FIX;echo_green "This file contains items that must be checked and fixed manually.
Please check and fix the requested items based on the data below." > $MANUAL_FIX
echo_red "-----------------------------------------------------------" >> $MANUAL_FIX

function backup {
   local file_address="${1}"
   local file_name=$(basename "$file_address")
   cp ${file_address}  $BACKUP_DIR/${file_name}_$TIME.bak
 }
 
function disable_fs {
  local arg="${1}"
  echo "install ${arg} /bin/false blacklist ${arg} " > /etc/modprobe.d/${arg}.conf || return
  rmmod  ${arg}

}


function service_disabled {
 local arg="${1}"
 systemctl --now disable ${arg}  >> $LOGDIR/service_disabled_$TIME.log
 systemctl stop ${arg}  >> $LOGDIR/service_stopped_$TIME.log
 systemctl mask ${arg}  >> $LOGDIR/service_masked_$TIME.log
}

function service_enabled {
local arg="${1}"
 systemctl --now enable ${arg}  >> $LOGDIR/service_disabled_$TIME.log
 systemctl start ${arg}  >> $LOGDIR/service_stopped_$TIME.log
 systemctl unmask ${arg}  >> $LOGDIR/service_masked_$TIME.log
}



function aide {
aideinit
 mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    if ! [ -f /etc/cron.daily/aide ]; then
    cp ./config/aidecheck.service /etc/systemd/system/aidecheck.service
    cp ./config/aidecheck.timer /etc/systemd/system/aidecheck.timer
    chmod 0644 /etc/systemd/system/aidecheck.*

    systemctl reenable aidecheck.timer
    systemctl restart aidecheck.timer
    systemctl daemon-reload
  fi
}

function package_install {
 local  arg="${1}"
 apt install --no-install-recommends ${arg} >> $LOGDIR/service_installed_$TIME.log
}

function package_remove {
 local  arg="${1}"
 systemctl stop ${arg} 
 apt purge -y  ${arg} >> $LOGDIR/service_uninstalled_$TIME.log
}

function set_file_perms {
  # set Perms on a supplied file based on pattern
  local file="${1}"
  local pattern="${2}"
  chmod "${pattern}" ${file}
}

function set_file_owner {
  # set owner on  supplied files based on pattern
  local file="${1}"
  local pattern="${2}"
  chown "${pattern}" ${file}
}


function replace_param {
 local argm="${1}"
 local value="${2}"
 local file="${3}"
 if grep -q "^\s*$argm" ${file} ; then
    sed -i "/^\s*${argm}/ c ${argm} ${value}" ${file}
      else
    echo "${argm} ${value}"  >> ${file} 
  fi
}

function replace_parm_nospace {
 local argm="${1}"
 local value="${2}"
 local file="${3}"
 if grep -q "^\s*$argm" ${file}  ; then
    sed -i "/^\s*${argm}/ c ${argm}${value}" ${file}
      else
    echo "${argm}${value}"  >> ${file}
  fi
}


function sysctl_param {
 #config sysctl for given argument
 local flag="${1}"
 sysctl -w  $flag
 sysctl -p
}

function apparmor_grub {
 sed -i 's/GRUB_CMDLINE_LINUX="apparmor=[^"]*"/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"/' ${GRUB_DF}
 grep '^GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' ${GRUB_DF} ||  echo 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"'  >> ${GRUB_DF}
 update-grub
}

function ipv6_grub {
 sed -i 's/GRUB_CMDLINE_LINUX="ipv6.disable=[^"]*"/GRUB_CMDLINE_LINUX="ipv6.disable=1"/' ${GRUB_DF}
 grep '^GRUB_CMDLINE_LINUX="ipv6.disable=1"' ${GRUB_DF} ||  echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"'  >> ${GRUB_DF}
 update-grub
}

function auditd_grub {
 sed -i 's/GRUB_CMDLINE_LINUX="audit_backlog_limit=[^"]*"/GRUB_CMDLINE_LINUX="audit_backlog_limit=8192" /' ${GRUB_DF}
 grep '^GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"' ${GRUB_DF} ||  echo 'GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"'  >> ${GRUB_DF}

 sed -i 's/GRUB_CMDLINE_LINUX="audit=[^"]*"/GRUB_CMDLINE_LINUX="audit=1"/' ${GRUB_DF}
 grep '^GRUB_CMDLINE_LINUX="audit=1"' ${GRUB_DF} ||  echo 'GRUB_CMDLINE_LINUX="audit=1"'  >> ${GRUB_DF}

 update-grub
}



function apparmor_cfg {
 apt install --no-install-recommends apparmor-utils  >> $LOGDIR/service_installed_$TIME.log
echo "List of profiles in complain mode in apparmor" >> $MANUAL_FIX
 aa-complain /etc/apparmor.d/*  >> $MANUAL_FIX
 echo
}




function chk_update {
echo "update check results : " >> $MANUAL_FIX
apt -s upgrade  >> $MANUAL_FIX

}


function ssh_banner {

echo -e '
*******************************************************************
* Authorized uses only. All activities on this system are logged. *
*   Disconnect IMMEDIATELY if you are not an authorized user!     *
*******************************************************************
' > /etc/issue.net
}

function login_banner {
local file="${1}"
echo -e  '\e[1;31m

#################################################################
#                   _    _           _   _                      #
#                  / \  | | ___ ____| |_| |                     #
#                 / _ \ | |/ _ \  __| __| |                     #
#                / ___ \| |  __/ |  | |_|_|                     #
#               /_/   \_\_|\___|_|   \__(_)                     #
#                                                               #
#   This service is restricted to authorized users only. All    #
#            activities on this system are logged.              #
#  Unauthorized access will be fully investigated and reported  #
#        to the appropriate law enforcement agencies.           #
#                                                               #
#################################################################


\e[0m' > "${file}"
}


function wlan_disabled {
 ip link set wlan0 down 
}



function ufw_conf {
#ufw allow proto tcp from any to any port 22
    if [ "$firewall_confirm" = "y" ]; then
      echo "firewall change agreed. setting firewall..."  >> ./$LOGFILE
       ufw enable
        service ufw start
         ufw allow in on lo 
          ufw allow out on lo 
           ufw deny in from 127.0.0.0/8 
            ufw deny in from ::1       
           ufw default deny incoming
          ufw default deny outgoing
         ufw default deny routed
        elif [ "$firewall_confirm" = "n" ]; then
       echo "firewall change not agreed. Exiting without apply settings." >> ./$LOGFILE
      else
     echo "Invalid input got for firewall change agreement. Please enter 'y' or 'n'."  >> ./$LOGFILE
    fi
}



function ufwruls_openports {  
# verify a firewall rule exists for all open ports:
ufw_out="$(ufw status verbose)"
ss -tuln | awk '($5!~/%lo:/ && $5!~/127.0.0.1:/ && $5!~/::1/) {split($5, a,":"); print a[2]}' | sort | uniq | while read -r lpn; do
 ! grep -Pq "^\h*$lpn\b" <<< "$ufw_out" && echo "- Port: \"$lpn\" is missing a firewall rule"
done
}


  #Extract the log file path from the auditd.conf
  log_file_path=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)
  # Get the directory path of the log file
  directory_log=$(dirname "$log_file_path")
    
function audit_log_perm {
 #owner is defined on  auditd.conig at  "log_group" value.

 #check log files are mode 0640 or less permissive. Find files in the directory and its subdirectories based on permission criteria
 find "$directory_log" -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) \
 -exec chmod u-x,g-wx,o-rwx {} +
 
 #check owner
 find "$directory_log" -type f ! -user root -exec chown root {} +
 find "$directory_log" -type f ! -group root -exec chgrp root {} +
 
 #check the audit log directory is 0750 or more restrictive 
 chmod g-w,o-rwx "$directory_log"
}

function audit_conf_perm {
 find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +
 find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +
 find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +
}

function audit_tools_perm {
 chmod go-w ${AUDIT_TOOLS}
 chown root ${AUDIT_TOOLS}
 chown root:root ${AUDIT_TOOLS}
}

function rsyslog_remote {
echo_red "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
echo_bold "4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client" >>  $MANUAL_FIX
echo " remove the specific lines highlighted by the audit. Ensure none of the
following entries are present in any of /etc/rsyslog.conf or /etc/rsyslog.d/*.conf" >> $MANUAL_FIX

if grep -P -- '^\h*module\(load="imtcp"\)' ${RSYS_CONF};then >> $MANUAL_FIX ;else true;fi >> $MANUAL_FIX
if grep -P -- '^\h*input\(type="imtcp" port="514"\)' ${RSYS_CONF} ;then >> $MANUAL_FIX ;else true;fi  >> $MANUAL_FIX

}

function varlog_perm {
find /var/log/ -type f -perm /g+wx,o+rwx -exec chmod --changes g-wx,o-rwx "{}" +
}


function cron_at_access {
 #restrict cron and at to rot user
 rm -f ${CRON_DENY} & touch ${CRON_ALLOW} & chown root:root ${CRON_ALLOW} & chmod 600 ${CRON_ALLOW} || return
 rm -f ${AT_DENY}   & touch ${AT_ALLOW}   & chown root:root ${AT_ALLOW}   & chmod 600 ${AT_ALLOW}   || return
}

function ssh_key_perm {
 #change permissions on SSH private and public host key files
 find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
 find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
 find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,g-wx,o-rwx {} \;
 find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
}


function otherfiles_conf_param {
#comment out any  parameter entries in files ending in *.conf in the /etc/ssh/sshd_config.d/ directory  that include any setting other than propper value.

  local arg="${1}"
  local value="${2}"
  local file="${3}"

  for file in /etc/ssh/sshd_config.d/*.conf; do
    sed -i -E "/^\s*${arg}\s+/ s/^[#]*/# /I; /${arg}\s+${value}/ s/^#//" "$file"
done

 #rep -Pi "^\h*${arg}\b" ${file} | grep -Evi ${value} | while read -r l_out; do sed -ri "/^\s*${arg}\s*+/s/^/# /" "$(awk -F: '{print $1}' <<< $l_out)";done

}

function cipher_algorithm {
 if ! grep -q "^Ciphers" "$SSHD_CFG" 2> /dev/null; then
  echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> "$SSHD_CFG"
 fi
}

function kex_algorithm {
 if ! grep -q "^KexAlgorithms" "$SSHD_CFG" 2> /dev/null; then
   echo 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' >> "$SSHD_CFG"
 fi
}

function mac_algorithm {
 if ! grep -q "^MACs" "$SSHD_CFG" 2> /dev/null; then
  echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' >> "$SSHD_CFG"
 fi
}


function replace_parm_simple {
 local arg="${1}"
 local file="${2}"
 grep -q "^\s*$arg" ${file} || echo "${arg}" >> ${file} || return
}



function escalation_sudo {
   local escal="$(grep -r "^[^#].*NOPASSWD" ${SUDOERS})"
    echo_red "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
    echo_bold "5.3.4 Ensure users must provide password for privilege escalation"  >>  $MANUAL_FIX
    echo "Remove any line with occurrences of !authenticate tags in the file"  >>  $MANUAL_FIX

   [[  -z "${escal}" ]] || echo $escal >>  $MANUAL_FIX

}

function reauth_escalation_sudo {
  local reauth_escal="$( grep -r "^[^#].*\!authenticate"  ${SUDOERS})"
   echo_red "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
   echo_bold "5.3.5 Ensure re-authentication for privilege escalation is not disabled globally" >> $MANUAL_FIX
   echo "Remove any line with occurrences of !authenticate tags in these files" >>  $MANUAL_FIX

    [[  -z "${reauth_escal}" ]] ||    echo $reauth_escal >>  $MANUAL_FIX

}

function  auth_timeout_sudo {
 local address="$(grep -v '^#' ${SUDOERS} | grep -E '\s*timestamp_timeout=')"
 local timeout="$(grep -v '^#' ${SUDOERS} | grep -oE '\s*timestamp_timeout=\s*([0-9]+)' | cut -d'=' -f2)"
 local timeout2="$(sudo -V | grep "Authentication timestamp timeout:" | cut -d" " -f4 | cut -d "." -f1)"
 if [[ $timeout -gt 15 ]] || [[ $timeout2 -gt 15 ]]; then
  echo_red "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
   echo_bold "5.3.6 Ensure sudo authentication timeout is configured correctly" >> $MANUAL_FIX
    echo " edit the file listed in the audit section with visudo -f <PATH TO FILE> and modify the entry timestamp_timeout= to 15 or less" >> $MANUAL_FIX
     echo $address >> $MANUAL_FIX
    echo $timeout  >> $MANUAL_FIX
    echo $timeout2 >> $MANUAL_FIX

   else
  return 0
 fi
}

function pam_su {
 groupadd sugroup
 grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' $PAM_SU ||
 echo 'auth            required        pam_wheel.so use_uid group=sugroup' >>  $PAM_SU
}




function enable_faillock {
    if ! grep faillock "$COMMONACCOUNT"; then
      echo 'account required pam_faillock.so' >> "$COMMONACCOUNT"
    fi

     if ! grep faillock "$COMMONAUTH"; then
      echo 'account required pam_faillock.so' >> "$COMMONAUTH"
     fi

  sed -i -E 's/(nullok|nullok_secure)//g' "$COMMONAUTH"
}

function pass_reuse {
if ! grep pam_pwhistory.so "$COMMONPASSWD"; then
    sed -i '/the "Primary" block/apassword\trequired\t\t\tpam_pwhistory.so\tremember=5' "$COMMONPASSWD"
  fi

}


function remove_hash {
  sed -i -E 's/(pam_unix\.so.*)\s+sha\d+\s*(.*)/\1 \2/g' "$COMMONAUTH"
}


function current_hash {
   echo_red "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
   echo_bold "5.4.5 Ensure all current passwords uses the configured hashing algorithm (Manual) " >> $MANUAL_FIX
   echo_bold "Change users password to force them to use the current configured hash algorithm " >> $MANUAL_FIX


 declare -A HASH_MAP=( ["y"]="yescrypt" ["1"]="md5" ["2"]="blowfish" ["5"]="SHA256" ["6"]="SHA512" ["g"]="gost-yescrypt" )
 CONFIGURED_HASH=$(sed -n "s/^\s*ENCRYPT_METHOD\s*\(.*\)\s*$/\1/p" /etc/login.defs)
 for MY_USER in $(sed -n "s/^\(.*\):\\$.*/\1/p" /etc/shadow)
 do
 CURRENT_HASH=$(sed -n "s/${MY_USER}:\\$\(.\).*/\1/p" /etc/shadow)
 if [[ "${HASH_MAP["${CURRENT_HASH}"]^^}" != "${CONFIGURED_HASH^^}" ]];then
 echo "The password for '${MY_USER}' is using '${HASH_MAP["${CURRENT_HASH}"]}' instead of the configured '${CONFIGURED_HASH}'."
 echo "The password for '${MY_USER}' is using '${HASH_MAP["${CURRENT_HASH}"]}' instead of the configured '${CONFIGURED_HASH}'."  >> $MANUAL_FIX

 fi
 done
}

function update_chage {
# chage all users
local ssh_users="$(awk -F: '{ if ($3 >= 1000 && $7 ~ "/bin/(ba|z)?sh") print $1 }' ${PASSWD} )"
for user in ${ssh_users}
   do
       chage --maxdays 365 $user
       chage --mindays  1  $user
       chage --warndays 7  $user
       chage --inactive 30 $user
 done
}  
   
function update_chage_specific {
#update chage for specific users,such as root or other critical users
 local user="${1}"
  chage --maxdays 365 $user
  chage --mindays  1  $user
  chage --warndays 7  $user
 }


function disabled_users {

 awk -F: '/^[^#:]+:[^!\*:]*:[^:]*:[^:]*:[^:]*:[^:]*:(\s*|-1|3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):[^:]*:[^:]*\s*$/ {print $1":"$7}' /etc/shadow || return 1

#echo >> ./$LOGFILE
}

function inactive_pass {
 useradd -D -f 30
}



function last_pass {

  #check last changed password date
   awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; \
   do change=$(date -d "$(passwd -S "$usr" | awk '{print $3}'| grep -v 'never$')" +%s); \
   if [[ "$change" -gt "$(date +%s)" ]]; then \
   echo_red "User: \"$usr\" last password change is on the future : \"$(passwd -S "$usr" | awk '{print $3}')\""
   echo_red "User: \"$usr\" last password change is on the future : \"$(passwd -S "$usr" | awk '{print $3}')\"" >> ./$LOGFILE
   echo "User: \"$usr\" will be locked, because its last password change date is on the future: \"$(passwd -S "$usr" | awk '{print $3}')\""
   passwd -l "$usr"

   fi
done

}

function secure_acc {
local users="$(awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/L?/) {print $1}')"
 passwd -l $users

 echo "Accounts that configured the shell as nologin but their password were  not locked:  ${users}" >> ./$LOGFILE
 echo "Accounts that configured the shell as nologin but their password were  not locked:  ${users}"

}


function root_gid {
 usermod -g 0 root
}

function otherfiles_conf_parm {
#comment out any  parameter entries in files ending in *.conf in the /etc/ssh/sshd_config.d/ directory  that include any setting other than propper value.

 local arg="${1}"
  local value="${2}"
  local file="${3}"
 grep -Pi "^\h*${arg}\b" ${file} | grep -Evi ${value} | while read -r l_out; do sed -ri "/^\s*${arg}\s*+/s/^/# /" "$(awk -F: '{print $1}' <<< $l_out)";done
      
}




function world_writable_files {
   echo "6.1.9  World Writable Files - Remove write access for the "other" category (chmod o-w <filename>) : " >>  $MANUAL_FIX
   df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >>  $MANUAL_FIX
   echo "---------------------------------------------------------------------------------------" >>  $MANUAL_FIX
 }
 
function unowned_files {
 echo "6.1.10 Reset the ownership of these files to some active user on the system as appropriate(chown): " >>  $MANUAL_FIX
 df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser >>  $MANUAL_FIX
 echo "---------------------------------------------------------------------------------------"     >>  $MANUAL_FIX
}

function ungrouped_files {
   echo "6.1.11 Reset the ownership of these files to some active group on the system as appropriate(chown): " >>  $MANUAL_FIX
   df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup >>  $MANUAL_FIX
   echo "---------------------------------------------------------------------------------------"     >>  $MANUAL_FIX
}
  
  
function SUID_executables {
 echo "6.1.12 Ensure that no rogue SUID programs have been introduced into the system.
 Review the files returned and confirm the integrity of these binaries: " >>  $MANUAL_FIX
 df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 >>  $MANUAL_FIX
 echo "---------------------------------------------------------------------------------------"     >>  $MANUAL_FIX
}

function SGID_executables {
 echo "6.1.13  Ensure that no rogue SGID programs have been introduced into the system.
 Review the files returned and confirm the integrity of these binaries: " >>  $MANUAL_FIX
 df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 >>  $MANUAL_FIX
 echo "---------------------------------------------------------------------------------------"     >>  $MANUAL_FIX
}
 
function audit_sys_rpm {
  echo "6.1.15 It is important to confirm that packaged system files and directories are maintained with
the permissions they were intended to have from the OS vendor. " >  $LOGDIR/rpm_packages_permissions_$TIME.log
  rpm -Va --nomtime --nosize --nomd5 --nolinkto >>   $LOGDIR/rpm_packages_permissions_$TIME.log
}

function sticky_bit {
echo -e "6.1.12 Setting the sticky bit on world writable directories prevents users from deleting or
renaming files in that directory that are not owned by them\n" > $LOGDIR/sticky_on_world_$TIME.log
 df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}' >> $LOGDIR/sticky_on_world_$TIME.log
}

function shadow_password {
  sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i ${PASSWD}
}
    
function empty_pass {
 awk -F: '($2 == "" ) {print $1}' ${SHADOW} | while read -r usr; do
 passwd -l $usr
done
}

function groups_passwd {
for i in $(cut -s -d: -f4 ${PASSWD} | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" ${GROUP}
   if [ $? -ne 0 ]; then
     echo "6.2.3 Group $i is referenced by /etc/passwd but does not exist in /etc/group" >>  $MANUAL_FIX
     echo "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
     return 1
   fi
  done
}

function duplicate_UID {
  cut -f3 -d":" ${PASSWD} | sort -n | uniq -c | while read x ; do
  [ -z "$x" ] && break
  set - $x
  if [ $1 -gt 1 ]; then
   users=$(awk -F: '($3 == n) { print $1 }' n=$2 ${PASSWD} | xargs)
   echo "6.2.5 Based on the results , Analyze the output of and perform the appropriate action to correct
any discrepancies found."  >>   $MANUAL_FIX
   echo "Duplicate UID ($2): $users" >>   $MANUAL_FIX
   echo "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
  fi
 done
}


function shadow_empty {
 sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' ${GROUP}
}

function duplicate_GID {
# delete empty groups by grpck
cut -d: -f3 ${GROUP} | sort | uniq -d | while read x ; do
 echo "6.2.6 Based on the results , establish unique GIDs and review all files
owned by the shared GID to determine which group they are supposed to belong to."  >>   $MANUAL_FIX
   echo "Duplicate GID ($x) in /etc/group" >>   $MANUAL_FIX
   echo "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
 done
}

function duplicate_username {
 cut -d: -f1 ${PASSWD} | sort | uniq -d | while read -r x; do
  echo "6.2.7 Based on the results , establish unique user names for the users. File
  ownerships will automatically reflect the change as long as the users have unique UIDs."  >>   $MANUAL_FIX
   echo "Duplicate login name $x in /etc/passwd" >>   $MANUAL_FIX
   echo "---------------------------------------------------------------------------------------)"  >>  $MANUAL_FIX
 done
}

function duplicate_groupname {
  cut -d: -f1 ${GROUP} | sort | uniq -d | while read -r x; do
  echo "6.2.8 Based on the results , establish unique names for the user groups. File group 
  ownerships will automatically reflect the change as long as the groups have unique GIDs."  >>   $MANUAL_FIX
  echo "Duplicate group name $x in /etc/group" >>   $MANUAL_FIX
  echo "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
done
} 
 

function root_path {
  echo "6.2.9 -Checking root path,Based on results,Correct or justify any items." >>  $MANUAL_FIX
local RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
 echo "$RPCV" | grep  "::" && echo "root's path contains a empty directory (::)" >>  $MANUAL_FIX
 echo "$RPCV" | grep  ":$" && echo "root's path contains a trailing (:)" >>  $MANUAL_FIX
 for x in $(echo "$RPCV" | tr ":" " "); do
   if [ -d "$x" ]; then
    ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"}  $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}' >>  $MANUAL_FIX
    else
   echo "$x is not a directory" >>  $MANUAL_FIX
  fi
 done
echo "---------------------------------------------------------------------------------------"  >>  $MANUAL_FIX
}

function root_uid {
 awk -F: '($3 == 0 ) { print $1 }' ${PASSWD} | while read -r u0usr; do
  if [ "$u0usr" != "root" ]; then
     echo "User: \"$u0usr\" will be locked, because it has UID 0 which belongs to root account" >> ./$LOGFILE
     echo "User: \"$u0usr\" will be locked, because it has UID 0 which belongs to root account"
     usermod -L $u0usr
  fi
 done
}

function home_dirs_exist {
local valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' ${PASSWD} | while read -r user home; do
  if [ ! -d "$home" ]; then
   echo -e "\n- User \"$user\" home directory \"$home\" doesn't exist\n- creating home directory \"$home\"\n" >> ./$LOGFILE
    echo -e "\n- User \"$user\" home directory \"$home\" doesn't exist\n- creating home directory \"$home\"\n"
     mkdir "$home"
    chmod g-w,o-wrx "$home"
   chown "$user" "$home"
  fi
 done
} 
 
function home_dirs_owner {
  local output=""
  local valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
  awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' "${PASSWD}" | while read -r user home; do
  owner="$(stat -L -c "%U" "$home")"
  if [ "$owner" != "$user" ]; then
    echo -e "\n- User \"$user\" home directory \"$home\" is owned by user \"$owner\"\n - changing ownership to \"$user\"\n"
    echo -e "\n- User \"$user\" home directory \"$home\" is owned by user \"$owner\"\n - changing ownership to \"$user\"\n" >> ./$LOGFILE
    chown "$user" "$home"
    echo  "$user" "$home"
  fi
  done
}


function home_dirs_perm {
 local perm_mask='0027'
 local maxperm="$( printf '%o' $(( 0777 & ~$perm_mask)) )"
 valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' ${PASSWD} | (while read -r user home; do
 mode=$( stat -L -c '%#a' "$home" )
 if [ $(( $mode & $perm_mask )) -gt 0 ]; then
  echo -e "- modifying User $user home directory: \"$home\"\nremoving excessive permissions from current mode of \"$mode\""
  echo -e "- modifying User $user home directory: \"$home\"\nremoving excessive permissions from current mode of \"$mode\"" >> ./$LOGFILE
  chmod g-w,o-rwx "$home"
  fi
 done
 )
}

function remove_netrc {
 local perm_mask='0177'
 local valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' ${PASSWD}| while read -r user home; do
  if [ -f "$home/.netrc" ]; then
   echo -e "\n- User \"$user\" file: \"$home/.netrc\" exists\n -removing file: \"$home/.netrc\"\n" >> $LOGFILE
   echo -e "\n- User \"$user\" file: \"$home/.netrc\" exists\n -removing file: \"$home/.netrc\"\n"
   rm -f "$home/.netrc"
  fi
 done
}

function remove_forward {
  local output=""
  local fname=".forward"
  local valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
   awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' ${PASSWD} | (while read -r user home; do
    if [ -f "$home/$fname" ]; then
     echo -e "$output\n- User \"$user\" file: \"$home/$fname\" exists\n - removing file: \"$home/$fname\"\n" >> $LOGFILE
     echo -e "$output\n- User \"$user\" file: \"$home/$fname\" exists\n - removing file: \"$home/$fname\"\n"
	rm -r "$home/$fname"
   fi
  done
 )
}

function remove_rhosts {
 local perm_mask='0177'
 local valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' ${PASSWD} | while read -r user home; do 
  if [ -f "$home/.rhosts" ]; then
   echo -e "\n- User \"$user\" file: \"$home/.rhosts\" exists\n -removing file: \"$home/.rhosts\"\n" >> $LOGFILE
   echo -e "\n- User \"$user\" file: \"$home/.rhosts\" exists\n -removing file: \"$home/.rhosts\"\n"
   rm -f "$home/.rhosts"
  fi
 done
}
 
function dot_files {
 local perm_mask='0022'
 local valid_shells="^($( sed -rn '/^\//{s,/,\\\\/,g;p}' /etc/shells | paste -s -d '|' - ))$"
 awk -v pat="$valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' ${PASSWD} | while read -r user home; do
  find "$home" -type f -name '.*' | while read -r dfile; do
   local mode=$( stat -L -c '%#a' "$dfile" )
    if [ $(( $mode & $perm_mask )) -gt 0 ]; then
     echo -e "\n- Modifying User \"$user\" file: \"$dfile\"\nremoving group and other write permissions" >> $LOGFILE
     echo -e "\n- Modifying User \"$user\" file: \"$dfile\"\nremoving group and other write permissions"
     chmod go-w "$dfile"
    fi
   done
  done
}


function history_time {
 grep -q "HISTTIMEFORMAT=" ${PROFILE_FILE} || echo "export HISTTIMEFORMAT=\"%d.%m.%y %T  \"" >> ${PROFILE_FILE}
}




========================================================================================================

  clear
  echo -e "\n\n IP Address : $IP_ADR"       > ./$LOGFILE
  echo -e "\n Host Name    : $(hostname)"  >> ./$LOGFILE
  echo -e "\n OS Version   : $OS_VERSION"  >> ./$LOGFILE
  echo -e "\n Date : $(date '+%Y.%m.%d')             Time: $(date '+%H:%M') "  >> ./$LOGFILE
  echo -e "\n State           Index           Defined Argument" >> ./$LOGFILE
  echo -e "==============================================================" >> ./$LOGFILE


  
  function f_return {
    let TOTAL++
    func_name=$1
    shift
    args=$@
    printf "${func_name} ${args}: "
    ${func_name} ${args} >/dev/null 2>&1
    if [[ "$?" -eq 0 ]]; then
      let PASS++
      echo_green   [Applied]
      echo_green "Applied          $func_name                          $args" >> ./$LOGFILE
      echo  -e "-----------------------------------------------------------" >> ./$LOGFILE

      else
      let FAILED++
      echo_red   [NOT Applied]
 
      echo_red   "Not Applied      $func_name                          $args" >> ./$LOGFILE
      echo  -e "-----------------------------------------------------------" >> ./$LOGFILE

    fi
   }



 echo_bold "#### 1.1.1.1 Ensure mounting of cramfs filesystems is disabled #####"
  f_return   disable_fs cramfs
  f_return   disable_fs udf
  f_return   disable_fs squashfs

 echo_bold "##### 1.1.23 Disable Automounting  #####"
  f_return   service_disabled  autofs

 echo_bold "##### 1.1.24 Disable USB Storage  #####"
  f_return  disable_fs usb-storage

 echo_bold "##### 1.3.1 Ensure AIDE is installed #####"
   f_return  package_install aide
   f_return  package_install aide-common

 echo_bold "##### 1.4.2 Ensure permissions on bootloader config are configured" 
  f_return  set_file_perms  ${GRUB_CFG} 400
  f_return  set_file_owner  ${GRUB_CFG} :root

 echo_bold "##### 1.5.1 Ensure address space layout randomization (ASLR) is enabled"
  f_return  replace_param "kernel.randomize_va_space=" 2 ${ASLR}
  f_return  sysctl_param  "kernel.randomize_va_space=2"

 echo_bold "##### 1.5.2 Ensure prelink is not installed #####"
 f_return  package_remove  prelink

 echo_bold "##### 1.5.3 Ensure Automatic Error Reporting is not enabled"
  f_return service_disabled apport
  f_return replace_param "enabled=" 0 ${APPPORT} 

 echo_bold "##### 1.5.4 Ensure core dumps are restricted"
  backup ${SEC_LIMITS}
  backup ${SYSCTL_CONF}
  f_return service_disabled coredump
  f_return sysctl_param "fs.suid_dumpable=0"
  replace_param '* hard core' 0 ${SEC_LIMITS}
  replace_param 'fs.suid_dumpable=' 0 ${SYSCTL_CONF}

 echo_bold "##### 1.6.1.1 Ensure AppArmor is installed"
  f_return package_install apparmor

 echo_bold "##### 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration"
  backup ${GRUB_DF}
  apparmor_grub 
  update-grub

 echo_bold "##### 1.6.1.3 Ensure all AppArmor Profiles are in  complain mode "
  f_return apparmor

  echo_bold "##### 1.7.1 - 3 Command Line Warning Banners #####"
   f_return  login_banner ${MOTD}
   f_return  login_banner ${ISSUE}
   f_return  ssh_banner  
 
  echo_bold "##### 1.7.4 - 6 Ensure permissions on warning banners files #####"
   f_return  set_file_perms  ${MOTD}  644
   f_return  set_file_perms  ${ISSUE} 644
   f_return  set_file_perms  ${ISSUE_NET} 64
   
  echo_bold "##### 1.8.1 Ensure GNOME Display Manager is removed"
   f_return  package_remove  gdm3

  echo_bold "##### 1.9 Ensure updates, patches, and additional security software are installed"
   chk_update
   
   #checking Servicess Configuration
  echo_red "\n**********2.Services **********\n"

 
  echo_bold "##### 2.1.1 Ensure time sync is in use"
#  f_return package_install chrony 
   f_return package_remove ntp
   f_return service_disabled systemd-timesyncd 

 echo_bold "##### 2.2.1 - 2.3.6  Removing lagacy services . . .  "
  f_return package_remove xserver-xorg*
  f_return package_remove avahi-daemon
  f_return package_remove cups
  f_return package_remove isc-dhcp-server
  f_return package_remove slapd
  f_return package_remove snfs-kernel-server
  f_return package_remove bind9
  f_return package_remove vsftpd
  f_return package_remove apache2
  f_return package_remove dovecot-imapd 
  f_return package_remove dovecot-pop3d
  f_return package_remove samba
  f_return package_remove squid
  f_return package_remove snmp
  f_return package_remove nis
  f_return package_remove postfix
  f_return package_remove rsync
  f_return package_remove nis
  f_return package_remove rsh-client
  f_return package_remove talk
  f_return package_remove telnet
  f_return package_remove ldap-utils
  f_return package_remove rpcbind

# Checking Network Configuration
  echo_red "\n********** Network Configuration **********\n"

  echo_bold "##### 3.1.1 Ensure system is checked to determine if IPv6 is NOT enabled "
   f_return  sysctl_param  "net.ipv6.conf.all.disable_ipv6=1"
   f_return  sysctl_param  "net.ipv6.conf.default.disable_ipv6=1"
   f_return  sysctl_param  "net.ipv6.route.flush=1"
   f_return replace_param  "net.ipv6.conf.all.disable_ipv6=" 1     ${SYSCTL_CONF}
   f_return replace_param  "net.ipv6.conf.default.disable_ipv6=" 1 ${SYSCTL_CONF}
   ipv6_grub 

  echo_bold "##### 3.1.2 Ensure wireless interfaces are disabled"
   f_return wlan_disabled 


  
  
#As flushing the routing table can temporarily disrupt network connectivity until the routing table is rebuilt

echo_bold "##### 3.2.1 Ensure packet redirect sending is disabled"
 backup ${SYSCTL_CONFv4}
 backup ${SYSCTL_CONFv6}
 f_return  replace_param "net.ipv4.conf.all.send_redirects=" 0  ${SYSCTL_CONFv4}
 f_return  replace_param "net.ipv4.conf.default.send_redirects=" 0 ${SYSCTL_CONFv4}
 f_return  sysctl_param  "net.ipv4.conf.all.send_redirects=0"
 f_return  sysctl_param  "net.ipv4.conf.default.send_redirects=0"

echo_bold "##### 3.2.2 Ensure IP forwarding is disabled "
 f_return  replace_param "net.ipv4.ip_forward=" 0 ${SYSCTL_CONFv4}
 f_return  sysctl_param  "net.ipv4.ip_forward=0"

 echo_bold "Checking IPV6:"
 f_return  replace_param "net.ipv6.conf.all.forwarding=" 0 ${SYSCTL_CONFv6}
 f_return  sysctl_param  "net.ipv6.conf.all.forwarding=0"

echo_bold "##### 3.3.1 Ensure source routed packets are not accepted "
 f_return  replace_param "net.ipv4.conf.all.accept_source_route=" 0  ${SYSCTL_CONFv4}
 f_return  replace_param "net.ipv4.conf.default.accept_source_route=" 0  ${SYSCTL_CONFv4}
 f_return  sysctl_param  "net.ipv4.conf.all.accept_source_route=0"
 f_return  sysctl_param  "net.ipv4.conf.default.accept_source_route=0"

 echo_bold "Checking IPV6:"
 f_return  replace_param "net.ipv6.conf.all.accept_source_route=" 0  ${SYSCTL_CONFv6}
 f_return  replace_param "net.ipv6.conf.default.accept_source_route=" 0  ${SYSCTL_CONFv6}
 f_return  sysctl_param  "net.ipv6.conf.all.accept_source_route=0"
 f_return  sysctl_param  "net.ipv6.conf.default.accept_source_route=0"

echo_bold "##### 3.3.2 Ensure ICMP redirects are not accepted "
 f_return replace_param "net.ipv4.conf.all.accept_redirects=" 0  ${SYSCTL_CONFv4}
 f_return replace_param "net.ipv4.conf.default.accept_redirects=" 0  ${SYSCTL_CONFv4}
 f_return sysctl_param  "net.ipv4.conf.all.accept_redirects=0"
 f_return sysctl_param  "net.ipv4.conf.default.accept_redirects=0"

 echo_bold "Checking IPV6:"
 f_return replace_param "net.ipv6.conf.all.accept_redirects=" 0  ${SYSCTL_CONFv6}
 f_return replace_param "net.ipv6.conf.default.accept_redirects=" 0  ${SYSCTL_CONFv6}
 f_return sysctl_param  "net.ipv6.conf.all.accept_redirects=0"
 f_return sysctl_param  "net.ipv6.conf.default.accept_redirects=0"

 echo_bold "##### 3.3.3 Ensure secure ICMP redirects are not accepted "

 f_return replace_param  "net.ipv4.conf.default.secure_redirects=" 0  ${SYSCTL_CONFv4}
 f_return replace_param  "net.ipv4.conf.all.secure_redirects=" 0  ${SYSCTL_CONFv4}
 f_return sysctl_param   "net.ipv4.conf.all.secure_redirects=0"
 f_return sysctl_param   "net.ipv4.conf.default.secure_redirects=0"

echo_bold "#####3.3.4 Ensure suspicious packets are logged  "
 f_return replace_param "net.ipv4.conf.all.log_martians=" 1  ${SYSCTL_CONFv4}
 f_return replace_param "net.ipv4.conf.default.log_martians=" 1  ${SYSCTL_CONFv4}
 f_return sysctl_param  "net.ipv4.conf.default.log_martians=1" 
 f_return sysctl_param  "net.ipv4.conf.all.log_martians=1"

echo_bold "##### 3.3.5 Ensure broadcast ICMP requests are ignored "
 f_return replace_param "net.ipv4.icmp_echo_ignore_broadcasts=" 1 ${SYSCTL_CONFv4}
 f_return sysctl_param  "net.ipv4.icmp_echo_ignore_broadcasts=1"

echo_bold "##### 3.3.6 Ensure bogus ICMP responses are ignored  "
 f_return replace_param "icmp_ignore_bogus_error_responses=" 1 ${SYSCTL_CONFv4}
 f_return sysctl_param  "icmp_ignore_bogus_error_responses=1"

echo_bold "##### 3.3.7 Ensure Reverse Path Filtering is enabled" 
 f_return replace_param "net.ipv4.conf.all.rp_filter=" 1  ${SYSCTL_CONFv4}
 f_return replace_param "net.ipv4.conf.default.rp_filter=" 1  ${SYSCTL_CONFv4}
 f_return sysctl_param  "net.ipv4.conf.default.rp_filter=1"
 f_return sysctl_param  "net.ipv4.conf.all.rp_filter=1"

echo_bold "##### 3.3.8 Ensure TCP SYN Cookies is enabled "
 f_return replace_param "net.ipv4.tcp_syncookies=" 1  ${SYSCTL_CONFv4}
 f_return sysctl_param  "net.ipv4.tcp_syncookies=1"

echo_bold "##### 3.3.9 Ensure IPv6 router advertisements are not accepted "
 f_return replace_param "net.ipv6.conf.all.accept_ra=" 0  ${SYSCTL_CONFv6}
 f_return replace_param "net.ipv6.conf.default.accept_ra=" 0  ${SYSCTL_CONFv6}
 f_return sysctl_param  "net.ipv6.conf.default.accept_ra=0"
 f_return sysctl_param  "net.ipv6.conf.all.accept_ra=0"

 f_return  sysctl_param  "net.ipv4.route.flush=1"
 f_return  sysctl_param  "net.ipv6.route.flush=1"


 echo_bold "#####3.4.1-4  Ensure uncommon network protocol  is disabled "
  f_return  disable_fs dccp
  f_return  disable_fs sctp
  f_return  disable_fs RDS
  f_return  disable_fs TIPC

 echo_bold"##### 3.5.1.1 Ensure ufw is installed"
  f_return package_install ufw

 echo_bold "##### 3.5.1.2 Ensure iptables-persistent is not installed with ufw"
  f_return package_remove iptables-persistent

 echo_bold "###### 3.5.1.3 - 7 Ensure ufw service is enabled "
  f_return ufw_conf
  
    #Checking Logging and Auditing
  echo_red "\n********** 4.Logging and Auditing **********\n"
   

  echo_bold "###### 4.1.1.1 - 2  Ensure auditd is installed and active"
   f_return package_install  auditd 
   f_return package_install  audispd-plugins
   f_return service_enabled  auditd  

 echo_bold "4.1.1.3 Ensure auditd Config  for processes that start prior to auditd is enabled"
 echo_bold "4.1.1.4 Ensure audit_backlog_limit is sufficient "
  auditd_grub

  echo_bold "##### 4.1.2 Config audit log setting #####"
   backup ${AUDITD_CNF}
   replace_parm_nospace "max_log_file_action=" ROTATE ${AUDITD_CNF}
   replace_parm_nospace "max_log_file=" 50 ${AUDITD_CNF}
   replace_parm_nospace "space_left_action=" ROTATE ${AUDITD_CNF}
   replace_parm_nospace "admin_space_left_action=" ROTATE ${AUDITD_CNF}
   replace_parm_nospace "disk_full_action=" ROTATE ${AUDITD_CNF}
   replace_parm_nospace "disk_error_action=" SYSLOG ${AUDITD_CNF}
   service auditd  restart

  echo_bold "##### 4.1.4.1 - 4 Ensure audit log files have proper or more restrictive permission and owner #####"
   f_return audit_log_perm

  echo_bold "##### 4.1.4.5 - 7 Ensure audit configuration files have 640 or more restrictive permission and owner"
   f_return audit_conf_perm

  echo_bold "##### 4.1.4.8 - 10 Ensure audit tools have proper or more restrictive permission and owner #####"
   f_return audit_tools_perm

  echo_bold "#####  4.2.1.1.4 Ensure journald is not configured to recieve logs from a remote client #####"
   f_return service_disabled systemd-journal-remote.socket  

  echo_bold "##### 4.2.1.2 Ensure journald service is enabled"
    f_return service_enabled  systemd-journald

  echo_bold "##### 4.2.1.3 Ensure journald is configured to compress large log files"
   f_return replace_param  "Compress=" yes  ${JOURNAL_CONF}

  echo_bold "##### 4.2.1.4 Ensure journald is configured to write logfiles to persistent disk"
   f_return replace_param  "Storage=" persistent  ${JOURNAL_CONF}
   systemctl restart systemd-journald

  echo_bold "##### 4.2.2.1-2 Ensure rsyslog is installed and enabled"
   f_return package_install rsyslog
   f_return service_enabled rsyslog
  
  echo_bold "##### 4.2.2.4 Ensure rsyslog default file permissions are configured"
   f_return replace_param '$FileCreateMode' 0640 ${RSYS_CONF}
   systemctl restart rsyslog

  echo_bold "##### 4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client"
   f_return rsyslog_remote

  echo_bold "##### 4.2.3 Ensure all logfiles have appropriate permissions and ownership #####"
   f_return varlog_perm

  echo_bold "##### 5.1.1 Ensure cron daemon is enabled and running "
   f_return service_enabled cron

  echo_bold "##### 5.1.1 - 7 Ensure permissions on Cron files are configured #####"
   f_return set_file_perms ${CRONTAB}      600
   f_return set_file_perms ${CRON_DIR}     700
   f_return set_file_perms ${CRON_DAILY}   700
   f_return set_file_perms ${CRON_HOURLY}  700
   f_return set_file_perms ${CRON_WEEKLY}  700
   f_return set_file_perms ${CRON_MONTHLY} 700
      
   f_return set_file_owner ${CRONTAB}      root:root
   f_return set_file_owner ${CRON_DIR}     root:root
   f_return set_file_owner ${CRON_DAILY}   root:root
   f_return set_file_owner ${CRON_HOURLY}  root:root
   f_return set_file_owner ${CRON_WEEKLY}  root:root
   f_return set_file_owner ${CRON_MONTHLY} root:root
   

  echo_bold "##### 5.1.8 - 9 Ensure cron and at is restricted to authorized users #####"
   backup ${CRON_DENY}
   backup ${AT_DENY}
   f_return cron_at_access 

  echo_bold "##### 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured #####"
   f_return set_file_perm  ${SSHD_CFG} 600
   f_return set_file_owner ${SSHD_CFG} root:root

  echo_bold "##### 5.2.2-3  Ensure permissions on SSH private and public host key files are configured #####"
   f_return ssh_key_perm 

  echo_bold "##### 5.2.5 - 20 Configure SSHD Config #####"
   backup ${SSHD_CFG}
   echo "disable RootLogin will not apply"
   #f_return replace_param PermitRootLogin no ${SSHD_CFG}
   f_return replace_param LogLevel VERBOSE ${SSHD_CFG}
   f_return replace_param UsePAM yes ${SSHD_CFG}
   f_return replace_param HostbasedAuthentication no ${SSHD_CFG}
   f_return replace_param PermitEmptyPasswords no ${SSHD_CFG}
   f_return replace_param PermitUserEnvironment no ${SSHD_CFG}
   f_return replace_param IgnoreRhosts yes ${SSHD_CFG}
   f_return replace_param X11Forwarding no ${SSHD_CFG}
   f_return replace_param AllowTcpForwarding no ${SSHD_CFG}
   f_return replace_param Banner /etc/issue.net ${SSHD_CFG}
   f_return replace_param MaxAuthTries 4 ${SSHD_CFG}
   f_return replace_param MaxStartups 10:30:60 ${SSHD_CFG}
   f_return replace_param MaxSessions 10 ${SSHD_CFG}
   f_return replace_param LoginGraceTime 60 ${SSHD_CFG}
   f_return replace_param ClientAliveInterval  900 ${SSHD_CFG}
   f_return replace_param ClientAliveCountMax 1 ${SSHD_CFG}
  
  echo_bold "##### 5.2.5 - 20 check and configure SSHD Config in other files"
   otherfiles_conf_param  HostbasedAuthentication no "${SSHD_ALL}"
   otherfiles_conf_param  PermitEmptyPasswords no "${SSHD_ALL}"
   otherfiles_conf_param  PermitUserEnvironment no "${SSHD_ALL}"
   otherfiles_conf_param  IgnoreRhosts yes "${SSHD_ALL}"
   otherfiles_conf_param  X11Forwarding no "${SSHD_ALL}"
   otherfiles_conf_param  AllowTcpForwarding no "${SSHD_ALL}"
   otherfiles_conf_param  Banner /etc/issue.net "${SSHD_ALL}"
   otherfiles_conf_param  MaxAuthTries 4 "${SSHD_ALL}"
   otherfiles_conf_param  MaxStartups 10:30:60 "${SSHD_ALL}"
   otherfiles_conf_param  MaxSessions 10 "${SSHD_ALL}"
   otherfiles_conf_param  LoginGraceTime 60 "${SSHD_ALL}"
   otherfiles_conf_param  ClientAliveInterval 900 "${SSHD_ALL}"
   otherfiles_conf_param  ClientAliveCountMax 1 "${SSHD_ALL}"
   service sshd restart >/dev/null 2>&1
   
   
 echo_bold "##### 5.2.13 Ensure only strong Ciphers are used "
  f_return  cipher_algorithm

 echo_bold "##### 5.2.14 Ensure only strong MAC algorithms are used "
  f_return  mac_algorithm

 echo_bold "##### 5.2.15 Ensure only strong Key Exchange algorithms are used "
  f_return  kex_algorithm

 echo_bold "##### 5.3.1 Ensure sudo is installed"
  f_return package_install sudo

 echo_bold "##### 5.3.2 Ensure sudo commands use pty "
  replace_parm_simple "Defaults use_pty" ${SUDO_CONF}

 echo_bold "##### 5.3.3 Ensure sudo log file exists "
  replace_parm_simple 'Defaults logfile="/var/log/sudo.log"' ${SUDO_CONF}

 echo_bold "##### 5.3.4 Ensure users must provide password for escalation"
  f_return escalation_sudo

 echo_bold "##### 5.3.5 Ensure re-authentication for privilege escalation is not disabled globally"
  f_return reauth_escalation_sudo

 echo_bold "##### 5.3.6 Ensure sudo authentication timeout is configured correctly"
  f_return auth_timeout_sudo

 echo_bold "##### 5.3.7 Ensure access to the su command is restricte #####"
  backup  ${PAM_SU}
  f_return pam_su

 echo_bold "5.4.1 Esure password creation requirements are configured" 
  backup ${PWQUAL_CNF}
  backup ${COMMONPASSWD}
  backup ${COMMONACCOUNT}
  backup ${COMMONAUTH}
  f_return package_install libpam-pwquality 
  f_return package_install cracklib-runtime
  f_return replace_param  "minclass=" 4  ${PWQUAL_CNF}
  f_return replace_param  "minlen=" 14   ${PWQUAL_CNF}

 echo_bold "5.4.2 Ensure lockout for failed password attempts is configured"
  enable_faillock
  replace_param "deny ="  5 ${FAIL_CONF}
  replace_param "unlock_time ="  900 ${FAIL_CONF}
  replace_param "enforce_for_root" ""  ${PWQUAL_CNF}
  replace_param "even_deny_root" ""   ${FAIL_CONF}
  replace_param "silent" "" ${FAIL_CONF}
  replace_param "audit" ""  ${FAIL_CONF}
  replace_param "even_deny_root" "" ${FAIL_CONF}
  service sshd restart >/dev/null 2>&1 

 echo_bold "##### 5.4.3 Ensure password reuse is limited #####"
  f_return pass_reuse
  
  echo_bold "##### 5.4.4 Ensure password hashing algorithm is uptodate (yescrypt) ####"
  f_return  remove_hash
  replace_param ENCRYPT_METHOD yescrypt ${LOGIN_DEFS}

 echo_bold "Ensure password hashing algorithm is up to date with the latest standards"
  current_hash

 echo_bold "##### 5.5.1.1 Ensure minimum days between password changes is 7 or more #####"
  replace_param PASS_MIN_DAYS 1   ${LOGIN_DEFS}

 echo_bold "##### 5.5.1.2 Ensure password expiration is 365 days or less #####"
  replace_parm PASS_MAX_DAYS 365 ${LOGIN_DEFS} 
 
 echo_bold "##### 5.5.1.3 Ensure password expiration warning days is 7 or more #####"
   replace_parm PASS_WARN_AGE 7 ${LOGIN_DEFS}  
   update_chage
  # you can add any specific user,inactive password lock will not set on these users.
  f_return update_chage_specific root

 echo_bold "##### 5.5.1.4 Ensure inactive password lock is 30 days or less "
  f_return inactive_pass

 echo_bold "##### 5.5.1.5 Ensure all users last password change date is in the past #####" 
  f_return last_pass

 echo_bold "##### 5.5.2 Ensure system accounts are secured #####"
  f_return secure_acc

 echo_bold "##### 5.5.3 ensure default group for the root account is GID 0 #####"
  f_return root_gid

 echo_bold "##### 5.5.4 Ensure default user umask is 027 or more restrictive #####"
  otherfiles_conf_param umask 027 "${PROFILE_D}"
  replace_param UMASK 027 ${LOGIN_DEFS}
  replace_param umask 027 ${BASHRC}
  replace_param USERGROUPS_ENAB no ${LOGIN_DEFS}
 
 echo_bold "##### 5.5.5 Shell Timeout#####"
  otherfiles_conf_param "readonly TMOUT=" "1800" "${PROFILE_D}"
  replace_param_nospace "readonly TMOUT=" "1800 ; export TMOUT" ${PROFILE_BASH}

 echo_bold "##### 6.1 set history time format #####"
  f_return history_time

 echo_bold "##### 6.1.1 - 8 Ensure permissions on passwd(-), group(-) and shadow(-) files are configures #####"
   f_return set_file_perms "${PASSWD}"   "u-x,go-wx"
   f_return set_file_perms "${PASSWD2}"  "u-x,go-wx" 
   f_return set_file_perms "${GROUP}"    "u-x,go-wx" 
   f_return set_file_perms "${GROUP2}"   "u-x,go-wx" 
   f_return set_file_perms "${SHADOW}"   "u-x,g-wx,o-rwx" 
   f_return set_file_perms "${SHADOW2}"  "u-x,g-wx,o-rwx"
   f_return set_file_perms "${GSHADOW}"  "u-x,g-wx,o-rwx"
   f_return set_file_perms "${GSHADOW2}" "u-x,g-wx,o-rwx"


   echo_bold "##### 6.1.1 - 8 Ensure owner on passwd(-), group(-) and shadow(-) files are configures #####"
   f_return set_file_owner "${PASSWD}"   "root:root"
   f_return set_file_owner "${PASSWD2}"  "root:root"
   f_return set_file_owner "${GROUP}"    "root:root"
   f_return set_file_owner "${GROUP2}"   "root:root"
   f_return set_file_owner "${SHADOW}"   "root:root"
   f_return set_file_owner "${SHADOW2}"  "root:root"
   f_return set_file_owner "${GSHADOW}"  "root:root"
   f_return set_file_owner "${GSHADOW2}" "root:root"

 echo_bold "##### 6.1.9 Ensure no world writable files exist (Manual) #####"
  f_return world_writable_files

   echo_bold "##### 6.1.10 Ensure no unowned files or directories exist (Manual) #####"
  f_return unowned_files

   echo_bold "##### 6.1.11 Ensure no ungrouped files or directories exist (Manual) #####"
  f_return ungrouped_files

echo_bold "##### 6.1.12 Audit SUID executables (Manual) #####"
  f_return SUID_executables

  echo_bold "##### 6.1.13 Audit SGID executables (Manual) #####"
  f_return SUID_executables

 echo_bold "##### 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords #####"
  f_return shadow_password

 echo_bold "##### 6.2.2 Ensure password fields are not empty #####"
  f_return empty_pass

 echo_bold "##### 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group #####"
  f_return groups_passwd

 echo_bold"##### 6.2.4 Ensure shadow group is empty"
  f_return  shadow_empty

 echo_bold "##### 6.2.5 Ensure no duplicate UIDs exist (Manual) #####"
  f_return duplicate_UID

 echo_bold "##### 6.2.6 Ensure no duplicate GIDs exist (Manual) #####"
  f_return duplicate_GID

  echo_bold "##### 6.2.7 Ensure no duplicate user names exist (Manual) #####"
  f_return duplicate_username

 echo_bold "##### 6.2.8 Ensure no duplicate group names exist (Manual) #####"
  f_return duplicate_groupname

 echo_bold "##### 6.2.9 Ensure root PATH Integrity (Manual) #####"
  f_return root_path

 echo_bold "##### 6.2.10 Ensure root is the only UID 0 account #####"
  f_return root_uid

 echo_bold "##### 6.2.11 Ensure local interactive user home directories exist #####"
  f_return home_dirs_exist 

 echo_bold "##### 6.2.12 Ensure local interactive users own their home directories #####"
  f_return home_dirs_owner

 echo_bold "##### 6.2.13 Ensure local interactive user home directories are mode 750 or more restrictive #####"
  f_return home_dirs_perm

 echo_bold "##### 6.2.14 Ensure no local interactive user has .netrc files #####"
  f_return  remove_netrc 
 
 echo_bold "##### 6.2.15 Ensure no local interactive user has .forward files #####"
  f_return remove_forward

 echo_bold "##### 6.2.16 Ensure no local interactive user has .rhosts files #####"
  f_return remove_rhosts

 echo_bold "##### 6.2.17 Ensure local interactive user dot files are not group or world writable #####"
  f_return dot_files
   

echo_bold "\n Hardening process successfully Completed!"
echo_bold "\n You can find changed files backup in \e[36m${BACKUP_DIR}\e[0m and hardening reports in \e[36m${LOGDIR}\e[0m."


results
###################END###################



