#!/bin/bash


#Program: Caliper v1.0
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
 Caliper 1.0
 Auditing Ubuntu 22
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




# Configuration files
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"
LOGFILE=log_$(date '+%Y%m%d.%H.%M')
LOGFILE_ERRORS=log_errors_$(date '+%Y%m%d.%H.%M')
LOGDIR="./$(hostname -s)_logs"
MANUAL_FIX="$LOGDIR/read_manual_fix.txt"
#IP_ADR=$(nmcli -f IP4.ADDRESS device show | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -n 1)
ASLR='/etc/sysctl.d/60-kernel_sysctl.conf'
APPPORT='/etc/default/apport'
SEC_LIMITS='/etc/security/limits.conf /etc/security/limits.d/*'
RSYSLOG_CONF='/etc/rsyslog.conf /etc/rsyslog.d/*.conf'
CHRONY_CONF='/etc/chrony.conf'
SYSCTL_CONF='/etc/sysctl.conf  /etc/sysctl.d/*.conf'
SYSCTL_CONFv4='/etc/sysctl.d/60-netipv4_sysctl.conf'
SYSCTL_CONFv6='/etc/sysctl.d/60-netipv6_sysctl.conf'
SUDOERS='/etc/sudoers* /etc/sudoers.d/*'
PROFILE_D='/etc/profile.d/bash_completion.sh'
AUDIT_TOOLS='/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules'
AUDIT_DIR='/etc/audit/'
FSTAB='/etc/fstab'
YUM_CONF='/etc/dnf/dnf.conf'
GRUB_CFG='/boot/grub/grub.cfg'
GRUB_DF='/etc/default/grub'
GRUB_DIR='/etc/grub.d'
RESCUE_DIR='/usr/lib/systemd/system/rescue.service'
DUMP_DIR='/etc/systemd/coredump.conf'
JOURNALD_CFG='/etc/systemd/journald.conf'
SECURETTY_CFG='/etc/securetty'
LIMITS_CNF='/etc/security/limits.conf'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
AUDIT_RULES='/etc/audit/audit.rules'
LOGR_SYSLOG='/etc/logrotate.d/syslog'
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
SYSTEM_AUTH='/etc/pam.d/system-auth'
PASS_AUTH='/etc/pam.d/password-auth'
PWQUAL_CNF='/etc/security/pwquality.conf'
PASS_AUTH='/etc/pam.d/password-auth'
PAM_SU='/etc/pam.d/su'
GROUP='/etc/group'
GROUP2='/etc/group-'
LOGIN_DEFS='/etc/login.defs'
LIB_USR='/etc/libuser.conf'
PASSWD='/etc/passwd'
PASSWD2='/etc/passwd-'
SHADOW='/etc/shadow'
SHADOW2='/etc/shadow-'
GSHADOW='/etc/gshadow'
GSHADOW2='/etc/gshadow-'
BASHRC='/etc/bash.bashrc'
PROF_D='/etc/profile.d'
PROFILE='/etc/profile'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
SUDO_CONF='/etc/sudoers'
PAM_SU='/etc/pam.d/su'
SUDOERS='/etc/sudoers*'
FAIL_CONF='/etc/security/faillock.conf'
PWQUAL_CNF='/etc/security/pwquality.conf'
COMMONPASSWD='/etc/pam.d/common-password'
COMMONACCOUNT='/etc/pam.d/common-account'
COMMONAUTH='/etc/pam.d/common-auth'
TOTAL=0
PASS=0
FAILED=0
. /etc/os-release
OS_VERSION="$(echo ${PRETTY_NAME})"


##Functions

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
echo_green   "Passed Items : $PASS $(create_bar $(($PASS / 10)))"
echo_red     "Failed Items : $FAILED  $(create_bar $((($FAILED+9) / 10)))"
echo_yellow  "Failure Percentage : $(expr $FAILED \* 100 / $TOTAL)%"

}


function echo_yellow {
  echo -e "\e[93m${@} \e[0m"
}


function echo_bold {
  echo -e "\e[1m${@} \e[0m"
}

function echo_red {
  echo -e "\e[91m${@} \e[0m"
}

function echo_green {
  echo -e "\e[92m${@} \e[0m"
}

function disable_fs {
  # Test the the supplied filesystem type $1 is disabled
 local module="${1}"
 if  lsmod | grep -q ${module}; then false;else true ; fi || return
 modprobe -n -v ${module} | grep -q "install \+/bin/false" || return
}

function service_disabled {
 local arg="${1}"
 if systemctl is-enabled ${arg} | grep -q enabled;then false;else true;fi || return
 if systemctl is-active ${arg} | grep -q "\bactive\b";then false;else true;fi || return

}

function service_enabled {
 local arg="${1}"
 if systemctl is-enabled ${arg} | grep -q enabled;then true;else false;fi || return
 if systemctl is-active ${arg} | grep -q "\bactive\b";then true;else false;fi || return

}

function aide {
	    systemctl status aidecheck.timer --no-pager


    }

function package_installed {
 # check if package installed
 local arg="${1}"
 dpkg -s ${arg}  >/dev/null 2>&1 && return 0 || return 1 || return
 dpkg -l | grep "${arg}\b" || return
 dpkg -s ${arg} | grep 'Status: install' || return
}

function package_not_installed {
 local arg="${1}"
 dpkg -s ${arg}  >/dev/null 2>&1 && return 1 || return 0 || return
 if dpkg -l | grep "^${arg}\b"; then false ;else true ;fi || return
}



function check_file_perm {
  # Check Perms on a supplied file match supplied pattern
  local file="${1}"
  local pattern="${2}"
  local perms=$(stat -L -c "%#a" "${file}" | rev | cut -c 1-3 | rev )
   if [ "${perms}" -le "${pattern}" ]; then true ; else false;fi || return
}

function check_root_owns {
  # Check if User/Group Owner on the specified file is root
  local file="${1}"
  stat -L -c "%u %g" ${file} | grep -q '^0 0' || return
}

function root_pass {
if grep -Eq '^root:\$[0-9]' ${SHADOW};then false;else true;fi ||  return 
}

function chk_param {
  local parameter="${1}" 
  local value="${2}" 
  local file="${3}"
 if cut -d\# -f1 "${file}" | tr -d '[[:space:]]' | grep -q ${parameter}${value} ; then  return 0;else return 1;fi || return
}


function chk_param2 {
  local file="${1}"
  local parameter="${2}"
  local value="${3}"
  [[ -z ${3} ]] && spacer="" || spacer="[[:space:]]"
  cut -d\# -f1 ${file} | egrep -q "^\s*${parameter}\b${spacer}${value}" || return
}


function chk_sysctl {
# check sysctl config for given argument 
 local flag="${1}"
 local value="${2}"
 sysctl ${flag} | grep "\b${value}\b" || return

}

function chk_apparmor {

apparmor_status | grep processes   >>$MANUAL_FIX
echo " verify the  profiles that  loaded in apparmor as complianed mode "  >>$MANUAL_FIX

}

function apparmor_grub {
grep '^GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' ${GRUB_DF} || return
}


function chk_grub_ipv6 {
grep '^GRUB_CMDLINE_LINUX="ipv6.disable=1"' ${GRUB_DF} || return
}

function chk_grub_auditd {
 grep '^GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"' ${GRUB_DF} ||  return
 grep '^GRUB_CMDLINE_LINUX="audit=1"' ${GRUB_DF} ||  return

}


function warning_banners {
  # Check that system login banners don't contain any OS information
  local motd
  local issue
  local issue_net
  motd="$( grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" ${MOTD})"
  issue="$( grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" ${ISSUE})"
  issue.net="$( grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" ${ISSUE_NET})"
  [[ -z "${motd}" ]] || return
  [[ -z "${issue}" ]] || return
  [[ -z "${issue_net}" ]] || return
}


function chrony_cfg {
 egrep -q "^(server|pool)" ${CHRONY_CONF} || return
 user="$(ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }')"
 
[[ -z "${user}" ]]  || return
}

function audit_merge {
  #test if Audit rules have changed
 if augenrules --check | grep  -q "No change"; then
   return 0
    else
   retuen 1
  echo "Rules configuration differences between what is currently running and what is on disk could
cause unexpected problems or may give a false impression of compliance requirements." >> $MANUAL_FIX
 fi
}

 #Extract the log file path from the auditd.conf
 log_file_path=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)
 # Get the directory path of the log file
 directory_log=$(dirname "$log_file_path")

function audit_log_perm1 {
 #check log files are mode 0640 or less permissive. Find files in the directory and its subdirectories based on permission criteria
 if [ -n "$(find ${directory_log} -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec stat -Lc "%n %#a" {} +)" ] ; then
   return  1
     else
   return  0
 fi
}

function audit_log_perm2 {
 #check user owner

  if [ -n "$(find ${directory_log} -type f ! -user root -exec stat -Lc "%n %U" {} +)" ] ; then
  return  1
    else
   return  0
 fi
}

function audit_log_perm3 {
 #check group owner
  if [ -n "$(find ${directory_log} -type f ! -group root -exec stat -Lc "%n %U" {} +)" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_log_perm4 {
 #check the audit log directory is 0750 or more restrictive
  if [ -n "$(stat -Lc "%n %a" ${directory_log} | grep -Pv -- '^\h*\H+\h+([0,5,7][0,5]0)')" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_conf_perm1 {
 #check the audit log directory is 0750 or more restrictive
 if find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$' >> ./$LOGFILE ;then
   return 1
    else
   return 0
 fi
}

function audit_conf_perm2 {
#check auditd dir user owner
  if [ -n "$(find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec stat -Lc "%n %U" {} +)" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_conf_perm3 {
#check auditd dir group owner
  if [ -n "$(find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec stat -Lc "%n %U" {} +)" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_tools_perm {
 #check audit tools permissions
 if stat -c "%n %a" ${AUDIT_TOOLS} | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$' >> ./$LOGFILE ;then return 1; else return 0;fi
 if stat -c "%n %U" ${AUDIT_TOOLS} | grep -Pv -- '^\h*\H+\h+root\h*$' >> ./$LOGFILE ;then return 1; else return 0;fi
 if stat -c "%n %a %U %G" ${AUDIT_TOOLS} | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$' >> ./$LOGFILE ;then return 1; else return 0;fi
}

function chk_journald_enabled {
  # Verify that the service journald is enabled
  systemctl list-unit-files | grep -q "systemd-journald" || return
  systemctl is-enabled "systemd-journald" | grep -q 'static' && return

  }


function rsyslog_remote {

if grep -P -- '^\h*module\(load="imtcp"\)' ${RSYSLOG_CONF};then >> $MANUAL_FIX & false;else true;fi || return  >> $MANUAL_FIX
if grep -P -- '^\h*input\(type="imtcp" port="514"\)' ${RSYSLOG_CONF};then >> $MANUAL_FIX & false ;else true;fi || return >> $MANUAL_FIX

}

function logfile_perm {
var=$(find /var/log/ -type f -perm /g+wx,o+rwx -exec ls -l "{}" +)
if test -z "$var" ;then true ;else false ;fi || return
}


function cron_auth_users {
 [[ ! -f ${CRON_DENY} ]] || return 
 check_root_owns "${CRON_ALLOW}"
 check_file_perm "${CRON_ALLOW}" 600 
}

function at_auth_users {
 [[ ! -f ${AT_DENY} ]] || return 
 check_root_owns "${AT_ALLOW}"
 check_file_perm "${AT_ALLOW}" 600 
}

function host_key {
  for hostkey in /etc/ssh/ssh_host_*_key; do
    f_return check_root_owns "${hostkey}" 
    f_return check_file_perm "${hostkey}" 600
  done
}

function pub_host_key {
  for pubhostkey in /etc/ssh/ssh_host_*_key.pub; do
    f_return check_root_owns "${pubhostkey}" 
    f_return check_file_perm "${pubhostkey}" 640
  done
  
}
  
function chk_ssh_conf2 {
 #check config using sshd command
 local arg="${1}" 
 local value="${2}" 
 sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -qi "${arg} ${value}" || return
}

function cipher_algorithm {
 grep -q "^KexAlgorithms" "$SSHD_CFG" 2> /dev/null || return
}

function kex_algorithm {
 grep -q "^Ciphers" "$SSHD_CFG" 2> /dev/null || return
}

function mac_algorithm {
 grep -qi "^Macs" "$SSHD_CFG" 2> /dev/null || return
}



function escalation_sudo {
   local escal="$(grep -r "^[^#].*NOPASSWD" ${SUDOERS})"
    echo "Remove any line with occurrences of !authenticate tags in the file"
    echo $reauth_escal
    echo $reauth_escal  >> ./$LOGFILE
   [[  -z "${escal}" ]] || return
} 
   
function reauth_escalation_sudo {
  local reauth_escal="$( grep -r "^[^#].*\!authenticate"  ${SUDOERS})"
    echo "Remove any line with occurrences of !authenticate tags in the file" >> ./$LOGFILE
    echo $reauth_escal
    echo $reauth_escal >> ./$LOGFILE
    [[  -z "${reauth_escal}" ]] || return
}

function  auth_timeout_sudo {
 local timeout="$(grep -v '^#' ${SUDOERS} | grep -oE '\s*timestamp_timeout=\s*([0-9]+)' | cut -d'=' -f2)"
 local timeout2="$(sudo -V | grep "Authentication timestamp timeout:" | cut -d" " -f4 | cut -d "." -f1)"
 if [[ $timeout -gt 15 ]] || [[ $timeout2 -gt 15 ]]; then
   echo $timeout
     echo $timeout >> ./$LOGFILE
       return 1
     else
   return 0
 fi
}


function su_access {
  grep -E '^\s*auth\s+required\s+pam_wheel\.so\s+(\S+\s+)*use_uid\s+(\S+\s+)*group=\S+\s*(\S+\s*)*(\s+#.*)?$' ${PAM_SU}| grep sugroup || return
  if [ -z "$(getent group sugroup | cut -d: -f4)" ]; then true ;else false ;fi || return
}

function faillock_enabled {
  fail="$(grep "pam_faillock.so" $COMMONACCOUNT)"
 fail2="$(grep "pam_faillock.so" ${COMMONAUTH})"
nullok="$(grep "nullok" ${COMMONAUTH})"
  [[ -n ${fail} && ${fail2} ]] || return
  [[ -z ${nullok} ]] || return 
}

function remember_passwd {
 grep -Pq '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' ${SYSTEM_AUTH} || return
 grep -Pq '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password_auth || return
 grep -Pq '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth || return

}

function nohash {

no_hash="$(grep -v ^# /etc/pam.d/common-password | grep -E "(yescrypt|md5|bigcrypt|sha256|sha512|blowfish)")"

[[ -z ${no_hash} ]]  || return

}



function chk_password_cnf {
   #check the values which may be changed by users manually

   grep_out1="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,5 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"
   grep_out2="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,4 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"
   grep_out3="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,6 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"
   grep_out4="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,7 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"


   #Password Expiration
   false_count1=$(echo $grep_out1 | xargs -n1 | while read num; do [[ $num -gt 0 && $num -lt 366 ]] || echo "false"; done | wc -l);echo $false_count1
   #minimum days between password changes:
   false_count2=$(echo $grep_out2 | xargs -n1 | while read num; do [[ $num -gt 0 && $num -lt 100 ]] || echo "false"; done | wc -l);echo $false_count2
   #expiration warning
   false_count3=$(echo $grep_out3 | xargs -n1 | while read num; do [[ $num -gt 6 && $num -lt 100 ]] || echo "false"; done | wc -l);echo $false_count3
   #inactive password lock:
   false_count4=$(echo $grep_out4 | xargs -n1 | while read num; do [[ $num -gt 0 && $num -lt 31 ]] || echo "false"; done | wc -l);echo $false_count4
  
  # Define the array with the values of false_counts
  false_counts=(false_count1 false_count2 false_count3 false_count4)

  # Loop through the array
  for count in "${false_counts[@]}"; do
    if [ "${!count}" -eq 0 ]; then
        true
    else
       false || return
    fi
  done

}

function inactive_usr_acs_locked {
  # After being inactive for a period of time the account should be disabled
  local days
  local inactive_threshold=30
  days="$(useradd -D | grep INACTIVE | cut -d= -f2)"
  [[ ${days} -ge ${inactive_threshold} ]] || return
}

function inactive_usr_password_disabled {
#Review list of users which INACTIVE PASSWORD LOCK feature is disabled for (value -1).
dis_users="$(awk -F: '/^[^#:]+:[^!\*:]*:[^:]*:[^:]*:[^:]*:[^:]*:(\s*|-1|3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):[^:]*:[^:]*\s*$/ {print $1":"$7}' /etc/shadow)"
echo "Users with inactivity password lock disabled :  ${dis_users}" >> ./$LOGFILE
echo "Users with inactivity password lock disabled :  ${dis_users}" >> ./$LOGFILE_ERRORS
echo "Users with inactivity password lock disabled :  ${dis_users}"
[[ -z ${dis_users} ]] || return

}

function last_pass {

  #check last changed password date
   awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; \
   do change=$(date -d "$(passwd -S "$usr" | awk '{print $3}'| grep -v 'never$')" +%s); \
   if [[ "$change" -gt "$(date +%s)" ]]; then \
   echo_red "User: \"$usr\" last password change is on the future : \"$(passwd -S "$usr" | awk '{print $3}')\""
   echo_red "User: \"$usr\" last password change is on the future : \"$(passwd -S "$usr" | awk '{print $3}')\"" >> ./$LOGFILE
   echo_red "User: \"$usr\" last password change is on the future : \"$(passwd -S "$usr" | awk '{print $3}')\"" >> ./$LOGFILE_ERRORS

   fi
done

   [[ -z ${1} ]] || return

#list the users need to chage their password
#for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr$usr:---$(chage --list $usr | grep '^Last password change' | cut -d: -f2)"; done
#chage --list 

}


function secure_acc {
  # Check that system account's password are disabled
 local users="$(awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' ${LOGIN_DEFS})"') {print $1}' ${PASSWD} | xargs -I '{}' passwd -S '{}' | awk '($2!~/L?/) {print $1}')"

  echo "Accounts that configured the shell as nologin but their password are not locked:  ${users}" >> ./$LOGFILE
 echo "Accounts that configured the shell as nologin but their password are not locked:  ${users}" 
 [[ -z "${users}" ]] || return
}



function root_def_grp {
  local gid1
  local gid2
  gid1="$(grep "^root:" "${PASSWD}" | cut -d: -f4)" 
  [[ "${gid1}" -eq 0 ]] || return
  gid2="$(id -g root)" 
  [[ "${gid2}" -eq 0 ]] || return
}

function def_umask_for_users {
  cut -d\#  -f1 "${BASHRC}" | egrep -q "umask[[:space:]]+027" || return


}

function umask2 {
   passing=""
   grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' ${LOGIN_DEFS} && grep -Eqi '^\s*USERGROUPS_ENAB\s*"?no"?\b' ${LOGIN_DEFS} && grep -Eq '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' /etc/pam.d/common-session && passing=true
   grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* /etc/bashrc* && passing=true
   [ "$passing" = true ] || return

}

function shell_tmout {
  #check shell time out
  grep -qxF 'readonly TMOUT=1800 ; export TMOUT' ${PROFILE_D} || return
}


function world_perm {
#find files with 777 permission
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)"
  echo_red "These files have 777 permission:\n$dirs \n "
  echo_red "These files have 777 permission:\n$dirs \n " >> ./$LOGFILE
  [[ -z "${dirs}" ]] || return
 }


function root_path {
 local  RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
 echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
 echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
 for x in $(echo "$RPCV" | tr ":" " "); do
  if [ -d "$x" ]; then
  output="$( ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"}  substr($1,6,1) != "-" {print $9, "is group writable"}  substr($1,9,1) != "-" {print $9, "is world writable"}')"
    else
   echo "$x is not a directory"
  fi
   if  [[ ! -z ${output} ]]; then
   echo -e "\n $output "  >> ./$LOGFILE
   return 1
  else
   echo
  fi
 done
}

function no_uid0_other_root {
  local grep_passwd
  grep_passwd="$(awk -F: '($3 == 0) { print $1 }' ${PASSWD})"
  [[ "${grep_passwd}" = "root" ]] || return  
}


function unowned_files {
  local uo_files
  uo_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
  echo_red "The files are:\n$uo_files\n "
  echo_red "The files are:$uo_files\n " >> ./$LOGFILE
  [[ -z "${uo_files}" ]] || return
}


function ungrouped_files {
  local ug_files
  ug_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
  echo_red "The files are:\n$ug_files\n "
  echo_red "The files are:\n$ug_files\n " >> ./$LOGFILE
  [[ -z "${ug_files}" ]] || return
}

function suid_exes {
  # For every suid exe on the host use the rpm cmd to verify that it should be suid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local suid_exes rpm rpm_out
  suid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for suid_exe in ${suid_exes}
  do
    rpm=$(rpm -qf $suid_exe)
    rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
    [[ -z "${rpm_out}" ]] || return
  done
}

function sgid_exes {
  # For every sgid exe on the host use the rpm cmd to verify that it should be sgid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local sgid_exes rpm rpm_out
  sgid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for sgid_exe in ${sgid_exes}
  do
    rpm=$(rpm -qf $suid_exe)
    rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
    [[ -z "${rpm_out}" ]] || return
  done
}


function passwd_field {
  local shadow_out
  shadow_out="$(awk -F: '($2 == "" ) { print $1 }' ${SHADOW})"
  echo_red "Results:\n$shadow_out \n " >> ./$LOGFILE
  [[ -z "${shadow_out}" ]] || return
}

function passwd_shadow {
  local shadowed
  shadowed="$(awk -F: '($2 != "x" ) { print $1 }' ${PASSWD})"
  echo_red "Results:\n$shadowed \n " >> ./$LOGFILE
  [[ -z "${shadowed}" ]] || return
}

function groups_passwd {
  # all groups in /etc/passwd should be exist in /etc/group
  for i in $(cut -s -d: -f4 ${PASSWD} | sort -u ); do
   grep -q -P "^.*?:[^:]*:$i:" ${GROUP}
   if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> ./$LOGFILE
    return 1
   fi
  done
}


function shadow_empty {
 
outlet1="$(awk -F: '($1=="shadow") {print $NF}' ${GROUP})"
#outlet2="$(awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd)"
 echo $outlet1
[[ -z ${outlet1} ]] || return

}


function duplicate_uids {
  local num_of_uids
  local uniq_num_of_uids
  num_of_uids="$(cut -f3 -d":" ${PASSWD} | wc -l)"
  uniq_num_of_uids="$(cut -f3 -d":" ${PASSWD} | sort -n | uniq | wc -l)"
  [[ "${num_of_uids}" -eq "${uniq_num_of_uids}" ]] || return
}

function duplicate_gids {
  local num_of_gids
  local uniq_num_of_gids
  num_of_gids="$(cut -f3 -d":" ${GROUP} | wc -l)"
  uniq_num_of_gids="$(cut -f3 -d":" ${GROUP} | sort -n | uniq | wc -l)"
  [[ "${num_of_gids}" -eq "${uniq_num_of_gids}" ]] || return
}

function duplicate_usernames {
  local num_of_usernames
  local num_of_uniq_usernames
  num_of_usernames="$(cut -f1 -d":" ${PASSWD} | wc -l)"
  num_of_uniq_usernames="$(cut -f1 -d":" ${PASSWD} | sort | uniq | wc -l)"
  [[ "${num_of_usernames}" -eq "${num_of_uniq_usernames}" ]] || return
}

function duplicate_groupnames {
  local num_of_groupnames
  local num_of_uniq_groupnames
  num_of_groupnames="$(cut -f1 -d":" ${GROUP} | wc -l)"
  num_of_uniq_groupnames="$(cut -f1 -d":" ${GROUP} | sort | uniq | wc -l)"
  [[ "${num_of_groupnames}" -eq "${num_of_uniq_groupnames}" ]] || return
}





function chk_home_dirs_exist {
  #Check that users home directory do all exist
  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nobody" ]] ; then
        echo ${user}

	    return 1
    
    fi

  done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function chk_home_dirs_owns {
  #Check that users home directory owner
  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nobody" ]] ; then
      local owner
      owner="$(stat -L -c "%U" "${dir}")"
      [[ "${owner}" = "${user}" ]] || return
    echo ${user}
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}


function home_dir_perms {
local count=0
local dir
# filter out specific users and get their directories
dirs=$(awk -F: '($1!="root" && $1!="halt" && $1!="sync" && $1!="shutdown" && $7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/usr/bin/false") { print $6 }' $PASSWD)

# check  permissions
 for dir in $dirs; do
  local stat=$(stat -c "%a"  $dir | awk '{print substr($0, length-2, 3)}')
   if [ $stat -gt 750 ]; then
     count=$((count+1))
    echo -e "Results: $dir"
   fi
 done

#check sum of false and true counts
 if [ $count -gt 0 ]; then
   return 1
    else
   return 0
 fi
}


function dot_file_perms {

local count=0
local dir

dirs=$(awk -F: '($1!="root" && $1!="halt" && $1!="sync" && $1!="shutdown" && $7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/usr/bin/false") { print $6 }' $PASSWD)

# check  permissions

 for dir in ${dirs}/.[A-Za-z0-9]* ; do
  stat=$(stat -c '%#a' $dir)
   if [ $stat -gt 0755 ]; then
     count=$((count+1))
    echo -e "Results: $dir"
   fi
 done

#check sum of false and true counts
 if [ $count -gt 0 ]; then
   return 1
    else
   return 0
 fi
}

function dot_rhosts_files {
     # We don't want to see any ~/.forward files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.rhosts" && -f "${dir}/.rhosts" ]] ; then
      return 1
    fi
  done
 }



function user_dot_netrc {
  # check existence of .netrc files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.netrc" && -f "${dir}/.netrc" ]] ; then
     echo -e "Failed: Please check  ${dir}/.netrc"    >> ./$LOGFILE
     echo -e "Failed: Please check  ${dir}/.netrc" 
     return 1
    fi
  done
}




function user_dot_forward {
  # We don't want to see any ~/.forward files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.forward" && -f "${dir}/.forward" ]] ; then
      return 1 
    fi
  done
}






























#######################################################################################################

clear
  echo -e "\n\n IP Address : $IP_ADR"       > ./$LOGFILE
  echo -e "\n Host Name    : $(hostname)"  >> ./$LOGFILE
  echo -e "\n OS Version   : $OS_VERSION"  >> ./$LOGFILE
  echo -e "\n Date : $(date '+%Y.%m.%d')             Time: $(date '+%H:%M') "  >> ./$LOGFILE
  echo -e "\n State           Index           Defined Argument" >> ./$LOGFILE
  echo -e "================================================================" >> ./$LOGFILE

  echo -e "\n\n IP Address : $IP_ADR"       > ./$LOGFILE_ERRORS
  echo -e "\n Host Name    : $(hostname)"  >> ./$LOGFILE_ERRORS
  echo -e "\n OS Version   : $OS_VERSION"  >> ./$LOGFILE_ERRORS
  echo -e "\n Date : $(date '+%Y.%m.%d')             Time: $(date '+%H:%M') "  >> ./$LOGFILE_ERRORS
  echo -e "\n State           Index           Defined Argument" >> ./$LOGFILE_ERRORS
  echo -e "================================================================" >> ./$LOGFILE_ERRORS

  
  function f_return {
    let TOTAL++
    func_name=$1
    shift
    args=$@
    printf "${func_name} ${args}: "
    ${func_name} ${args} >/dev/null 2>&1
    if [[ "$?" -eq 0 ]]; then
      let PASS++
      echo_green [PASSED]
 
      echo_green "Passed          $func_name                          $args" >> ./$LOGFILE
      echo -e "------------------------------------------------------------" >> ./$LOGFILE
    else
      let FAILED++
      echo_red [FAILED]
 
      echo_red   "Error on:       $func_name                          $args" >> ./$LOGFILE
      echo  -e "-----------------------------------------------------------" >> ./$LOGFILE
      echo_red   "Error on:       $func_name                          $args" >> ./$LOGFILE_ERRORS
      echo  -e "-----------------------------------------------------------" >> ./$LOGFILE_ERRORS
    fi
 
  }
  


 echo_red "\n********** 1.Initial Setup **********"

 echo_bold "##### 1.1.1.1 Ensure mounting of cramfs filesystems is disabled #####"
  f_return disable_fs cramfs
  f_return disable_fs udf
  f_return disable_fs squashfs

 echo_bold "##### 1.1.23 Disable Automounting  #####"
  f_return service_disabled  autofs

 echo_bold "##### 1.1.24 Disable USB Storage  #####"
  f_return disable_fs usb-storage

 echo_bold "##### 1.3.1 Ensure AIDE is installed #####"
  f_return package_installed   aide-common
  f_return package_installed   aide

 echo_bold "##### 1.4.2 Ensure permissions on bootloader config are configured"
  f_return check_file_perm  ${GRUB_CFG} 400
  f_return check_root_owns  ${GRUB_CFG}

 echo_bold "##### 1.4.3 Ensure authentication required for single user mode(root user must have a password)"
  f_return root_pass

 echo_bold "##### 1.5.1 Ensure address space layout randomization (ASLR) is enabled"
  f_return chk_param "kernel.randomize_va_space=" 2  ${SYSCTL_CONF}
  f_return chk_sysctl kernel.randomize_va_space 2

 echo_bold "##### 1.5.2 Ensure prelink is not installed #####"
  f_return  package_not_installed prelink

 echo_bold "##### 1.5.3 Ensure Automatic Error Reporting is not enabled"
  f_return  service_disabled apport
  f_return  chk_param "enabled=" 0 ${APPPORT}

 echo_bold "##### 1.5.4 Ensure core dumps are restricted"
  f_return service_disabled coredump
  f_return chk_sysctl fs.suid_dumpable   0
  f_return chk_param "fs.suid_dumpable=" 0 ${SYSCTL_CONF}
  f_return chk_param " hard core" 0 ${SEC_LIMITS}

  echo_bold "##### 1.6.1.1 Ensure AppArmor is installed"
   f_return package_installed  apparmor
   f_return apparmor_grub
   chk_apparmor 

  echo_bold "##### 1.7.1 - 3 Ensure banners are configured"
   f_return warning_banners

  echo_bold "##### 1.7.4 - 6 Ensure permissions on warning banners files #####"
   f_return check_file_perm  ${MOTD}  644
   f_return check_file_perm  ${ISSUE} 644
   f_return check_file_perm  ${ISSUE_NET}  644

  echo_bold "##### 1.8.1 Ensure GNOME Display Manager is removed"
   f_return  package_not_installed  gdm3

#checking Servicess Configuration
  echo_red "\n**********2.Services **********\n"


  echo_bold "##### 2.1.1 Ensure time sync is in use"
   f_return package_installed chrony
   f_return package_not_installed  ntp
   f_return service_disabled systemd-timesyncd
   f_return service_enabled chrony  

   echo_bold "##### 2.1.2 Ensure chrony is configured"
    f_return chrony_cfg


  echo_bold "##### 2.2.1 - 2.3.6 Removing insecure  services . . .  "
   f_return package_not_installed isc-dhcp-server
   f_return package_not_installed slapd
   f_return package_not_installed nfs-kernel-server
   f_return package_not_installed bind9
   f_return package_not_installed vsftpd
   f_return package_not_installed apache2
   f_return package_not_installed dovecot-imapd
   f_return package_not_installed dovecot-pop3d
   f_return package_not_installed samba
   f_return package_not_installed squid
   f_return package_not_installed snmp
   f_return package_not_installed nis
   f_return package_not_installed postfix
   f_return package_not_installed rsync
   f_return package_not_installed nis
   f_return package_not_installed rsh-client
   f_return package_not_installed talk
   f_return package_not_installed telnet
   f_return package_not_installed ldap-utils
   f_return package_not_installed rpcbind

# Checking Network Configuration
  echo_red "\n********** Network Configuration **********\n"

  echo_bold "##### 3.1.1 Ensure system is checked to determine if IPv6 is NOT enabled "
   f_return chk_sysctl net.ipv6.conf.all.disable_ipv6 1
   f_return chk_sysctl net.ipv6.conf.default.disable_ipv6 1
   f_return chk_param "net.ipv6.conf.all.disable_ipv6=" 1     ${SYSCTL_CONF}
   f_return chk_param "net.ipv6.conf.default.disable_ipv6=" 1 ${SYSCTL_CONF}
   f_return chk_grub_ipv6
 
 echo_bold "##### 3.2.1 Ensure packet redirect sending is disabled"
  f_return  chk_param  "net.ipv4.conf.all.send_redirects=" 0  ${SYSCTL_CONFv4}
  f_return  chk_param  "net.ipv4.conf.default.send_redirects=" 0 ${SYSCTL_CONFv4}
  f_return  chk_sysctl  net.ipv4.conf.all.send_redirects 0
  f_return  chk_sysctl  net.ipv4.conf.default.send_redirects 0

 echo_bold "##### 3.2.2 Ensure IP forwarding is disabled "
  f_return  chk_param "net.ipv4.ip_forward=" 0 ${SYSCTL_CONFv4}
  f_return  chk_sysctl net.ipv4.ip_forward 0

  echo_bold "Checking IPV6:"
  f_return  chk_param "net.ipv6.conf.all.forwarding=" 0 ${SYSCTL_CONFv6}

  echo_bold "##### 3.3.1 Ensure source routed packets are not accepted "
  f_return  chk_param "net.ipv4.conf.all.accept_source_route=" 0  ${SYSCTL_CONFv4}
  f_return  chk_param "net.ipv4.conf.default.accept_source_route=" 0  ${SYSCTL_CONFv4}
  f_return  chk_sysctl net.ipv4.conf.all.accept_source_route 0
  f_return  chk_sysctl net.ipv4.conf.default.accept_source_route 0

  echo_bold "Checking IPV6:"
  f_return  chk_param "net.ipv6.conf.all.accept_source_route=" 0  ${SYSCTL_CONFv6}
  f_return  chk_param "net.ipv6.conf.default.accept_source_route=" 0  ${SYSCTL_CONFv6}
 
 echo_bold "##### 3.3.2 Ensure ICMP redirects are not accepted "
  f_return chk_param "net.ipv4.conf.all.accept_redirects=" 0  ${SYSCTL_CONFv4}
  f_return chk_param "net.ipv4.conf.default.accept_redirects=" 0  ${SYSCTL_CONFv4}
  f_return chk_sysctl net.ipv4.conf.all.accept_redirects 0
  f_return chk_sysctl net.ipv4.conf.default.accept_redirects 0

  echo_bold "Checking IPV6:"
  f_return chk_param "net.ipv6.conf.all.accept_redirects=" 0  ${SYSCTL_CONFv6}
  f_return chk_param "net.ipv6.conf.default.accept_redirects=" 0  ${SYSCTL_CONFv6}
 
 echo_bold "##### 3.3.3 Ensure secure ICMP redirects are not accepted "
  f_return chk_param  "net.ipv4.conf.default.secure_redirects=" 0  ${SYSCTL_CONFv4}
  f_return chk_param  "net.ipv4.conf.all.secure_redirects=" 0  ${SYSCTL_CONFv4}
  f_return chk_sysctl net.ipv4.conf.all.secure_redirects 0
  f_return chk_sysctl net.ipv4.conf.default.secure_redirects 0

 echo_bold "#####3.3.4 Ensure suspicious packets are logged  "
  f_return chk_param "net.ipv4.conf.all.log_martians=" 1  ${SYSCTL_CONFv4}
  f_return chk_param "net.ipv4.conf.default.log_martians=" 1  ${SYSCTL_CONFv4}
  f_return chk_sysctl net.ipv4.conf.default.log_martians 1 
  f_return chk_sysctl net.ipv4.conf.all.log_martians 1

 echo_bold "##### 3.3.5 Ensure broadcast ICMP requests are ignored "
  f_return chk_param "net.ipv4.icmp_echo_ignore_broadcasts=" 1 ${SYSCTL_CONFv4}
  f_return chk_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1

 echo_bold "##### 3.3.6 Ensure bogus ICMP responses are ignored  "
  f_return chk_param "icmp_ignore_bogus_error_responses=" 1 ${SYSCTL_CONFv4}
  #f_return chk_sysctl icmp_ignore_bogus_error_responses 1

 echo_bold "##### 3.3.7 Ensure Reverse Path Filtering is enabled" 
  f_return chk_param "net.ipv4.conf.all.rp_filter=" 1  ${SYSCTL_CONFv4}
  f_return chk_param "net.ipv4.conf.default.rp_filter=" 1  ${SYSCTL_CONFv4}
  f_return chk_sysctl net.ipv4.conf.default.rp_filter 1
  f_return chk_sysctl net.ipv4.conf.all.rp_filter 1

 echo_bold "##### 3.3.8 Ensure TCP SYN Cookies is enabled "
  f_return chk_param "net.ipv4.tcp_syncookies=" 1  ${SYSCTL_CONFv4}
  f_return chk_sysctl net.ipv4.tcp_syncookies 1


 echo_bold "##### 3.3.9 Ensure IPv6 router advertisements are not accepted "
  f_return chk_param "net.ipv6.conf.all.accept_ra=" 0  ${SYSCTL_CONFv6}
  f_return chk_param "net.ipv6.conf.default.accept_ra=" 0  ${SYSCTL_CONFv6}

  echo_bold " ##### check ip v6 configuration from kernel #####"
    if chk_grub_ipv6 >/dev/null 2>&1 ; then
     echo "ip v6 is disabled"
    else
     f_return  chk_sysctl net.ipv6.conf.all.forwarding 0
     f_return  chk_sysctl net.ipv6.conf.all.accept_source_route 0
     f_return  chk_sysctl net.ipv6.conf.default.accept_source_route 0
     f_return chk_sysctl net.ipv6.conf.all.accept_redirects 0
     f_return chk_sysctl net.ipv6.conf.default.accept_redirects 0
     f_return chk_sysctl net.ipv6.conf.default.accept_ra 0
     f_return chk_sysctl net.ipv6.conf.all.accept_ra 0
     f_return chk_sysctl net.ipv6.conf.default.disable_ipv6 1
     f_return chk_sysctl net.ipv6.conf.all.disable_ipv6 1
    fi
		
 echo_bold "#####3.4.1-4  Ensure uncommon network protocol is disabled "
  f_return  disable_fs dccp
  f_return  disable_fs sctp
  f_return  disable_fs RDS
  f_return  disable_fs TIPC


 echo_bold"##### 3.5.1.1 Ensure ufw is installed"
  f_return package_installed ufw

 echo_bold "##### 3.5.1.2 Ensure iptables-persistent is not installed with ufw"
  f_return package_not_installed iptables-persistent

 echo_bold "###### 3.5.1.3 Ensure ufw service is enabled "
  f_return service_enabled ufw

    #Checking Logging and Auditing
  echo_red "\n********** 4.Logging and Auditing **********\n"

  echo_bold "##### 4.1.1.1 Ensure auditd is installed"
   f_return package_installed auditd

   echo_bold "###### 4.1.1.2 Ensure auditd is active"
    f_return service_enabled auditd 

  echo_bold "###### 4.1.1.3 Ensure auditing procs start prior auditd enabled" 
  echo_bold "###### 4.1.1.4 Ensure audit_backlog_limit is sufficient"
   f_return chk_grub_auditd

 echo_bold "##### 4.1.2 Ensure audit logs are not deleted - Set Max Log actions"
  f_return chk_param  "max_log_file=" 50 ${AUDITD_CNF}
  f_return chk_param  "max_log_file_action=" ROTATE ${AUDITD_CNF}
  f_return chk_param  "space_left_action=" ROTATE ${AUDITD_CNF}
  f_return chk_param  "admin_space_left_action=" ROTATE ${AUDITD_CNF}
  f_return chk_param  "disk_full_action=" ROTATE ${AUDITD_CNF}
  f_return chk_param  "disk_error_action=" SYSLOG ${AUDITD_CNF}

 echo_bold "##### 4.1.3.21 Ensure the running and on disk configuration is the same" 
  f_return audit_merge 

  echo_bold "##### 4.1.3.21 Ensure the running and on disk configuration is the same"
   f_return audit_merge

  echo_bold "##### 4.1.4.1 Ensure audit log files are mode 0640 or less permissive"
   f_return  audit_log_perm1

  echo_bold "##### 4.1.4.2 Ensure only authorized users own audit log files "
   f_return  audit_log_perm2

  echo_bold "##### 4.1.4.3 Ensure only authorized groups are assigned ownership of audit log files"
   f_return  audit_log_perm3

  echo_bold "##### 4.1.4.4 Ensure the audit log directory is 0750 or more restrictive"
   f_return  audit_log_perm4

  echo_bold "##### 4.1.4.5 Ensure audit configuration files are 640 or more restrictive"
   f_return  audit_conf_perm1

  echo_bold "##### 4.1.4.6 Ensure audit configuration files are owned by root "
   f_return  audit_conf_perm2

  echo_bold "##### 4.1.4.7 Ensure audit configuration files belong to group root"
   f_return  audit_conf_perm3

  echo_bold "##### 4.1.4.8 - 10 Ensure audit tools have proper or more restrictive permission and owner"
   f_return audit_tools_perm

  echo_bold"#####  4.2.1.1.4 Ensure journald is not configured to recieve logs from a remote client #####"
   f_return service_disabled systemd-journal-remote.socket

  echo_bold "##### 4.2.1.2 Ensure journald service is enabled"
 chk_journald_enabled 

  echo_bold "##### 4.2.1.3 Ensure journald is configured to compress large log files"
   f_return chk_param  "Compress=" yes  ${JOURNALD_CFG}

  echo_bold "##### 4.2.1.4 Ensure journald is configured to write logfiles to persistent disk"
   f_return chk_param  "Storage=" persistent  ${JOURNALD_CFG}

  echo_bold "##### 4.2.2.1-2 Ensure rsyslog is installed and enabled"
   f_return  package_installed rsyslog
   f_return service_enabled rsyslog
  
   echo_bold "##### 4.2.2.7 Ensure rsyslog is not configured to receive logs from a remote client (Check Manual guide)"
   f_return rsyslog_remote

  echo_bold "##### 4.2.3 Ensure permissions on all logfiles are configured "
   f_return logfile_perm

  echo_bold "##### 5.1.1 Ensure cron daemon is enabled and running "
   f_return service_enabled chrony

  echo_bold "##### 5.1.1 - 7 Ensure permissions on Cron files are configured #####"

   f_return check_file_perm ${CRONTAB}      600
   f_return check_file_perm ${CRON_DIR}     700
   f_return check_file_perm ${CRON_DAILY}   700
   f_return check_file_perm ${CRON_HOURLY}  700
   f_return check_file_perm ${CRON_WEEKLY}  700
   f_return check_file_perm ${CRON_MONTHLY} 700
         
   f_return check_root_owns ${CRONTAB}      
   f_return check_root_owns ${CRON_DIR}     
   f_return check_root_owns ${CRON_DAILY}  
   f_return check_root_owns ${CRON_HOURLY}  
   f_return check_root_owns ${CRON_WEEKLY}  
   f_return check_root_owns ${CRON_MONTHLY} 

  echo_bold "##### 5.1.8  Ensure cron is restricted to authorized users"
   f_return cron_auth_users

  echo_bold "##### 5.1.9 Ensure at is restricted to authorized users"
   f_return at_auth_users

  echo_bold "##### 5.2.3 Ensure permissions on SSH private host key files"
   f_return host_key 

  echo_bold "##### 5.2.4 Ensure permissions on SSH public host key files"
   f_return pub_host_key

  echo_bold "##### 5.2.5-20 Ensure SSH options are set properly"
   f_return chk_param  LogLevel VERBOSE ${SSHD_CFG}
   f_return chk_param  UsePAM yes ${SSHD_CFG}
   f_return chk_param  PermitRootLogin no ${SSHD_CFG}
   f_return chk_param  HostbasedAuthentication no ${SSHD_CFG}
   f_return chk_param  PermitEmptyPasswords no ${SSHD_CFG}
   f_return chk_param  PermitUserEnvironment no ${SSHD_CFG}
   f_return chk_param  IgnoreRhosts yes ${SSHD_CFG}
   f_return chk_param  X11Forwarding no ${SSHD_CFG}
   f_return chk_param  AllowTcpForwarding no ${SSHD_CFG}
   f_return chk_param  Banner /etc/issue.net ${SSHD_CFG}
   f_return chk_param  MaxAuthTries 4 ${SSHD_CFG}
   f_return chk_param  MaxStartups 10:30:60 ${SSHD_CFG}
   f_return chk_param  MaxSessions 10 ${SSHD_CFG}
   f_return chk_param  LoginGraceTime 60 ${SSHD_CFG}
   f_return chk_param  ClientAliveInterval 900 ${SSHD_CFG}
   f_return chk_param  ClientAliveCountMax 1 ${SSHD_CFG}

  echo_bold "##### 5.2.5-20 Ensure SSH options are set properly - Second Check"
   f_return chk_ssh_conf2  LogLevel VERBOSE
   f_return chk_ssh_conf2  UsePAM yes
   f_return chk_ssh_conf2  PermitRootLogin no
   f_return chk_ssh_conf2  HostbasedAuthentication no
   f_return chk_ssh_conf2  PermitEmptyPasswords no
   f_return chk_ssh_conf2  PermitUserEnvironment no
   f_return chk_ssh_conf2  IgnoreRhosts yes
   f_return chk_ssh_conf2  X11Forwarding no
   f_return chk_ssh_conf2  AllowTcpForwarding no
   f_return chk_ssh_conf2  Banner /etc/issue.net
   f_return chk_ssh_conf2  MaxAuthTries 4
   f_return chk_ssh_conf2  MaxStartups 10:30:60
   f_return chk_ssh_conf2  MaxSessions 10
   f_return chk_ssh_conf2  LoginGraceTime 60
   f_return chk_ssh_conf2  ClientAliveInterval 900
   f_return chk_ssh_conf2  ClientAliveCountMax 1
  
 echo_bold "##### 5.2.13 Ensure only strong Ciphers are used "
  f_return cipher_algorithm

 echo_bold "##### 5.2.14 Ensure only strong MAC algorithms are used "
  f_return mac_algorithm

 echo_bold "##### 5.2.15 Ensure only strong Key Exchange algorithms are used "
  f_return kex_algorithm

 echo_bold "##### 5.3.1 Ensure sudo is installed"
    f_return  package_installed sudo

 echo_bold "##### 5.3.2 Ensure sudo commands use pty "
  f_return chk_param  Defaults use_pty ${SUDO_CONF}

 echo_bold "##### 5.3.3 Ensure sudo log file exists "
  f_return chk_param  Defaults 'logfile="/var/log/sudo.log"' ${SUDO_CONF}

  echo_bold "##### 5.3.4 Ensure users must provide password for escalation"
   f_return escalation_sudo

  echo_bold "##### 5.3.5 Ensure re-authentication for privilege escalation is not disabled globally"
   f_return reauth_escalation_sudo
   
  echo_bold "##### 5.3.6 Ensure sudo authentication timeout is configured correctly"
   f_return auth_timeout_sudo

  echo_bold "##### 5.3.7 Ensure access to su command restricted"
   f_return su_access


  echo_bold "5.4.2 Ensure lockout for failed password attempts is configured"
   f_return faillock_enabled 
   f_return chk_param "deny="  5 ${FAIL_CONF}
   f_return chk_param "unlock_time="  900 ${FAIL_CONF}
   f_return chk_param2 "${FAIL_CONF}"  "silent" ""
   f_return chk_param2 "${PWQUAL_CNF}" "enforce_for_root" ""
   f_return chk_param2 "${FAIL_CONF}"  "even_deny_root" ""
   f_return chk_param2 "${FAIL_CONF}"  "silent" ""
   f_return chk_param2 "${FAIL_CONF}"  "audit"  ""
   f_return chk_param2 "${FAIL_CONF}"  "even_deny_root"  ""

  echo_bold "##### 5.5.3 Ensure password reuse is limited"
   f_checker remember_passwd 

  echo_bold "##### 5.4.4 Ensure password hashing algorithm is uptodate (yescrypt) #####"
   f_return nohash
   f_return chk_param ENCRYPT_METHOD yescrypt ${LOGIN_DEFS}

  echo_bold "##### 5.5.1.1 - 3 Ensure password config"
   f_return chk_param PASS_MAX_DAYS 365 ${LOGIN_DEFS}
   f_return chk_param PASS_MIN_DAYS 1   ${LOGIN_DEFS}
   f_return chk_param PASS_WARN_AGE 7   ${LOGIN_DEFS}

  echo_bold "##### 5.5.1.1 - 3 Ensure curent users password configs are correct (check values)"
   f_return chk_password_cnf

  echo_bold "##### 5.5.1.4 Ensure inactive password lock is 30 days or less" 
   f_return inactive_usr_acs_locked

  echo_bold "##### 5.5.1.4 Review list of users which INACTIVE PASSWORD LOCK feature is disabled for (value -1)"
   f_return inactive_usr_password_disabled
            inactive_usr_password_disabled

   echo_bold "##### 5.5.1.5 Ensure all users last password change date is in the past"
    last_pass

   echo_bold "##### 5.5.2 Ensure sys accounts are secured"
    f_return secure_acc

  echo_bold "##### 5.5.3 Ensure default group for root is GID 0"
   f_return  root_def_grp

  echo_bold "##### 5.5.4 Ensure default user umask 027"
   f_return  def_umask_for_users
   f_return  umask2

  echo_bold "##### 5.5.5 Ensure default user shell timeout is 1800"
   f_return shell_tmout 

  echo_bold "##### 6.1.1 - 8 Ensure perms on passwd(-), group(-) and shadow(-) files"
   f_return check_file_perm "${PASSWD}"   644
   f_return check_file_perm "${PASSWD2}"  644
   f_return check_file_perm "${GROUP}"    644
   f_return check_file_perm "${GROUP2}"   644
   f_return check_file_perm "${SHADOW}"   640
   f_return check_file_perm "${SHADOW2}"  640
   f_return check_file_perm "${GSHADOW}"  640
   f_return check_file_perm "${GSHADOW2}" 640
   for file in ${PASSWD} ${PASSWD2} ${SHADOW} ${SHADOW2} ${GSHADOW} ${GSHADOW2} ${GROUP} ${GROUP2} ; do
   f_return check_root_owns ${file}
   done


    echo_bold "##### 6.1.9 Ensure no world writable files exist (777)"
    f_return world_perm 
             world_perm     
  
  echo_bold "##### 6.1.10 Ensure no unowned files exist"
   f_return unowned_files	
            unowned_files

  echo_bold "##### 6.1.11 Ensure no ungrouped files exist"
   f_return ungrouped_files
  	        ungrouped_files

  echo_bold "##### 6.1.12 Audit SUID executables"
   f_return suid_exes
  
  echo_bold "##### 6.1.13 Audit SGID executables"
   f_return sgid_exes
  
  echo_bold "##### 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords"
   f_return passwd_shadow
       
  echo_bold "##### 6.2.2 Ensure password fields are not empty"
   f_return passwd_field

  echo_bold "##### 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group "
   f_return groups_passwd

  echo_bold " #####  6.2.4 Ensure shadow group is empty"
    f_return shadow_empty
    shadow_empty

  echo_bold "##### 6.2.5 Ensure no duplicate UIDs exist"
   f_return duplicate_uids

  echo_bold "##### 6.2.6 Ensure no duplicate GIDs"
   f_return duplicate_gids

  echo_bold "##### 6.2.7 Ensure no duplicate user names"
   f_return duplicate_usernames

  echo_bold "##### 6.2.8 Ensure no duplicate group names"
   f_return duplicate_groupnames

  echo_bold "##### 6.2.9 Ensure root PATH integrity"
   f_return root_path

  echo_bold "##### 6.2.10 Ensure root only uid0"
   f_return no_uid0_other_root

  echo_bold "##### 6.2.11 Ensure all users home dir exist"
   f_return chk_home_dirs_exist
            chk_home_dirs_exist

  echo_bold "##### 6.2.12 Ensure users own their home directories"
   f_return chk_home_dirs_owns
            chk_home_dirs_owns

  echo_bold "##### 6.2.13 Ensure users home directories permissions are 750 or more restrictive"
   f_return home_dir_perms
            home_dir_perms

  echo_bold "##### 6.2.14 Ensure no local interactive user has .netrc files"
   f_return user_dot_netrc
            user_dot_netrc
  echo_bold "##### 6.2.15 Ensure no users have .forward files "
   f_return user_dot_forward             
            user_dot_forward

  echo_bold "##### 6.2.16 Ensure no users have .rhosts files "
   f_return dot_rhosts_files
            dot_rhosts_files 

  echo_bold "##### 6.2.17 Ensure users dot files are not group or world writable"
   f_return dot_file_perms
            dot_file_perms


echo_bold "\n Auditing Successfully Completed!"
echo_bold "\n You can find the reports in \e[36m$LOGFILE ,  $LOGFILE_ERRORS\e[0m files."

results
###################END###################



