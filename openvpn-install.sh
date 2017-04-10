#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu and CentOS

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.

log () {
    local red='\033[0;31m'
    local  nc='\033[0m' 
    echo -e "${red}$1${nc}"
}

detect_linux_distribution () {
    if [[ -e /etc/debian_version ]]; then
	OS=debian
    elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	    OS=centos5
	else
	    OS=centos
	fi
    else
	OS=wrong
    fi
}

# Assumptions made about environment

assume_run_by_bash () {
    # Detect Debian users running the script with "sh" instead of bash
    if readlink /proc/$$/exe | grep -qs "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit 1
    fi
}

assume_run_by_root () {
    if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit 2
    fi
}

assume_tun_device_available () {
    if [[ ! -e /dev/net/tun ]]; then
	echo "The TUN device is not available. You need to enable TUN before running this script"
	exit 3
    fi
}

assume_distribution_supported () {
    case "$OS" in
	centos5)
	    echo "CentOS 5 is too old and not supported"
	    exit 4 ;;
	wrong)
	    echo "Looks like you aren't running this installer on Debian, Ubuntu or CentOS"
	    exit 5 ;;
	*)
	    return 0 ;;
    esac
}

check_environment () {
    assume_run_by_bash
    assume_run_by_root
    assume_tun_device_available
    assume_distribution_supported
}

# Setup variables

setup_variables () {
    # Try to get our IP from the system and fallback to the Internet.
    # I do this to make the script compatible with NATed servers (lowendspirit.com)
    # and to avoid getting an IPv6.
    IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    if [[ "$IP" = "" ]]; then
	IP=$(wget -4qO- "http://whatismyip.akamai.com/")
    fi

    case "$OS" in
	debian)
	    GROUPNAME=nogroup
	    RCLOCAL='/etc/rc.local' ;;
	centos)
	    GROUPNAME=nobody
	    RCLOCAL='/etc/rc.d/rc.local' ;;
    esac	    
}

# Firewall

firewalld_enabled () {
    if pgrep firewalld; then
	return 0
    else
	return 1
    fi
}

rclocal_create () {
    # Needed to use rc.local with some systemd distros
    if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
	echo '#!/bin/sh -e'  >  $RCLOCAL
        echo 'exit 0'        >> $RCLOCAL
    fi
    chmod +x $RCLOCAL
}

firewall_ip_forwarding_enable () {

    log firewall_ip_forwarding_enable
    
    # Enable net.ipv4.ip_forward for the system
    sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
    if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then
	    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    # Avoid an unneeded reboot
    echo 1 > /proc/sys/net/ipv4/ip_forward
}    

firewall_port_open () {
    log firewall_port_open

    log "PORT IS $PORT. PROTOCOL IS $PROTOCOL"
    
    if firewalld_enabled ; then
	# Using both permanent and not permanent rules to avoid a firewalld
	# reload.
	# We don't use --add-service=openvpn because that would only work with
	# the default port and protocol.
	firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
	firewall-cmd --zone=trusted --add-source=10.8.0.0/24
	firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
	firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
    else
	if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
	    # If iptables has at least one REJECT rule, we asume this is needed.
	    # Not the best approach but I can't think of other and this shouldn't
	    # cause problems.
	    iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
	    iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
	    iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	    sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
	    sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
	    sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
	fi
    fi
}

firewall_port_close () {
    log firewall_port_close
    
    if firewalld_enabled ; then
	IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 7)
	# Using both permanent and not permanent rules to avoid a firewalld reload.
	firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
	firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
	firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
    else
	if iptables -L -n | grep -qE '^ACCEPT'; then
	    iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
	    iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
	    iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
	    sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
	    sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
	    sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
	fi
    fi
}

firewall_nat_enable () {
    log firewall_nat_enable
    
    # Set NAT for the VPN subnet
    if firewalld_enabled ; then
	firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -j SNAT --to $IP
	firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -j SNAT --to $IP
    else
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
    fi
}

firewall_nat_disable () {
    log firewall_nat_disable
    
    if firewalld_enabled ; then
	firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
	firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -j SNAT --to $IP
	firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 -j SNAT --to $IP
    else
	IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 11)
	iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP
	sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
    fi
}

# SELinux

selinux_enforced () {
    if hash sestatus 2>/dev/null; then
	if sestatus | grep "Current mode" | grep -qs "enforcing"; then
	    return 0
	else
	    return 1
	fi
    else
	return 1
    fi
}

selinux_needs_adjustment () {
    if selinux_enforced ; then
	if [[ "$PORT" != '1194' || "$PROTOCOL" = 'tcp' ]]; then
	    return 0
	else
	    return 1
	fi
    else
	return 1
    fi
}

semanage_packages_install () {
    # semanage isn't available in CentOS 6 by default
    if ! hash semanage 2>/dev/null; then
	yum install policycoreutils-python -y
    fi
}

selinux_port_open () {
    log selinux_port_open
    
    if selinux_needs_adjustment ; then
       semanage_packages_install
       semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
    fi
}

selinux_port_close () {
    log selinux_port_close
    
    if selinux_needs_adjustment ; then
	semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
    fi
}

# EasyRSA

easyrsa_packages_install () {
    case "$OS" in
	debian)
	    apt-get update
	    apt-get wget -y ;;
	centos)
	    yum install epel-release -y
	    yum install wget -y ;;
    esac

    # An old version of easy-rsa was available by default in some openvpn packages
    if [[ -d /etc/openvpn/easy-rsa/ ]]; then
	rm -rf /etc/openvpn/easy-rsa/
    fi
    
    # Get easy-rsa
    wget -O ~/EasyRSA-3.0.1.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz"
    tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
    mv ~/EasyRSA-3.0.1/ /etc/openvpn/
    mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
    chown -R root:root /etc/openvpn/easy-rsa/
    rm -rf ~/EasyRSA-3.0.1.tgz
}

easyrsa_configure () {
    cd /etc/openvpn/easy-rsa/
    # Create the PKI, set up the CA, the DH params and the server + client certificates
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass
    ./easyrsa gen-crl
}

# OpenVPN - Utilities

openvpn_client_config_generate () {
    # Generates the custom client.ovpn

    log "openvpn_client_config_generate - $CLIENT - $1"
    
    local        name="$CLIENT"
    local config_path="/root/$name.ovpn"
    
    cp /etc/openvpn/client-common.txt $config_path

    echo "<ca>"                                     >> $config_path
    cat /etc/openvpn/easy-rsa/pki/ca.crt            >> $config_path
    echo "</ca>"                                    >> $config_path

    echo "<cert>"                                   >> $config_path
    cat /etc/openvpn/easy-rsa/pki/issued/$name.crt  >> $config_path
    echo "</cert>"                                  >> $config_path

    echo "<key>"                                    >> $config_path
    cat /etc/openvpn/easy-rsa/pki/private/$name.key >> $config_path
    echo "</key>"                                   >> $config_path

    echo "<tls-auth>"                               >> $config_path
    cat /etc/openvpn/ta.key                         >> $config_path
    echo "</tls-auth>"                              >> $config_path
}

openvpn_client_add () {
    log "openvpn_client_add"
    
    cd /etc/openvpn/easy-rsa/
    ./easyrsa build-client-full $CLIENT nopass
    openvpn_client_config_generate "$CLIENT"
}

openvpn_client_remove () {
    cd /etc/openvpn/easy-rsa/
    ./easyrsa --batch revoke $CLIENT
    ./easyrsa gen-crl
    rm -rf pki/reqs/$CLIENT.req
    rm -rf pki/private/$CLIENT.key
    rm -rf pki/issued/$CLIENT.crt
    rm -rf /etc/openvpn/crl.pem
    cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    # CRL is read with each client connection, when OpenVPN is dropped to nobody
    chown nobody:$GROUPNAME /etc/openvpn/crl.pem
}

# OpenVPN - Installation

openvpn_installed () {
    if [[ -e /etc/openvpn/server.conf ]]; then
	return 0
    else
	return 1
    fi
}

openvpn_packages_install () {
    case "$OS" in
	debian)
	    apt-get update
	    apt-get install openvpn iptables openssl ca-certificates -y ;;
	centos)
	    yum install epel-release -y
	    yum install openvpn iptables openssl ca-certificates -y ;;
    esac
}

openvpn_packages_remove () {
    case "$OS" in
	debian) apt-get remove --purge -y openvpn openvpn-blacklist ;;
	centos) yum remove openvpn -y ;;
    esac
}

openvpn_certificates_copy () {
    cd /etc/openvpn/easy-rsa/
    # Move the stuff we need
    cp pki/ca.crt             /etc/openvpn
    cp pki/private/ca.key     /etc/openvpn
    cp pki/dh.pem             /etc/openvpn
    cp pki/issued/server.crt  /etc/openvpn
    cp pki/private/server.key /etc/openvpn
    cp pki/crl.pem            /etc/openvpn
    # CRL is read with each client connection, when OpenVPN is dropped to nobody
    chown nobody:$GROUPNAME /etc/openvpn/crl.pem
}

openvpn_tls_auth_key_generate () {
    openvpn --genkey --secret /etc/openvpn/ta.key
}

openvpn_server_conf_generate () {
    # Generate server.conf

    local path='/etc/openvpn/server.conf'
    
    echo "port $PORT"                    >  $path
    echo "proto $PROTOCOL"               >> $path
    echo "dev tun"                       >> $path
    echo "sndbuf 0"                      >> $path
    echo "rcvbuf 0"                      >> $path
    echo "ca ca.crt"                     >> $path
    echo "cert server.crt"               >> $path
    echo "key server.key"                >> $path
    echo "dh dh.pem"                     >> $path
    echo "tls-auth ta.key 0"             >> $path
    echo "topology subnet"               >> $path
    echo "server 10.8.0.0 255.255.255.0" >> $path
    echo "ifconfig-pool-persist ipp.txt" >> $path
    
    echo 'push "redirect-gateway def1 bypass-dhcp"' >> $path

    # DNS
    case $DNS in
	    1) 
	    # Obtain the resolvers from resolv.conf and use them for OpenVPN
	    grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
		    echo "push \"dhcp-option DNS $line\"" >> $path
	    done
	    ;;
	    2) 
	    echo 'push "dhcp-option DNS 8.8.8.8"' >> $path
	    echo 'push "dhcp-option DNS 8.8.4.4"' >> $path
	    ;;
	    3)
	    echo 'push "dhcp-option DNS 208.67.222.222"' >> $path
	    echo 'push "dhcp-option DNS 208.67.220.220"' >> $path
	    ;;
	    4) 
	    echo 'push "dhcp-option DNS 129.250.35.250"' >> $path
	    echo 'push "dhcp-option DNS 129.250.35.251"' >> $path
	    ;;
	    5) 
	    echo 'push "dhcp-option DNS 74.82.42.42"' >> $path
	    ;;
	    6) 
	    echo 'push "dhcp-option DNS 64.6.64.6"' >> $path
	    echo 'push "dhcp-option DNS 64.6.65.6"' >> $path
	    ;;
    esac

    echo "keepalive 10 120"          >> $path
    echo "cipher AES-256-CBC"        >> $path
    echo "comp-lzo"                  >> $path
    echo "user nobody"               >> $path
    echo "group $GROUPNAME"          >> $path
    echo "persist-key"               >> $path
    echo "persist-tun"               >> $path
    echo "status openvpn-status.log" >> $path
    echo "verb 3"                    >> $path
    echo "crl-verify crl.pem"        >> $path
}

openvpn_restart () {
    log openvpn_restart
    
    if [[ "$OS" = 'debian' ]]; then
	# Little hack to check for systemd
	if pgrep systemd-journal; then
	    systemctl restart openvpn@server.service
	else
	    /etc/init.d/openvpn restart
	fi
    else
	if pgrep systemd-journal; then
	    systemctl restart openvpn@server.service
	    systemctl enable openvpn@server.service
	else
	    service openvpn restart
	    chkconfig openvpn on
	fi
    fi
}

openvpn_client_template_create () {
    log openvpn_client_template_create
    
    # client-common.txt is created so we have a template to add further users later

    local path='/etc/openvpn/client-common.txt'
    
    echo "client"                       >  $path
    echo "dev tun"                      >> $path
    echo "proto $PROTOCOL"              >> $path
    echo "sndbuf 0"                     >> $path
    echo "rcvbuf 0"                     >> $path
    echo "remote $IP $PORT"             >> $path
    echo "resolv-retry infinite"        >> $path
    echo "nobind"                       >> $path
    echo "persist-key"                  >> $path
    echo "persist-tun"                  >> $path
    echo "remote-cert-tls server"       >> $path
    echo "cipher AES-256-CBC"           >> $path
    echo "comp-lzo"                     >> $path
    echo "setenv opt block-outside-dns" >> $path
    echo "key-direction 1"              >> $path
    echo "verb 3"                       >> $path
}

openvpn_configure () {
    openvpn_certificates_copy
    openvpn_tls_auth_key_generate
    openvpn_server_conf_generate
    openvpn_client_template_create
    
    rclocal_create
    firewall_ip_forwarding_enable
    firewall_port_open
    firewall_nat_enable
    
    selinux_port_open
}

openvpn_install () {   
    openvpn_packages_install

    easyrsa_packages_install
    easyrsa_configure

    openvpn_configure
    openvpn_restart
}

openvpn_remove () {
    PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
    PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

    firewall_port_close
    firewall_nat_disable
    
    openvpn_packages_remove
    
    rm -rf /etc/openvpn
    rm -rf /usr/share/doc/openvpn*
}

# OpenVPN - Interactive install helpers

show_preinstall_note () {
    clear
    echo 'Welcome to this quick OpenVPN "road warrior" installer'
    echo ""
}

show_postinstall_note () {
    echo ""
    echo "Finished!"
    echo ""
    echo "Your client configuration is available at" ~/"$CLIENT.ovpn"
    echo "If you want to add more clients, you simply need to run this script again!"
}

get_ip_address () {
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i $IP IP
	echo ""
}

get_protocol () {
    echo "Which protocol do you want for OpenVPN connections?"
    echo "   1) UDP (recommended)"
    echo "   2) TCP"
    read -p "Protocol [1-2]: " -e -i 1 PROTOCOL
    case $PROTOCOL in
	1) PROTOCOL=udp ;;
	2) PROTOCOL=tcp ;;
    esac
    echo ""
}

get_port () {
    echo "What port do you want OpenVPN listening to?"
    read -p "Port: " -e -i 1194 PORT
    echo ""
}

get_dns () {
   echo "Which DNS do you want to use with the VPN?"
   echo "   1) Current system resolvers"
   echo "   2) Google"
   echo "   3) OpenDNS"
   echo "   4) NTT"
   echo "   5) Hurricane Electric"
   echo "   6) Verisign"
   read -p "DNS [1-6]: " -e -i 1 DNS
   echo ""
}

get_external_ip_address () {
    # Try to detect a NATed connection and ask about it to potential LowEndSpirit users
    EXTERNALIP=$(wget -4qO- "http://whatismyip.akamai.com/")
    if [[ "$IP" != "$EXTERNALIP" ]]; then
	    echo ""
	    echo "Looks like your server is behind a NAT!"
	    echo ""
	    echo "If your server is NATed (e.g. LowEndSpirit), I need to know the external IP"
	    echo "If that's not the case, just ignore this and leave the next field blank"
	    read -p "External IP: " -e USEREXTERNALIP
	    if [[ "$USEREXTERNALIP" != "" ]]; then
		    IP=$USEREXTERNALIP
	    fi
    fi
}

# Interactive 

interactive_openvpn_install () {
    show_preinstall_note

    get_ip_address
    get_port
    get_protocol
    get_dns
    get_external_ip_address

    echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
    read -n1 -r -p "Press any key to continue..."

    openvpn_install
    
    interactive_client_add

    show_postinstall_note
}

interactive_openvpn_remove () {
    echo ""
    read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
    if [[ "$REMOVE" = 'y' ]]; then
	openvpn_remove
	echo ""
	echo "OpenVPN removed!"
    else
	echo ""
	echo "Removal aborted!"
    fi
}

interactive_client_add () {
    echo ""
    echo "Tell me a name for the client certificate"
    echo "Please, use one word only, no special characters"
    read -p "Client name: " -e -i client CLIENT

    openvpn_client_add

    echo ""
    echo "Client $CLIENT added, configuration is available at" ~/"$CLIENT.ovpn"
}

interactive_client_remove () {
    NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
    if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
	echo ""
	echo "You have no existing clients!"
	exit 6
    fi
    echo ""
    echo "Select the existing client certificate you want to revoke"
    tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
    if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
	read -p "Select one client [1]: " CLIENTNUMBER
    else
	read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
    fi
    CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)

    openvpn_client_remove

    echo ""
    echo "Certificate for client $CLIENT revoked"
}

interactive_menu () {
    clear
    echo "Looks like OpenVPN is already installed"
    echo ""
    echo "What do you want to do?"
    echo "   1) Add a new user"
    echo "   2) Revoke an existing user"
    echo "   3) Remove OpenVPN"
    echo "   4) Exit"
    read -p "Select an option [1-4]: " option
    case $option in
	1) interactive_client_add     ;;
	2) interactive_client_remove  ;;
	3) interactive_openvpn_remove ;;
	4)                            ;;
    esac

    exit 0
}

detect_linux_distribution 
check_environment
setup_variables

yum install epel-release wget -y
systemctl start firewalld

if openvpn_installed; then
    interactive_menu
else
    interactive_openvpn_install
fi
