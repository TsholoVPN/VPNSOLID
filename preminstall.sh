#!/bin/bash
# Version: 0.4.r2
export DEBIAN_FRONTEND=noninteractive
history -c && rm -rf ~/.bash_history
# Check VPS Is Debian
source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exiting..." 
exit 1
fi

if [[ $EUID -ne 0 ]];then
echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
exit 1
fi

# Gather input
echo -e " To exit the script, kindly Press \e[1;32mCRTL\e[0m key together with \e[1;32mC\e[0m"
echo -e ""
echo -e " Choose VPN Server installation type:"
echo -e " [1] Premium Server"
echo -e " [2] VIP Server"
echo -e " [3] Private Server"
until [[ "$opts" =~ ^[1-3]$ ]]; do
read -rp " Choose from [1-3]: " -e opts
done

# Script name
MyScriptName='WaGo-G Premium Script'
VPN_Owner='Warren Pretorius AkA WaGo-G'
VPN_Name='Wago-VPN'
Filename_alias='wagovpn'

# Server local time
MyVPS_Time='Africa/Johannesburg'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='109'

# Dropbear Ports
Dropbear_Port1='442'
Dropbear_Port2='445'

# Stunnel Ports
Stunnel_Port1='143' # through Dropbear
Stunnel_Port2='444' # through OpenSSH
Stunnel_Port3='441' # through OpenVPN
Stunnel_Port4='443' # through Web Socket

# OpenVPN Ports
OpenVPN_TCP_Port='1194'
OpenVPN_UDP_Port='9019'

# Squid Ports
Squid_Port1='8080'
Squid_Port2='3128'
Squid_Port3='60000'

# Nginx port
Nginx_Port='85'

# Apache Port
Apache_Port='80'

# Monitor Ports
MGMT_TCP_PORT='5555'
MGMT_UDP_PORT='5556'
Monitor_Port='5000'

# Websocket Vars
WsPort='8880'
WsConnectPort='1194'
WsResponse='HTTP/1.1 101 Switching Protocols\r\n\r\n'

# V2Ray Vars
V2ray_Port1='8443' # through vmess tls
V2ray_Port2='2082' # through vmess none tls
V2ray_Port3='2053' # through vless tls
V2ray_Port4='2083' # through vless none tls
UUID='37fb4c33-c93d-4274-9334-716a7be713bb'
domain='dexter.wtb-crackers.tk'

# Database Info
DatabaseHost='162.246.16.67';
DatabaseName='wagogpan_wago';
DatabaseUser='wagogpan_wago';
DatabasePass='wagopanel2020';
DatabasePort='3306';

# Apache Directory
web=/var/www/html

# Get Public IP
IPADDR="$( wget -qO- ipv4.icanhazip.com)"

# Update VPS
APT="apt-get --allow-unauthenticated -y"
$APT update
yes | $APT upgrade

systemctl stop apache2
$APT install dropbear openvpn stunnel4 squid python3 apt-transport-https software-properties-common gnupg2 ca-certificates curl nginx fail2ban mariadb-server

# Removing Unnecessary packages
$APT remove --purge ufw firewalld
$APT autoremove

# Configure SSH
mv /etc/ssh/sshd_config /etc/ssh/sshd-config-old
cat << MySSHConfig > /etc/ssh/sshd_config
Port $SSH_Port1
Port $SSH_Port2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveCountMax 2
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

# Creating Banner Message
cat << banner > /etc/banner
<br><font color='#000000'>=======================================</br></font>
<br><font color='#008080'>***************** <b>GAMING SERVER</b> ****************</br></font>
<br><font color='#000000'>=======================================</br></font>
<br></br>
<br><font color='#FF0000'>**************** <b>!!!WARNING!!!</b> ****************</br></font>
<br></br>
<br><font color='#860000'>NO SPAM !!!</br></font>
<br><font color='#1E90FF'>NO DDOS !!!</br></font>
<br><font color='#FF0000'>NO HACKING !!!</br></font>
<br><font color='#008080'>NO CARDING !!!</br></font>
<br><font color='#BA55D3'>NO TORRENT !!!</br></font>
<br><font color='#32CD32'>NO MULTI-LOGIN !!!</br></font>
<br></br>
<br><font color='#FF0000'>FOLLOW THE RULES OR</br></font>
<br><font color='#FF0000'>YOUR ACCOUNT WILL BE BANNED</br></font>
<br></br>
<br><font color='#000000'>=======================================</br></font>
<br><font color='#0000FF'>************ <b>Created by WaGo~G</b> **************</br></font>
<br><font color='#000000'>=======================================</br></font>
banner

# SSH Fixes
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d;s/use_authtok //g' /etc/pam.d/common-password
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells
systemctl restart ssh

# Install Dropbear
mv /etc/default/dropbear /etc/default/dropbear-old
cat << MyDropbear > /etc/default/dropbear
NO_START=0
DROPBEAR_PORT=$Dropbear_Port1
DROPBEAR_EXTRA_ARGS="-p $Dropbear_Port2"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear
systemctl restart dropbear

# Install Stunnel
StunnelDir=$(ls /etc/default | grep stunnel | head -n1)
cat << MyStunnelD > /etc/default/stunnel4
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/banner"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD
sed -i '/ENABLED=/{s/0/1/g}' /etc/init.d/stunnel4
rm -rf /etc/stunnel/*

# Create SSL Certs
openssl req -new -x509 -days 9999 -nodes -subj "/C=PH/ST=NCR/L=Manila/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null

# Creating Stunnel Config
cat << MyStunnelC > /etc/stunnel/stunnel.conf
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = $Stunnel_Port1
connect = 127.0.0.1:$Dropbear_Port1

[openssh]
accept = $Stunnel_Port2
connect = 127.0.0.1:$SSH_Port1

[openvpn]
accept = $Stunnel_Port3
connect = 127.0.0.1:$OpenVPN_TCP_Port

[websocket]
accept = $Stunnel_Port4
connect = 127.0.0.1:$WsPort
MyStunnelC

# Restarting Stunnel
systemctl daemon-reload
systemctl restart stunnel4

# [ Setup Openvpn ]
# OpenVPN Cert CA
cat << CA > /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIDMjCCAhqgAwIBAgIJAMb77qui+OOTMA0GCSqGSIb3DQEBCwUAMBUxEzARBgNV
BAMMCldhR28tRyBWUE4wHhcNMjAwODIwMTAzMzM4WhcNMzAwODE4MTAzMzM4WjAV
MRMwEQYDVQQDDApXYUdvLUcgVlBOMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA5qBWvOJsvLv9m4PzKv6IwE7c0/gevI1GbQjv+qfH5jnDDfk+QkwfmwyI
7NkFtJezQJfcoRprA3au1ot3vrOEQHPAKrl7vs71Mv3pfcY5qAh2iyki1R80pdMV
7TIKmWclev4F31EZHlcbbJ5USPZxbJFjk2ck8khjFb9+aJrode4OE71eGC/xUBSl
PgQ8uTKkxp9Ziut4t3ta4i1KVENdRt4ILoIjjMIef1yJdFiWLdf+v6ZMVhYjL63X
zAuSGaS/Hx3Esygqa2dDxsB35E2S89NLKOI8RVLDxyt0iFWeDbQ3B5TRYJpJAwhl
9ng2Hr9b0TLi6VvfHg9LiCF0T2smUQIDAQABo4GEMIGBMB0GA1UdDgQWBBSdEBv8
h3TguzJhVpZe0FKOsc0peTBFBgNVHSMEPjA8gBSdEBv8h3TguzJhVpZe0FKOsc0p
eaEZpBcwFTETMBEGA1UEAwwKV2FHby1HIFZQToIJAMb77qui+OOTMAwGA1UdEwQF
MAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAJIlKDSQ0mkbut
KG/IUmEG1r9V6jvrikDFMbH50yX6yZihJGCcKhcU9pNny2QdqGZRAhmleLqpTrwh
AUR0/HCrR+kKumbYI6bn2llDMejiQ+VDFy4xHkGFM3HuvWTacPAyPkRcTSJAjc1P
abArqcquuOfa5CG4ohi8hsccvV42HBcPaYW3wZ0TuSY7XqXh5c2ZD1XY5/pfZTBo
0CqCVmhAVKL1h2CbMNbNNXdPLaMtF9QOKo54PWjEfE0mRrVTTnLRSePDxq7WPF2W
UkGOj/88WXIk4UYTvAsaOhYAdafJC4l+kxfj61vKW9H9jEgh1oR38JcM3uxTIRig
VhSSO0Fh
-----END CERTIFICATE-----
CA

# Server CRT
cat << CRT > /etc/openvpn/server.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            22:35:73:73:b1:05:89:4b:5e:43:9a:1b:b3:10:86:d2
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=WaGo-G VPN
        Validity
            Not Before: Aug 20 10:34:31 2020 GMT
            Not After : Nov 23 10:34:31 2022 GMT
        Subject: CN=WaGo-G VPN
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b8:11:b1:05:14:1c:d0:be:a5:d5:9f:f0:40:6f:
                    d1:77:8d:82:16:0a:b2:12:fb:1c:3d:e0:d6:4e:8f:
                    3e:2a:34:ae:48:92:9c:06:9d:5a:7f:72:fb:ea:7a:
                    4f:61:eb:21:0e:1c:c7:03:0b:7b:7b:97:2a:2c:4e:
                    93:fc:84:0c:33:97:50:70:f2:97:f3:ec:5a:60:c5:
                    32:df:be:23:d8:44:7e:4f:b8:8a:fb:6f:46:8d:f3:
                    a9:ea:53:6f:ff:ec:f3:48:8a:62:b5:15:76:38:1b:
                    6c:87:d0:79:07:6c:27:67:6d:32:cf:0a:e9:5b:db:
                    70:5e:9d:ce:da:b7:bb:2b:a7:ce:21:57:d9:6a:ea:
                    33:6a:c1:bc:2c:96:77:e1:6b:84:0f:43:35:c9:65:
                    75:d2:07:66:dd:1f:ad:d9:59:63:d6:d9:e9:ce:f7:
                    2d:3d:b7:ed:b3:d3:71:39:3b:5a:ed:ed:81:13:7d:
                    87:d2:1a:41:b7:58:14:ea:2a:b9:a7:21:e2:89:31:
                    6a:8a:2b:fc:27:1a:14:a4:b9:63:dc:9f:66:d0:b8:
                    c2:f5:f4:c9:a8:fe:d4:a0:5f:2d:77:43:6a:bd:35:
                    aa:0e:3b:fb:20:62:f3:68:39:0b:6d:2a:27:2c:3b:
                    49:c1:71:40:81:0d:ff:df:2c:36:2b:37:1b:7e:3f:
                    53:49
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                5C:D5:92:79:4D:68:6F:85:00:30:49:3B:EC:6B:E9:3D:AA:47:73:7E
            X509v3 Authority Key Identifier: 
                keyid:9D:10:1B:FC:87:74:E0:BB:32:61:56:96:5E:D0:52:8E:B1:CD:29:79
                DirName:/CN=WaGo-G VPN
                serial:C6:FB:EE:AB:A2:F8:E3:93

            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:WaGo-G VPN
    Signature Algorithm: sha256WithRSAEncryption
         1f:70:2a:2c:a5:a9:37:a5:ca:d7:1b:e6:d3:08:c4:11:30:6a:
         7c:6c:34:ba:8b:22:6e:2d:ad:38:98:b2:8a:2b:c1:51:28:69:
         95:b0:92:1a:c6:e1:18:f1:da:7b:1f:f1:ac:b6:d4:89:1b:f8:
         1e:70:5c:46:57:9d:e4:f2:24:16:28:82:19:f9:e8:aa:08:60:
         c2:1b:5d:e6:4a:1d:cb:46:9f:1e:4d:70:71:af:59:bc:f8:d4:
         0b:41:3e:73:c0:8f:0f:e5:1e:16:3c:0e:84:3a:59:b6:1e:8b:
         ef:73:7f:d3:65:1f:3c:55:2a:0a:6f:ec:97:da:dd:f1:66:6e:
         27:20:c7:90:b4:c3:03:de:3b:2f:53:42:32:ca:61:96:f7:b3:
         2b:4d:5a:1c:e9:13:ec:fe:32:be:76:58:6e:0b:e0:46:20:c8:
         3f:26:bd:ec:80:96:e4:92:84:ad:29:09:07:4d:f1:19:a6:27:
         5b:18:b1:1c:8a:8e:6e:19:5b:1c:74:fc:ae:80:8b:05:44:27:
         1e:d8:08:e0:7c:2b:67:eb:e7:9d:72:52:c4:09:5a:9f:29:f9:
         7f:d9:dc:fd:f2:67:75:f7:72:d2:af:59:fe:e4:0c:59:0f:37:
         5e:a5:e4:c0:56:7e:5f:73:77:44:2b:77:79:c4:9b:c3:bd:8e:
         54:41:6f:5b
-----BEGIN CERTIFICATE-----
MIIDYjCCAkqgAwIBAgIQIjVzc7EFiUteQ5obsxCG0jANBgkqhkiG9w0BAQsFADAV
MRMwEQYDVQQDDApXYUdvLUcgVlBOMB4XDTIwMDgyMDEwMzQzMVoXDTIyMTEyMzEw
MzQzMVowFTETMBEGA1UEAwwKV2FHby1HIFZQTjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALgRsQUUHNC+pdWf8EBv0XeNghYKshL7HD3g1k6PPio0rkiS
nAadWn9y++p6T2HrIQ4cxwMLe3uXKixOk/yEDDOXUHDyl/PsWmDFMt++I9hEfk+4
ivtvRo3zqepTb//s80iKYrUVdjgbbIfQeQdsJ2dtMs8K6VvbcF6dztq3uyunziFX
2WrqM2rBvCyWd+FrhA9DNcllddIHZt0frdlZY9bZ6c73LT237bPTcTk7Wu3tgRN9
h9IaQbdYFOoquach4okxaoor/CcaFKS5Y9yfZtC4wvX0yaj+1KBfLXdDar01qg47
+yBi82g5C20qJyw7ScFxQIEN/98sNis3G34/U0kCAwEAAaOBrTCBqjAJBgNVHRME
AjAAMB0GA1UdDgQWBBRc1ZJ5TWhvhQAwSTvsa+k9qkdzfjBFBgNVHSMEPjA8gBSd
EBv8h3TguzJhVpZe0FKOsc0peaEZpBcwFTETMBEGA1UEAwwKV2FHby1HIFZQToIJ
AMb77qui+OOTMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIFoDAVBgNV
HREEDjAMggpXYUdvLUcgVlBOMA0GCSqGSIb3DQEBCwUAA4IBAQAfcCospak3pcrX
G+bTCMQRMGp8bDS6iyJuLa04mLKKK8FRKGmVsJIaxuEY8dp7H/GsttSJG/gecFxG
V53k8iQWKIIZ+eiqCGDCG13mSh3LRp8eTXBxr1m8+NQLQT5zwI8P5R4WPA6EOlm2
Hovvc3/TZR88VSoKb+yX2t3xZm4nIMeQtMMD3jsvU0IyymGW97MrTVoc6RPs/jK+
dlhuC+BGIMg/Jr3sgJbkkoStKQkHTfEZpidbGLEcio5uGVscdPyugIsFRCce2Ajg
fCtn6+edclLECVqfKfl/2dz98md193LSr1n+5AxZDzdepeTAVn5fc3dEK3d5xJvD
vY5UQW9b
-----END CERTIFICATE-----
CRT

# Server KEY
cat << KEY > /etc/openvpn/server.key
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC4EbEFFBzQvqXV
n/BAb9F3jYIWCrIS+xw94NZOjz4qNK5IkpwGnVp/cvvqek9h6yEOHMcDC3t7lyos
TpP8hAwzl1Bw8pfz7FpgxTLfviPYRH5PuIr7b0aN86nqU2//7PNIimK1FXY4G2yH
0HkHbCdnbTLPCulb23Benc7at7srp84hV9lq6jNqwbwslnfha4QPQzXJZXXSB2bd
H63ZWWPW2enO9y09t+2z03E5O1rt7YETfYfSGkG3WBTqKrmnIeKJMWqKK/wnGhSk
uWPcn2bQuML19Mmo/tSgXy13Q2q9NaoOO/sgYvNoOQttKicsO0nBcUCBDf/fLDYr
Nxt+P1NJAgMBAAECggEAbsRGsHWv+XYguXMr0rr3ZGhFlhoNmxp9nkcE7/WHRUK6
dnWzas+aPAPn0OyVhKlIFQQARrbMMk1/VXZb26Ni7FDsWWvDQUhEAuPof3geffCJ
ylOVX0VRQe8VmytmxK3EoSyVxb8Kiy0FnJ05l9vfwn+WCb3ZPCvLbUStzDSwb83f
8LA+Z3In0OIBsnHpO1mX7EtlR2IFPT4jhfi9CxfJF/FzJ1ZnWyA6/wD44VZLrk69
cliIkGRpSxeOhhHxbTh/i8IvpmLoxZ/95PavK5ntDyvwDHwhFZKn72+ZbVs60xoC
dsBj6MKM3HqzJLfAYYVsykoW/ThcrLwJli238dRoAQKBgQDhE9T+IgDFN6amk3am
QiBf+PKgHgYHqIZmy0Z3xAD9QkCJKSWK9gIa3TR2TffBXvvnr7rPCFWYa2eTePfj
flmQ9ndnQaN7qChLvxfcDCOWWt+4WUJz7B7tW47SxbjqNqjxmd+VZomYO+spjKM9
LZEv9MCN5KyE2EA/rJgFQgPBgQKBgQDRW49nSf+sksY28m7K+uRZ3Grtv/5OD7mS
lqF79K0cE4L2ePexnYojExfff4dIkfqY+u2IKb2jzu0onncWnAB2amEJB+Pj+f/s
+1wZij3iSoGO38M2/1VOc8zbPTOSGgLqRquZRYlmZWqqsVEy3qavM/JQwQV2RLNK
56CrfzTlyQKBgCkb+DEagM2EppmSIX+oYEVnMNlx4mQPscygoBRL5mpbaXIj48mH
uUay1FwvTWsyMAxXGmWp/ghCxb43v/77GtzRR2nCoVt6kTGUi4UTaoSRwH7pPqvx
mox7xpBUsLuGlEDce+vLuKHnf8Is/7uy0OvTZkAEXkY9QS7gFTwQnKMBAoGAa/lU
1GiNvGtWXzBZg8Yxz0amv0et2ISzqK6XSl6+iSRm/scUuD4P6FcIkPQsyXjATfXc
W8VrUPh/x9sygC6k7m2e7hFrr0BYhdh9f46UrAjRGOa+v7agQH3owYmm90sDBeC8
z6fVXUIg6TfaMOoz/VhFOPDT6FM2RQOBEfHhTkECgYAzC6GBD0AoBWUFNmki+RE7
y8cZBcdrPG4QxT5bRsGYO2ymJUTm5s4cxtp/8iT/pMUw6c/jEeXuiVdSZIeo1Pvf
e2kzsJElesf9htZRDKsgqrBGEI5sG/idz8aByBywgh50iF9bdKBwaHAh+Q8x3UQj
HHk8Bm5Jk5VPIsuKAPpkmA==
-----END PRIVATE KEY-----
KEY

# Server DH2048
 cat << DH > /etc/openvpn/dh2048.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA91b4VcFS8XqvFzucPLhZxwezSJ+0nU7OiksTDi+eObpLqhzXlxhi
A1PCEW+qI0JeUI9z/hu81fVNK+4R4UYAnzFoc7hRKPEH+dSrK9Xmd50z1AEEDOyj
C6aDnV3VVawDhWtITlUc74gyT+I76INi4NYMQYo0HLnlPwoTKdC5tWFBuSiDKCzd
u4Oc5W9DGrOpHORkqAhm7LxfWqRnMJsVwffQ9x0lqaQPIG+ijkZMpfnNLUiFMBir
v3nxaUurLQtJ/S6d0euf+K54OAvaFRTiDvGMWECINMlWXGh6CmeFfJcltHuZnzzF
FojsvC77GYfeMdoadhMetWmEhrAb4GBsSwIBAg==
-----END DH PARAMETERS-----
DH

# Some workaround for OpenVZ machines for "Startup error" openvpn service
if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
systemctl daemon-reload
fi

# Iptables Rule for OpenVPN server
cat << 'EOFipt' > /etc/openvpn/openvpn.bash
#!/bin/bash
PUBLIC_INET="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
IPCIDR='10.200.0.0/16'
IPCIDR2='10.201.0.0/16'
iptables -I FORWARD -s $IPCIDR -j ACCEPT
iptables -I FORWARD -s $IPCIDR2 -j ACCEPT
iptables -t nat -A POSTROUTING -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR -o $PUBLIC_INET -j MASQUERADE
iptables -t nat -A POSTROUTING -s $IPCIDR2 -o $PUBLIC_INET -j MASQUERADE
EOFipt
chmod +x /etc/openvpn/openvpn.bash
bash /etc/openvpn/openvpn.bash

# Setting Up Squid 
rm -rf /etc/squid/squid.con*
cat << mySquid > /etc/squid/squid.conf
acl VPN dst $IPADDR/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:$Squid_Port1
http_port 0.0.0.0:$Squid_Port2
http_port 0.0.0.0:$Squid_Port3
request_header_access Allow allow all 
request_header_access Authorization allow all 
request_header_access WWW-Authenticate allow all 
request_header_access Proxy-Authorization allow all 
request_header_access Proxy-Authenticate allow all 
request_header_access Cache-Control allow all 
request_header_access Content-Encoding allow all 
request_header_access Content-Length allow all 
request_header_access Content-Type allow all 
request_header_access Date allow all 
request_header_access Expires allow all 
request_header_access Host allow all 
request_header_access If-Modified-Since allow all 
request_header_access Last-Modified allow all 
request_header_access Location allow all 
request_header_access Pragma allow all 
request_header_access Accept allow all 
request_header_access Accept-Charset allow all 
request_header_access Accept-Encoding allow all 
request_header_access Accept-Language allow all 
request_header_access Content-Language allow all 
request_header_access Mime-Version allow all 
request_header_access Retry-After allow all 
request_header_access Title allow all 
request_header_access Connection allow all 
request_header_access Proxy-Connection allow all 
request_header_access User-Agent allow all 
request_header_access Cookie allow all 
request_header_access All deny all
reply_header_access Allow allow all 
reply_header_access Authorization allow all 
reply_header_access WWW-Authenticate allow all 
reply_header_access Proxy-Authorization allow all 
reply_header_access Proxy-Authenticate allow all 
reply_header_access Cache-Control allow all 
reply_header_access Content-Encoding allow all 
reply_header_access Content-Length allow all 
reply_header_access Content-Type allow all 
reply_header_access Date allow all 
reply_header_access Expires allow all 
reply_header_access Host allow all 
reply_header_access If-Modified-Since allow all 
reply_header_access Last-Modified allow all 
reply_header_access Location allow all 
reply_header_access Pragma allow all 
reply_header_access Accept allow all 
reply_header_access Accept-Charset allow all 
reply_header_access Accept-Encoding allow all 
reply_header_access Accept-Language allow all 
reply_header_access Content-Language allow all 
reply_header_access Mime-Version allow all 
reply_header_access Retry-After allow all 
reply_header_access Title allow all 
reply_header_access Connection allow all 
reply_header_access Proxy-Connection allow all 
reply_header_access User-Agent allow all 
reply_header_access Cookie allow all 
reply_header_access All deny all
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname WaGo-G
mySquid

# Restarting Squid Proxy
echo -e "Restarting proxy server..."
systemctl restart squid

# Setting System Time
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime

# Setting Terminal Message
[[ `cat .profile` =~ Dexter ]] ||
cat << 'intro' >> .profile
clear
echo -e '
     /$$      /$$            /$$$$$$                     /$$$$$$ 
    | $$  /$ | $$           /$$__  $$                   /$$__  $$
    | $$ /$$$| $$  /$$$$$$ | $$  \__/  /$$$$$$         | $$  \__/
    | $$/$$ $$ $$ |____  $$| $$ /$$$$ /$$__  $$ /$$$$$$| $$ /$$$$
    | $$$$_  $$$$  /$$$$$$$| $$|_  $$| $$  \ $$|______/| $$|_  $$
    | $$$/ \  $$$ /$$__  $$| $$  \ $$| $$  | $$        | $$  \ $$
    | $$/   \  $$|  $$$$$$$|  $$$$$$/|  $$$$$$/        |  $$$$$$/
    |__/     \__/ \_______/ \______/  \______/          \______/  
' && echo "
                       WaGo's VPN Script
                     by WaGo-G AND (X-DCB)
               https://fb.me/warren.pretorius.73
"
intro

# TCP BBR
brloc=/etc/modules-load.d/modules.conf
if [[ ! `cat $brloc` =~ "tcp_bbr" ]];then
modprobe tcp_bbr
echo tcp_bbr >> $brloc; fi

# System Settings
cat << sysctl > /etc/sysctl.d/xdcb.conf
net.ipv4.ip_forward=1
net.ipv4.tcp_rmem=65535 131072 4194304
net.ipv4.tcp_wmem=65535 131072 194304
net.ipv4.ip_default_ttl=50
net.ipv4.tcp_congestion_control=bbr
net.core.wmem_default=262144
net.core.wmem_max=4194304
net.core.rmem_default=262144
net.core.rmem_max=4194304
net.core.netdev_budget=600
net.core.default_qdisc=fq
net.ipv6.conf.all.accept_ra=2
sysctl
sysctl --system

# Startup scripts setup
mkdir -p /etc/wago
cat <<EOFSH > /etc/wago/startup.sh
#!/bin/bash
ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
export DEBIAN_FRONTEND=noninteractive
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT
/bin/bash /etc/openvpn/openvpn.bash
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port1 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port2 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port3 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $V2ray_Port4 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port1 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port2 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port3 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport $V2ray_Port4 -j ACCEPT
exit 0
EOFSH

# Startup Script
cat << wago > /etc/systemd/system/wago.service
[Unit]
Description=Wago Startup Script
Wants=network.target
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/wago/startup.sh
RemainAfterExit=yes
[Install]
WantedBy=network.target
wago

chmod +x /etc/wago/startup.sh
systemctl daemon-reload
systemctl enable wago
systemctl start wago

# Database Auth
cat << EOF > /etc/openvpn/script/config.sh
#!/bin/bash
HOST='$DatabaseHost'
USER='$DatabaseUser'
PASS='$DatabasePass'
DB='$DatabaseName'
PORT='$DatabasePort'
EOF
chmod +x /etc/openvpn/script/config.sh

# Setting Up Socks
loc=/etc/socksproxy
mkdir -p $loc

cat << Socks > $loc/proxy.py
import socket, threading, thread, select, signal, sys, time, getopt

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = $WsPort
PASS = ''

BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = "127.0.0.1:$WsConnectPort"
RESPONSE = '$WsResponse'

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
	self.threadsLock = threading.Lock()
	self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:                    
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue
                
                conn = ConnectionHandler(c, self, addr)
                conn.start();
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()
            
    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()
	
    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()
                    
    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()
                
    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()
            
            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()
			

class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True
            
        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
        
            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')
            
            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)
            
            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')
    
        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = $WsPort

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path
        
        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print 'proxy.py -b <bindAddr> -p <port>'
    print 'proxy.py -b 0.0.0.0 -p $WsPort'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)
    

def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()

    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break
    
if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
Socks

cat << service > /etc/systemd/system/socksproxy.service
[Unit]
Description=Socks Proxy
Wants=network.target
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python -O $loc/proxy.py
ExecStop=/bin/bash -c "kill -15 \`cat $loc/.pid\`"
[Install]
WantedBy=network.target
service
systemctl daemon-reload
systemctl enable socksproxy
systemctl restart socksproxy

# Setup Php 7.*

$APT update
$APT install php php-fpm php-cli php-mysql php-mcrypt libxml-parser-perl php-xml php-json php-pdo php-zip php-gd php-mbstring php-curl php-bcmath

phpl=`php --ini | grep -om 1 /etc/php/*`
phpv=`echo $phpl | cut -d/ -f4`

sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g;/display_errors =/{s/Off/On/g};/;session.save_path =/{s/;//g}' $phpl/fpm/php.ini
sed -i '/listen =/{s/= .*/= 127.0.0.1:9000/g}' $phpl/fpm/pool.d/www.conf

# Setup WebMin
echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
wget http://www.webmin.com/jcameron-key.asc -qO- | apt-key add -
$APT update
$APT install webmin
sed -i "s/ssl=1/ssl=0/g" /etc/webmin/miniserv.conf

systemctl restart {php$phpv-fpm,webmin}

# Setup Up Nginx
cat << myNginxC > /etc/nginx/conf.d/wago-config.conf
server {
 listen 0.0.0.0:$Nginx_Port;
 server_name localhost;
 root /var/www/openvpn;
 index index.html;
}
myNginxC
rm -rf /etc/nginx/sites-*/*
rm -rf /var/www/openvpn
mkdir -p /var/www/openvpn
echo "WaGo VPN Services" > /var/www/openvpn/index.html

# OpenVPN Cert
ovpnDir='/etc/openvpn'
cert="<ca>
$(cat $ovpnDir/ca.crt)
</ca>"

# Creating OpenVPN Configs 
cat << CLIENT > /var/www/openvpn/wago-tcp.ovpn
# WaGo's VPN Premium Script
# © Github.com/wagovps
# Official Repository: https://github.com/wagovps/AutoScriptDB
# Facebook: https://fb.me/warren.pretorius.73
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_TCP_Port
nobind
persist-key
persist-tun
resolv-retry infinite
auth-user-pass
verb 3
chiper AES-128 -CBC
auth SHA1
setenv CLIENT_CERT 0
reneg-sec 0
route $IPADDR 255.255.255.255 net_gateway

$cert
CLIENT

cat <<CLIENT> /var/www/openvpn/wago-udp.ovpn
# WaGo's VPN Premium Script
# © Github.com/wagovps
# Official Repository: https://github.com/wagovps/AutoScriptDB
# Facebook: https://fb.me/warren.pretorius.73
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
tls-client
dev tun
proto udp
setenv FRIENDLY_NAME "Debian VPN UDP"
remote $IPADDR $OpenVPN_UDP_Port
resolv-retry infinite
float
fast-io
nobind
persist-key
persist-remote-ip
persist-tun
auth-user-pass
auth-nocache
comp-lzo
redirect-gateway def1
reneg-sec 0
verb 1
key-direction 1

$cert
CLIENT

cat > /var/www/openvpn/wago-ssl.ovpn << CLIENT
# WaGo's VPN Premium Script
# © Github.com/wagovps
# Official Repository: https://github.com/wagovps/AutoScriptDB
# Facebook: https://fb.me/warren.pretorius.73
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp
remote 127.0.0.1 $Stunnel_Port3
nobind
persist-key
persist-tun
resolv-retry infinite
auth-user-pass
verb 3
chiper AES-128 -CBC
auth SHA1
setenv CLIENT_CERT 0
reneg-sec 0
route $IPADDR 255.255.255.255 net_gateway

$cert
CLIENT

cat <<CLIENT> /var/www/openvpn/wago-ssl2.ovpn
# WaGo's VPN Premium Script
# © Github.com/wagovps
# Official Repository: https://github.com/wagovps/AutoScriptDB
# Facebook: https://fb.me/warren.pretorius.73
# Thanks for using this script, Enjoy Highspeed OpenVPN Service
client
dev tun
proto tcp
remote $IPADDR $OpenVPN_TCP_Port
rport $Stunnel_Port3
nobind
persist-key
persist-tun
resolv-retry infinite
auth-user-pass
verb 3
chiper AES-128 -CBC
auth SHA1
setenv CLIENT_CERT 0
reneg-sec 0
route $IPADDR 255.255.255.255 net_gateway

$cert
CLIENT

# Creating OVPN Download Site
cat << mySiteOvpn > /var/www/openvpn/index.html
<!DOCTYPE html>
<html lang="en">

<!-- Simple OVPN Download site by WaGo-G VPN -->

<head><meta charset="utf-8" /><title>WaGo-G OVPN Config Download</title><meta name="description" content="WaGo-G VPN" /><meta content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" name="viewport" /><meta name="theme-color" content="#000000" /><link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.2/css/all.css"><link href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.8.3/css/mdb.min.css" rel="stylesheet"></head><body><div class="container justify-content-center" style="margin-top:9em;margin-bottom:5em;"><div class="col-md"><div class="view"><img src="https://openvpn.net/wp-content/uploads/openvpn.jpg" class="card-img-top"><div class="mask rgba-white-slight"></div></div><div class="card"><div class="card-body"><h5 class="card-title">Config List</h5><br /><ul class="list-group"><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>UDP Config <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://$IPADDR:$OvpnDownload_Port/wago-udp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP+Proxy <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /><a class="btn btn-outline-success waves-effect btn-sm" href="http://$IPADDR:$OvpnDownload_Port/wago-tcp.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP+SSL <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://$IPADDR:$OvpnDownload_Port/wago-openvpn-ssl.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li><li class="list-group-item justify-content-between align-items-center" style="margin-bottom:1em;"><p>TCP+Stunnel <span class="badge light-blue darken-4">Android/iOS/PC/Modem</span><br /></p><a class="btn btn-outline-success waves-effect btn-sm" href="http://$IPADDR:$OvpnDownload_Port/wago-openvpn-stunnel.ovpn" style="float:right;"><i class="fa fa-download"></i> Download</a></li></ul></div></div></div></div></body></html>
mySiteOvpn

# Restarting nginx service
systemctl restart nginx

cd /var/www/openvpn
zip -qq -r configs.zip *.ovpn
cd

# Setup Menu
cd /usr/local/sbin/
cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://raw.githubusercontent.com/wagovps/OvpnSsl/master/tool/premiummenu.zip'
unzip -qq premiummenu.zip
rm -f premiummenu.zip
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|g;s|http_port|listen-address|g' ./*

# Setup BadVPN
if [[ ! `ps -A | grep badvpn` ]]; then
if [[ ! `type -P docker` ]]; then
curl -fsSL https://download.docker.com/linux/$ID/gpg | apt-key add - 
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$ID $(lsb_release -cs) stable"
apt update
apt-cache policy docker-ce
apt install docker-ce -y
apt clean; fi

export sqx=n
[ `type -P dcomp` ] || wget "https://github.com/docker/compose/releases/download/1.24.0/docker-compose-$(uname -s)-$(uname -m)" -qO /sbin/dcomp
chmod +x /sbin/dcomp || return

wget -qO- https://github.com/X-DCB/Unix/raw/master/badvpn.yaml | dcomp -f - up -d; fi

docker run -d --restart always --name openvpn-monitor \
  --net host --cap-add NET_ADMIN \
  -e OPENVPNMONITOR_DEFAULT_DATETIMEFORMAT="%%d/%%m/%%Y %%H:%%M:%%S" \
  -e OPENVPNMONITOR_DEFAULT_MAPS=True \
  -e OPENVPNMONITOR_DEFAULT_MAPSHEIGHT=500 \
  -e OPENVPNMONITOR_DEFAULT_SITE="WaGo" \
  -e OPENVPNMONITOR_SITES_0_ALIAS=TCP \
  -e OPENVPNMONITOR_SITES_0_HOST=127.0.0.1 \
  -e OPENVPNMONITOR_SITES_0_NAME=TCP \
  -e OPENVPNMONITOR_SITES_0_PORT=$MGMT_TCP_PORT \
  -e OPENVPNMONITOR_SITES_0_SHOWDISCONNECT=True \
  -e OPENVPNMONITOR_SITES_1_ALIAS=UDP \
  -e OPENVPNMONITOR_SITES_1_HOST=127.0.0.1 \
  -e OPENVPNMONITOR_SITES_1_NAME=UDP \
  -e OPENVPNMONITOR_SITES_1_PORT=$MGMT_UDP_PORT \
  ruimarinho/openvpn-monitor gunicorn openvpn-monitor --bind 0.0.0.0:$Monitor_Port

# Create OpenVPN Paths
mkdir /etc/openvpn/script
chmod -R 777 /etc/openvpn/script
mkdir /var/www/html/stat
chmod -R 777 /var/www/html/stat

# Credentials
cat << EOF > /etc/openvpn/script/config.sh
#!/bin/bash
HOST='$DatabaseHost'
USER='$DatabaseUser'
PASS='$DatabasePass'
DB='$DatabaseName'
PORT='$DatabasePort'
EOF
chmod +x /etc/openvpn/script/config.sh

case $opts in
    1) cat='premium';;
    2) cat='vip';;
    3) cat='private';;
esac

# Creating TCP OpenVPN Config
cat << WAGO01 >/etc/openvpn/server_tcp.conf
# $VPN_Name Server
# Server by $VPN_Owner

mode server 
tls-server 
port $OpenVPN_TCP_Port
management 127.0.0.1 $MGMT_TCP_PORT
proto tcp4
dev tun 
cipher AES-128-CBC
auth SHA1
tun-mtu-extra 32 
tun-mtu 1400 
mssfix 1360
tcp-queue-limit 128
txqueuelen 2000
tcp-nodelay
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
script-security 3
ifconfig-pool-persist ipp.txt
verify-client-cert none
username-as-common-name 
auth-user-pass-verify "/etc/openvpn/script/auth.sh" via-env
client-connect /etc/openvpn/script/connect.sh
client-disconnect /etc/openvpn/script/disconnect.sh
server 10.200.0.0 255.255.0.0
push "redirect-gateway def1" 
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 5 30
persist-key 
persist-tun
verb 3
status /var/www/html/stat/tcp.txt

WAGO01

# Creating UDP OpenVPN Config
cat << WAGO02 >/etc/openvpn/server_udp.conf
# $VPN_Name Server
# Server by $VPN_Owner

port $OpenVPN_UDP_Port
management 127.0.0.1 $MGMT_UDP_PORT
proto udp
dev tun
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh2048.pem
client-to-client
username-as-common-name
client-cert-not-required
auth-user-pass-verify "/etc/openvpn/script/auth.sh" via-env
client-connect /etc/openvpn/script/connect.sh
client-disconnect /etc/openvpn/script/disconnect.sh
server 10.201.0.0 255.255.0.0
ifconfig-pool-persist ipp.txt
push "route-method exe"
push "route-delay 2"
keepalive 5 60
reneg-sec 0
comp-lzo
persist-key
persist-tun
status /var/www/html/stat/udp.txt
log udp.log
verb 2
status-version 1
script-security 3

WAGO02

# Auth Connect Script
cat <<'WAGO05' | sed -e "s|#cat#|$cat|g" >/etc/openvpn/script/connect.sh
#!/bin/bash

tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

##set status online to user connected
bandwidth_check=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-names -e "SELECT bandwidth_logs.username FROM bandwidth_logs WHERE bandwidth_logs.username='$common_name' AND bandwidth_logs.category='#cat#' AND bandwidth_logs.status='online'"`
if [ "$bandwidth_check" == 1 ]; then
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwith_logs SET server_ip='$local_1', server_port='$trusted_port', timestamp='$timestamp', ipaddress='$trusted_ip:$trusted_port', username='$common_name', time_in='$tm', since_connected='$time_ascii', bytes_received='$bytes_received', bytes_sent='$bytes_sent' WHERE username='$common_name' AND status='online' AND category='#cat#' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=1 WHERE user_name='$common_name' "
else
mysql -u $USER -p$PASS -D $DB -h $HOST -e "INSERT INTO bandwidth_logs (server_ip, server_port, timestamp, ipaddress, since_connected, username, bytes_received, bytes_sent, time_in, status, time, category) VALUES ('$local_1','$trusted_port','$timestamp','$trusted_ip:$trusted_port','$time_ascii','$common_name','$bytes_received','$bytes_sent','$dt','online','$tm','#cat#') "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET device_connected=1, is_connected=1 WHERE user_name='$common_name' "
fi

WAGO05

# Auth Disconnect Script 
cat <<'WAGO06' | sed -e "s|#cat#|$cat|g" >/etc/openvpn/script/disconnect.sh
#!/bin/bash
tm="$(date +%s)"
dt="$(date +'%Y-%m-%d %H:%M:%S')"
timestamp="$(date +'%FT%TZ')"

. /etc/openvpn/script/config.sh

mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE bandwidth_logs SET bytes_received='$bytes_received',bytes_sent='$bytes_sent',time_out='$dt', status='offline' WHERE username='$common_name' AND status='online' AND category='#cat#' "
mysql -u $USER -p$PASS -D $DB -h $HOST -e "UPDATE users SET is_connected=0 WHERE user_name='$common_name' "

WAGO06

# Auth Script
cat <<'WAGO07' >/etc/openvpn/script/auth.sh
#!/bin/bash
. /etc/openvpn/script/config.sh
  
##PREMIUM##
PRE="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.duration > 0"
  
##VIP##
VIP="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.vip_duration > 0"
  
##PRIVATE##
PRIV="users.user_name='$username' AND users.auth_vpn=md5('$password') AND users.is_validated=1 AND users.is_freeze=0 AND users.is_active=1 AND users.is_ban=0 AND users.private_duration > 0"
  
Query="SELECT users.user_name FROM users WHERE $VIP OR $PRIV OR $PRE"
user_name=`mysql -u $USER -p$PASS -D $DB -h $HOST --skip-column-names -e "$Query"`
  
[ "$user_name" != '' ] && [ "$user_name" = "$username" ] && echo "user : $username" && echo 'authentication ok.' && exit 0 || echo 'authentication failed.'; exit 1

WAGO07

# Setting SSH CRON Jobs
cat <<'CronPanel2' > "/etc/$Filename_alias.cron.php"
<?php
error_reporting(E_ERROR | E_PARSE);
ini_set('display_errors', '1');

$DB_host = 'DatabaseHost';
$DB_user = 'DatabaseUser';
$DB_pass = 'DatabasePass';
$DB_name = 'DatabaseName';

$mysqli = new MySQLi($DB_host,$DB_user,$DB_pass,$DB_name);
if ($mysqli->connect_error) {
    die('Error : ('. $mysqli->connect_errno .') '. $mysqli->connect_error);
}

function encrypt_key($paswd)
    {
      $mykey=getEncryptKey();
      $encryptedPassword=encryptPaswd($paswd,$mykey);
      return $encryptedPassword;
    }
     
    // function to get the decrypted user password
    function decrypt_key($paswd)
    {
      $mykey=getEncryptKey();
      $decryptedPassword=decryptPaswd($paswd,$mykey);
      return $decryptedPassword;
    }
     
    function getEncryptKey()
    {
        $secret_key = md5('eugcar');
        $secret_iv = md5('sanchez');
        $keys = $secret_key . $secret_iv;
        return encryptor('encrypt', $keys);
    }
    function encryptPaswd($string, $key)
    {
      $result = '';
      for($i=0; $i<strlen ($string); $i++)
      {
        $char = substr($string, $i, 1);
        $keychar = substr($key, ($i % strlen($key))-1, 1);
        $char = chr(ord($char)+ord($keychar));
        $result.=$char;
      }
        return base64_encode($result);
    }
     
    function decryptPaswd($string, $key)
    {
      $result = '';
      $string = base64_decode($string);
      for($i=0; $i<strlen($string); $i++)
      {
        $char = substr($string, $i, 1);
        $keychar = substr($key, ($i % strlen($key))-1, 1);
        $char = chr(ord($char)-ord($keychar));
        $result.=$char;
      }
     
        return $result;
    }
    
    function encryptor($action, $string) {
        $output = false;

        $encrypt_method = "AES-256-CBC";
        //pls set your unique hashing key
        $secret_key = md5('eugcar sanchez');
        $secret_iv = md5('sanchez eugcar');

        // hash
        $key = hash('sha256', $secret_key);
        
        // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
        $iv = substr(hash('sha256', $secret_iv), 0, 16);

        //do the encyption given text/string/number
        if( $action == 'encrypt' ) {
            $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
            $output = base64_encode($output);
        }
        else if( $action == 'decrypt' ){
            //decrypt the given text/string/number
            $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
        }

        return $output;
    }

$data = '';
$query = $mysqli->query("SELECT * FROM users
WHERE is_freeze = 0 AND vip_duration > 0 OR is_freeze = 0 AND private_duration > 0 ORDER by user_id DESC");

if($query->num_rows > 0)
{
    while($row = $query->fetch_assoc())
    {
        $data .= '';
        $username = $row['user_name'];
        $password = decrypt_key($row['user_pass']);
        $password = encryptor('decrypt',$password);     
        $data .= '/usr/sbin/useradd -p $(openssl passwd -1 '.$password.') -s /bin/false -M '.$username.' &> /dev/null;'.PHP_EOL;
    }
}
$location = '/etc/openvpn/active.sh';
$fp = fopen($location, 'w');
fwrite($fp, $data) or die("Unable to open file!");
fclose($fp);


#In-Active and Invalid Accounts
$data2 = '';
$premium_deactived = "duration <= 0";
$vip_deactived = "vip_duration <= 0";
$private_deactived = "private_duration <= 0";
$is_validated = "is_validated=0";
$is_activate = "is_active=0";
$freeze = "is_freeze=1";
//$suspend = "suspend=1";

$query2 = $mysqli->query("SELECT * FROM users 
WHERE ".$freeze." OR ".$premium_deactived." AND ".$vip_deactived ." AND ".$private_deactived." OR ".$is_activate."
");
if($query2->num_rows > 0)
{
    while($row2 = $query2->fetch_assoc())
    {
        $data2 .= '';
        $toadd = $row2['user_name'];    
        $data2 .= '/usr/sbin/userdel -r -f '.$toadd.' &> /dev/null;'.PHP_EOL;
    }
}
$location2 = '/etc/openvpn/inactive.sh';
$fp = fopen($location2, 'w');
fwrite($fp, $data2) or die("Unable to open file!");
fclose($fp);

$mysqli->close();
?>
CronPanel2

sed -i "s|DatabaseHost|$DatabaseHost|g;s|DatabaseName|$DatabaseName|g;s|DatabaseUser|$DatabaseUser|g;s|DatabasePass|$DatabasePass|g" "/etc/$Filename_alias.cron.php"

chmod +x "/etc/$Filename_alias.cron.php"

# Setting Permissions
chmod +x /etc/openvpn/script/auth.sh
chmod +x /etc/openvpn/script/connect.sh
chmod +x /etc/openvpn/script/disconnect.sh

# Fixing Multilogin Script
cat <<'Multilogin' >/usr/local/sbin/set_multilogin_autokill_lib
#!/bin/bash
clear
MAX=1
if [ -e "/var/log/auth.log" ]; then
        OS=1;
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        OS=2;
        LOG="/var/log/secure";
fi

if [ $OS -eq 1 ]; then
    service ssh restart > /dev/null 2>&1;
fi
if [ $OS -eq 2 ]; then
    service sshd restart > /dev/null 2>&1;
fi
    service dropbear restart > /dev/null 2>&1;
                
if [[ ${1+x} ]]; then
        MAX=$1;
fi

        cat /etc/passwd | grep "/home/" | cut -d":" -f1 > /root/user.txt
        username1=( `cat "/root/user.txt" `);
        i="0";
        for user in "${username1[@]}"
            do
                username[$i]=`echo $user | sed 's/'\''//g'`;
                jumlah[$i]=0;
                i=$i+1;
            done
        cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/log-db.txt
        proc=( `ps aux | grep -i dropbear | awk '{print $2}'`);
        for PID in "${proc[@]}"
            do
                cat /tmp/log-db.txt | grep "dropbear\[$PID\]" > /tmp/log-db-pid.txt
                NUM=`cat /tmp/log-db-pid.txt | wc -l`;
                USER=`cat /tmp/log-db-pid.txt | awk '{print $10}' | sed 's/'\''//g'`;
                IP=`cat /tmp/log-db-pid.txt | awk '{print $12}'`;
                if [ $NUM -eq 1 ]; then
                        i=0;
                        for user1 in "${username[@]}"
                            do
                                if [ "$USER" == "$user1" ]; then
                                        jumlah[$i]=`expr ${jumlah[$i]} + 1`;
                                        pid[$i]="${pid[$i]} $PID"
                                fi
                                i=$i+1;
                            done
                fi
            done
        cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/log-db.txt
        data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);
        for PID in "${data[@]}"
            do
                cat /tmp/log-db.txt | grep "sshd\[$PID\]" > /tmp/log-db-pid.txt;
                NUM=`cat /tmp/log-db-pid.txt | wc -l`;
                USER=`cat /tmp/log-db-pid.txt | awk '{print $9}'`;
                IP=`cat /tmp/log-db-pid.txt | awk '{print $11}'`;
                if [ $NUM -eq 1 ]; then
                        i=0;
                        for user1 in "${username[@]}"
                            do
                                if [ "$USER" == "$user1" ]; then
                                        jumlah[$i]=`expr ${jumlah[$i]} + 1`;
                                        pid[$i]="${pid[$i]} $PID"
                                fi
                                i=$i+1;
                            done
                fi
        done
        j="0";
        for i in ${!username[*]}
            do
                if [ ${jumlah[$i]} -gt $MAX ]; then
                        date=`date +"%Y-%m-%d %X"`;
                        echo "$date - ${username[$i]} - ${jumlah[$i]}";
                        echo "$date - ${username[$i]} - ${jumlah[$i]}" >> /root/log-limit.txt;
                        kill ${pid[$i]};
                        pid[$i]="";
                        j=`expr $j + 1`;
                fi
            done
        if [ $j -gt 0 ]; then
                if [ $OS -eq 1 ]; then
                        service ssh restart > /dev/null 2>&1;
                fi
                if [ $OS -eq 2 ]; then
                        service sshd restart > /dev/null 2>&1;
                fi
                service dropbear restart > /dev/null 2>&1;
                j=0;
        fi
Multilogin

systemctl enable openvpn@server_tcp
systemctl start openvpn@server_tcp
systemctl enable openvpn@server_udp
systemctl start openvpn@server_udp

# Setup V2Ray
mkdir -p /etc/v2ray
curl https://acme-install.netlify.app/acme.sh -o /usr/local/bin/acme.sh
chmod +x /usr/local/bin/acme.sh
acme.sh --issue -d $domain --standalone -k ec-256 --home /etc/v2ray
acme.sh --install-cert -d $domain \
 --fullchain-file /etc/v2ray/v2ray.crt \
 --key-file /etc/v2ray/v2ray.key \
 --ecc --home /etc/v2ray

cat> /etc/v2ray/config.json << END
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": $V2ray_Port1,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 2
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/v2ray/v2ray.crt",
              "keyFile": "/etc/v2ray/v2ray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/wago",
          "headers": {
            "Host": "$domain"
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END

cat> /etc/v2ray/none.json << END
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": $V2ray_Port2,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "alterId": 2
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/wago",
          "headers": {
            "Host": "$domain"
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /etc/v2ray/vless.json << END
{
  "log": {
    "access": "/var/log/v2ray/access2.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": $V2ray_Port3,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/v2ray/v2ray.crt",
              "keyFile": "/etc/v2ray/v2ray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/wago",
          "headers": {
            "Host": "$domain"
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /etc/v2ray/vnone.json << END
{
  "log": {
    "access": "/var/log/v2ray/access2.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": $V2ray_Port4,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/wago",
          "headers": {
            "Host": "$domain"
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END

docker run -d --restart always --name v2ray --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 v2fly/v2fly-core
docker run -d --restart always --name v2ray-none --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 -v /etc/v2ray/none.json:/etc/v2ray/config.json \
 v2fly/v2fly-core
docker run -d --restart always --name v2ray-vless --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 -v /etc/v2ray/vless.json:/etc/v2ray/config.json \
 v2fly/v2fly-core
docker run -d --restart always --name v2ray-vnone --net host --cap-add NET_ADMIN \
 -v /etc/v2ray:/etc/v2ray \
 -v /etc/v2ray/vnone.json:/etc/v2ray/config.json \
 v2fly/v2fly-core

# Setup Apache
sed -i "s|Listen 80|Listen $Apache_Port|g" /etc/apache2/ports.conf
service apache2 restart
a2enmod proxy_fcgi setenvif
a2enconf php$phpv-fpm
systemctl reload apache2 #activate

# Set Stat Permissions
chmod 777 /var/www/html/stat/tcp.txt
chmod 777 /var/www/html/stat/udp.txt

# Setting SSH To Work With Panel
mkdir /usr/sbin/kpn
wget -O /usr/sbin/kpn/connection.php "https://raw.githubusercontent.com/pcfreak/ssh-ssl-connect/master/premiumconnection.sh"

# Cloudflare Domain
echo "$Cloudflare_Domain" >> /root/domain

# Setup Cron
cat << cron > /etc/cron.d/$Filename_alias
* * * * * root php -q /etc/$Filename_alias.cron.php
* * * * * root bash /etc/openvpn/active.sh
* * * * * root bash /etc/openvpn/inactive.sh

cron
echo -e "0 4 * * * root reboot" > /etc/cron.d/b_reboot_job
echo -e "* * * * *  root /usr/local/sbin/set_multilogin_autokill_lib 1" >> "/etc/cron.d/set_multilogin_autokill_lib"
echo -e "* * * * * root /usr/bin/php /usr/sbin/kpn/connection.php >/dev/null 2>&1" > /etc/cron.d/connection
echo -e "* * * * * root /bin/bash /usr/sbin/kpn/active.sh>/dev/null 2>&1"> /etc/cron.d/active
echo -e "* * * * * root /bin/bash /usr/sbin/kpn/inactive.sh >/dev/null 2>&1" > /etc/cron.d/inactive
systemctl restart cron
systemctl enable cron

# Script Info
clear

cat << logs | tee -a ~/log-install.txt

INSTALLATION HAS BEEN COMPLETED!!
============================-AUTOSCRIPT WAGO-G-============================

---------------------------------------------------------------------------

   >>> Service & Port
   - OpenSSH                 : $SSH_Port1, $SSH_Port2 
   - OpenVPN                 : TCP $OpenVPN_TCP_Port UDP $OpenVPN_UDP_Port
   - Stunnel/SSL             : $Stunnel_Port1, $Stunnel_Port2, $Stunnel_Port3
   - Dropbear                : $Dropbear_Port1, $Dropbear_Port2
   - Squid Proxy             : $Squid_Port1, $Squid_Port2 , $Squid_Port3
   - Badvpn                  : 7300
   - Nginx                   : $Nginx_Port
   - Apache                  : $Apache_Port
   - Socks                   : $WsPort
   - V2RAY Vmess TLS         : $V2ray_Port1
   - V2RAY Vmess None TLS    : $V2ray_Port2
   - V2RAY Vless TLS         : $V2ray_Port3
   - V2RAY Vless None TLS    : $V2ray_Port4

   >>> Server Information & Features
   - Timezone                : Africa/Johannesburg (GMT +2)
   - Fail2Ban                : [ON]
   - IPtables                : [ON]
   - Auto-Reboot             : [ON]
   - IPv6                    : [OFF]
   - Webmin Login Page       : http://$IPADDR:10000/
   - OpenVPN Monitor         : http://$IPADDR:$Monitor_Port/
   - Download All Configs    : http://$IPADDR:$Nginx_Port/configs.zip
   - Download TCP Config     : http://$IPADDR:$Nginx_Port/wago-tcp.ovpn
   - Download UDP Config     : http://$IPADDR:$Nginx_Port/wago-udp.ovpn
   - Download SSL Config     : http://$IPADDR:$Nginx_Port/wago-ssl.ovpn
   - Download SSL2 Config    : http://$IPADDR:$Nginx_Port/wago-ssl2.ovpn
   - Dev/Main                : ©WaGo-G
   - Telegram                : T.me/WaGo_G_30
   - Facebook                : Fb.me/warren.pretorius.73

---------------------------------------------------------------------------

===========================================================================

logs

# Clearing Logs
rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
rm -f *.sh

cd
exit 0