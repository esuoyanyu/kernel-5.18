# ubuntu update kernel
```
#查看
sudo apt list | grep linux-image
#卸载
sudo apt remove --purge linux-image-xxxx
#安装
sudo apt install linux-image-xxx
#下载源码
sudo apt install linux-source
cp /usr/src/linux-source-xxx ./
cp /boot/config-5.15.0-53-generic ./.config
```

# grub
```
#手动选择内核
sudo cp /etc/default/grub /etc/default/grub.back
sudo vim /etc/default/grub

GRUB_SAVEDEFAULT=true
GRUB_DEFAULT=1
#GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=10
```

# bcompare 
```
rm -rf ~/.config/bcompare/registry.dat
```

# vscode
```
"[python]": {
	"editor.insertSpaces": true, 
	"editor.tabSize": 4
},
"[markdown]": {
	"editor.insertSpaces": true,
	"editor.tabSize": 4
},
"[shellscript]": {
	"editor.insertSpaces": false,
	"editor.tabSize": 8
},
```

# ubuntu server
## set time zone
```
sudo cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
```
## http proxy
```
sudo apt install squid

sudo vim /etc/squid/squid.conf
acl esuoyanyu src 192.168.3.0/24
http_access allow esuoyanyu
http_port 192.168.3.100:3128

sudo systemctl restart squid.service
```

## VPN
```
sudo apt-get install strongswan xl2tpd ppp

sudo vim /etc/ipsec.conf
conn esuoyanyu
        auto=add
        keyexchange=ikev1
        authby=secret
        type=transport
        left=%defaultroute
        leftprotoport=17/1701
        rightprotoport=17/1701
        right=xxx.xxx.xxx.xxx
        ike=aes128-sha1-modp2048
        esp=aes128-sha1

sudo vim /etc/xl2tpd/xl2tpd.conf
[lac esuoyanyu]
lns = 119.28.135.58
;ppp debug = yes
pppoptfile = /etc/ppp/options.l2tpd.client
length bit = yes

sudo vim /etc/ppp/options.l2tpd.client
ipcp-accept-local
ipcp-accept-remote
refuse-eap
require-chap
noccp
noauth
mtu 1280
mru 1280
noipdefault
defaultroute
usepeerdns
connect-delay 5000
name "chy"
password "xxxxxxxxxxxxxxxxxxx"

sudo vim /etc/ipsec.secrets
%any %any : PSK 'xxxxxxxxxxxxxxxxxxx'

sudo systemctl restart ipsec.service
sudo systemctl restart l2tpd.service

sudo ip route add 119.28.135.58 via 192.168.3.1
sudo ip route change default via 10.0.0.2 dev ppp0

sudo ipsec up esuoyanyu
sudo bash -c "echo 'c esuoyanyu' > /var/run/xl2tpd/l2tp-control"

```

