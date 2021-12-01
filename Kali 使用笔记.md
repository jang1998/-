# Kali 使用笔记

2021年3月8日

> 大部分需要前面加sudo权限，输入完成后reboot重启



系统语言 	zh-cn utf-8 utf-8

```
dpkg-reconfigure locales
```

安装图形化界面

```
vi /etc/apt/sources.lst
deb http://http.kali.org/kali kali-rolling contrib main non-free
apt-get update
apt install x-window-system-core xfce4 -y
```

改root密码

```
passwd root
```

乱码问题

```
apt-get install fonts-wqy-microhei fonts-wqy-zenhei
```

安装谷歌浏览器
```
apt-get install chromium -y
```

安装第三方软件

```
dpkg -i 软件名
```

切换root用户

```
sudo su -
exit
```

wireshake查看访问过ip

```
统计-ipv4 statistics-all address
```

wireshake提取照片

```
文件-导出对象-http	选中照片导出
```

wireshark捕获无线数据包

```
ifconfig /查看网口
airmon-ng start wlan0
iwconfig
打开wireshark
```

Wireshark发现周边无线网络和设备

```
无线-wlan流量
```

wireshark显示过滤器

```
ip.addr == 192.168.1.1	/过滤ip地址
ip.src == 192.168.1.1	/过滤来源ip
ip.dst == 192.168.1.1	/过滤目的ip

tcp.port == 80	/过滤端口
tcp.srcport == 80	
tcp.dstport == 80
tcp.flag.syn == 1

arp tcp,	udp,	not http,	not arp	/过滤协议
```



查看网络接口

```
ifconfig
```

查看无线接口

```
iwconfig
```

扫描无线网络

```
wash -i wlan0 -s -a
```

扫描加密网络

```
wash -i wlan0 -s 
```

挂代理

```
安装proxychains
vim /etc/proxychains.conf
http 192.168.124.21 1080 /不能翻墙的地址通过可以翻墙的地址上网
```

共享文件

```
window共享后
smbclient //192.168.124.21/study -U jang	//远程连接
? 	//查看可使用命令
help xx //查看命令
get xx//下载
```

查找文件

locate xxx

burpsuite安装笔记

```
下载同windows，将cmd内容改成下  后缀并改成sh
/usr/lib/jvm/java-11-openjdk-amd64/bin/java --illegal-access=permit -Dfile.encoding=utf-8 -javaagent:BurpSuiteLoader_v2021.5.1.jar -noverify -jar burpsuite_pro_v2021.5.1.jar

cd burpsuite
chmod +x load.jar
chmod +x keyden.jar
chmod +x start.sh
./start.sh  其他同windowns
```



### 1.信息收集

> https://wizardforcel.gitbooks.io/daxueba-kali-linux-tutorial/content/16.html
>
> 存活主机识别、路由分析、情报分析、网络扫描、DNS分析、IDS/IPS识别、SMB，SMTP，SNMP，SSL分析

#### 1.1枚举

##### 1.1.1DNSenum

> 域名信息收集工具，执行域服axfr请求，通过谷歌得到信息

- --threads [number]：设置用户同时运行多个进程数。
- -r：允许用户启用递归查询。
- -d：允许用户设置WHOIS请求之间时间延迟数（单位为秒）。
- -o：允许用户指定输出位置。
- -w：允许用户启用WHOIS请求。

##### 1.1.2DNS枚举工具fierce

> 子域名扫描，获得目标主机所有ip地址和主机信息

爆破子域名

```
fierce -dns xx.com
```

自定义字典爆破子域名

```
cat xx.txt /生成字典文件,只需要输入前缀
fierce -dns xx.com -wordlist xx.txt/使用自定义字典进行爆破
```

> 通过threads、tcptimeout、delay三个参数可以进行扫描调优。具体的参数随不同机器、网络状况而不同
>

##### 1.1.3SNMP枚举工具Snmpwalk

> 使用SNMP的GETNEXT请求，查询指定的所有OID树信息





#### 1.2测试网络范围

##### 1.2.1 域名查询DMitry

> DMitry工具是用来查询IP或域名WHOIS信息的,使用该工具可以查到域名的注册商和过期时间等

```
dmitry -wnpb baidu.com	/查询域名信息
netmask -s baidu.com	/将域名转换为标准格式
```



##### 1.2.2 跟踪路由工具Scapy

> 一款强大的交互式数据包处理工具、数据包生成器、网络扫描器、网络发现工具和包嗅探工具

```
scapy	/启动
ans,unans=sr(IP(dst="www.rzchina.net/30",ttl=(1,6))/TCP())/使用sr函数实现发送和接受包
ans.make_table(lambda(s,r):(s.dst,s.ttl,r.src))	/以表形式查看包发送情况
res,unans=traceroute(["ip","ip","ip"],dport=[80,443],maxttl=20,retry=-2)/查看tcp路由跟踪
res.graph()	/图表形式显示路由跟踪信息(target=">/tmp/graph.svg")保存
exit() /退出ctrl+d
```

#### 1.3识别活跃主机

> arping,fping,hping3,masscan,thcping6,unicornscan,xprobe2

##### 1.3.1 网络映射器工具Nmap

> 1探测主机在线，2扫描主机端口，3推断使用系统

```
nmap -sP 192.168.41.136 	/查看主机是否在线
nping --echo-client "public" echo.nmap.org	/查看发送数据包

```

##### 1.3.2 使用Nmap识别活跃主机

```
nping -tcp -p 445 -data AF56A43D 192.168.41.136	/发送指定端口
通过发送数据包到指定端口模拟出一些常见的网络层攻击，以验证目标系统对这些测试的防御情况
```

#### 1.4查看打开端口

```
nmap 192.168.41.136	/查看开放端口号 -p 1-n 指定范围
nmap -p 22 192.168.41.*	/指定端口 -oG /tmp/nmap-targethost-tcp445.txt 指定输出格式
```

#### 1.5系统指纹识别

##### 1.5.1使用Nmap工具识别系统指纹信息

```
nmap -O 192.168.124.1	/启动操作系统测试功能
```

##### 1.5.2 指纹识别工具p0f

> 百分百的被动指纹识别工具，通过分析目标主机发出包对操作系统进行鉴别

```
p0f -r pcap文件地址 -o log文件地址 	/分析wireshark文件 
```

#### 1.6服务的指纹识别

##### 1.6.1Nmap

```
nmap -sV 192.168.124.1	/查看正在运行的端口
```

##### 1.6.2Amap

> 识别指定端口的应用程序

```
amap -bq 192.168.41.136 50-100
```

#### 1.7其他信息手记手段

##### 1.7.1recon-ng框架

> python开源web侦查框架，自动收集信息和网络侦查

```
recon-ng	/启动，help
show modules	/展示模块
use recon/domains-hosts/baidu_site	/使用模块，查看模块可配置选项参数
set SOURCE baidu.com	/设置参数
run	/运行

use reporting/csv	/使用报告模块
run	/生成报告

```



##### 1.7.2ARP侦查工具Netdiscover

> Netdiscover是一个主动/被动的ARP侦查工具。该工具在不使用DHCP的无线网络上非常有用

```
netdiscover
-i device：指定网络设备接口。
-r range：指定扫描网络范围。
-l file：指定扫描范围列表文件。
-p：使用被动模式，不发送任何数据。
-s time：每个ARP请求之间的睡眠时间。
-n node：使用八字节的形式扫描。
-c count：发送ARP请求的时间次数。
-f：使用主动模式。
-d：忽略配置文件。
-S：启用每个ARP请求之间抑制的睡眠时间。
-P：打印结果。
-L：将捕获信息输出，并继续进行扫描。
```



##### 1.7.3搜索引擎工具Shodan

> 搜索服务器shodan.io

1. City和Country命令

使用City和Country命令可以缩小搜索的地理位置。如下所示。

- country:US表示从美国进行搜索。
- city:Memphis表示从孟斐斯城市搜索。

City和Country命令也可以结合使用。如下所示。

- country:US city:Memphis。

2. HOSTNAME命令

HOSTNAME命令通过指定主机名来扫描整个域名。

- hostname:google表示搜索google主机。

3. NET命令

使用NET命令扫描单个IP或一个网络范围。如下所示。

- net:192.168.1.10：扫描主机192.168.1.10。
- net:192.168.1.0/24：扫描192.168.1.0/24网络内所有主机。

4. Title命令

使用Title命令可以搜索项目。如下所示。

- title:“Server Room”表示搜索服务器机房信息。

5. 关键字搜索

Shodan使用一个关键字搜索是最受欢迎的方式。如果知道目标系统使用的服务器类型或嵌入式服务器名，来搜索一个Web页面是很容易的。如下所示。

- apache/2.2.8 200 ok：表示搜索所有Apache服务正在运行的2.2.8版本，并且仅搜索打开的站点。
- apache/2.2.8 -401 -302：表示跳过显示401的非法页或302删除页。

6．组合搜索

- IIS/7.0 hostname:YourCompany.com city:Boston表示搜索在波士顿所有正在运行IIS/7.0的Microsoft服务器。
- IIS/5.0 hostname:YourCompany.com country:FR表示搜索在法国所有运行IIS/5.0的系统。
- Title:camera hostname:YourCompany.com表示在某台主机中标题为camera的信息。
- geo:33.5,36.3 os:Linux表示使用坐标轴（经度33.5，纬度36.3）的形式搜索Linux操作系统。

7．其他搜索术语

- Port：通过端口号搜索。
- OS：通过操作系统搜索。
- After或Before：使用时间搜索服务。



#### 1.8使用Maltego收集信息



#### 1.9绘制网络结构图





### 2.漏洞扫描

> https://wizardforcel.gitbooks.io/daxueba-kali-linux-tutorial/content/26.html
>
> 压力测试、Cisco工具集、Fuzzing工具集、Nessus、OpenVAS（GVM）、VoIP工具集

#### 2.1nessus使用

[nessus学习地址]: https://wizardforcel.gitbooks.io/daxueba-kali-linux-tutorial/content/27.html

##### 5.1.1安装和配置nessus

```
systemctl start nessusd.service	/打开
https://127.0.0.1:8834 	/地址
769R-ZNDU-656D-CN7Y-9APL	/激活码
```



##### 5.1.2扫描本地漏洞



##### 5.1.3扫描网络漏洞



##### 5.1.4扫描指定Linux系统漏洞 



##### 5.1.5 扫描指定Windows的系统漏洞





#### 2.2openvas使用

[openvas学习]: https://wizardforcel.gitbooks.io/daxueba-kali-linux-tutorial/content/28.html

##### 2.2.1配置openvas

```
127.0.0.1:9392	/地址
sudo runuser -u _gvm -- gvmd --user=admin --new-password=admin  /修改密码
gvm-start  stop	/开启服务
```

##### 2.2.2创建Scan Config和扫描任务



##### 2.2.3扫描本地漏洞



##### 2.2.4 扫描网络漏洞



##### 2.2.5 扫描指定Linux系统漏洞



##### 2.2.6 扫描指定Windows系统漏洞



### 3.web程序

> CMS识别、Web漏扫、Web爬行、Web应用代理
>

### 4数据库评估

> 
>

### 5.密码攻击

> https://wizardforcel.gitbooks.io/daxueba-kali-linux-tutorial/content/40.html
>
> 哈希工具集、离线攻击、在线攻击、Password Profilling & Wordlists

#### 5.1密码在线破解

#### 5.2分析密码

#### 5.3破解LM Hashes密码

#### 5.4绕过Utilman登录

#### 5.5破解纯文本密码工具mimikatz

#### 5.6破解操作系统用户密码

#### 5.7创建密码字典



### 6.无线攻击

> https://wizardforcel.gitbooks.io/daxueba-kali-linux-tutorial/content/50.html
>
> 蓝牙工具集、其他无线工具、软件无线电、无线工具集、RFID/NFC工具集

#### 6.1无线网络嗅探工具Kismet

```
kismet
127.0.0.1:2501
```



#### 6.2使用Aircrack-ng破解

> 基于破解802.11协议，主要使用fms攻击和korek攻击
>

##### 6.2.1 WEP

```
airmon-ng check kill   
ifconfig wlan0 down
iwconfig wlan0 mode monitor /(开启监听模式)
ifconfig wlan0 up  

CH：信道号	ENC：加密算法体系	CIPHER:加密算法	AUTH:认证协议	
airodump-ng wlan0  /定位附件wifi  -c指定频道 -w指定文件名 -bssid指定id
aireplay-ng -1 0 -a [BSSID] -h [our Chosen MAC address] -e [ESSID] [Interface]
aireplay-ng -dauth 1 -a [BSSID] -c [our Chosen MAC address] [Interface]

aireplay-ng 3 -b [BSSID] -h [MAC address] [Interface]	/发送无线流量以至于捕获
aircrack-ng xx-01.cap -w /root/下载/passwd.txt 

ifconfig wlan0 down
iwconfig wlan0 mode manager
ifconfig wlan0 up  
systemctl net restart	/重新开启服务
连接wifi
```

##### 6.2.2 WPA和WPA2

```
airodump-ng wlan0	/找wifi

airodump-ng -c ch -b mac -w filename wlan0  /-w接保存cap文档，-b接目标mac，ch是频道，捕获目标
获得目标已连接的mac后，另开窗口
aireplay-ng -0 频道 -a 目标 -c 目标已连接的mac wlan0 /进行Deauth攻击，取消工作站认证，--deauth同
aircrack-ng cap地址 -w 密码本地址 	/暴力破解，cap地址默认为/root
```

##### 6.2.3 WPS/QSS

使用Reaver

```
reaver -i mon0 -b 14:E6:E4:AC:FB:20 -vv
```

使用Wifite

```
wifite -dict common.txt
```

转6.4

#### 6.3Gerix Wifi Cracker破解

> 图形化界面，抛弃

#### 6.4使用Wifite破解无线网络

> 一键脚本，不推荐学习使用，仅做测试使用

```
/usr/lib/python3/dist-package/wifite  /脚本目录
/root/hs 	/扫描握手包保存目录
wifite
```

#### 6.5使用Easy-Creds工具攻击无线

> 中间人攻击，分析数据流

 [https://github.com/brav0hax/easy-creds](https://github.com/brav0hax/easy-creds) 

#### 6.6树莓派破解无线

#### 6.7攻击路由器

Rouerpwn

#### 6.8Arpspoof工具

> ARP欺骗工具通过替代传输中数据达成欺骗

##### 6.8.1URL流量操纵攻击

```
echo 1 >> /proc/sys/net/ipv4/ip_forward  /开启路由转发 ，0为关闭，目标无法联网
cat /proc/sys/net/ipv4/ip_forward  /查询路由转发
arpspoof -i wlan0 -t 192.168.6.101 192.168.6.1  /伪装成网关
arpspoof -i wlan0 -t 192.168.6.1 192.168.6.101  /伪装成目标系统
成功，通过Wireshark查看，蓝色是目标发出的，黑色是本机转发的，粉色是网关发给目标被我们截取的
```

##### 6.8.2 端口重定向攻击

> 重定向流量到不同端口

```
echo 1 >> /proc/sys/net/ipv4/ip_forward
arpspoof -i eth0 192.168.6.1 /伪装网关
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
当用户向网关192.168.6.1的80端口发送请求时，将会被转发为8080端口发送到攻击者主机上
```

##### 6.8.3 捕获并监视无线网络数据

> 中间人攻击

```
开启路由转发
arpspoof -i wlan0 -t 192.168.1.10 192.168.1.1  /攻击目标系统和网关
urlsnarf -i wlan0  /查看访问url
driftnet -i wlan	/查看访问图片
.3
```



### 7.逆向工程



### 8.漏洞利用工具集



### 9.嗅探/欺骗

> 网络欺骗、网络嗅探

### 10.权限维持

> 系统后门、Tunnel工具集、Web后门

### 11.数字取证

> 取证分割工具集、取证镜像工具集、数字取证、数字取证套件、PDF取证工具集

### 12.报告



### 13.社会工程学



### 14.系统服务

> BeEF、Dradis、GVM、OpenVas