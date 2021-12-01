# Vulhub漏洞笔记

[vulhub]: vulhub.org

```
kali:
docker-compose build 
docker-compose up -d
实验室环境因为外网原因，需要在命令前面加代理proxychains
环境建设成功后打开ip即可
```



## 中间件解析漏洞

### Apache HTTPD 换行解析漏洞（CVE-2017-15715）

https://vulhub.org/#/environments/httpd/CVE-2017-15715/

环境：Ip:8080,apache httpd 2.4.0~2.4.29

1. 上传1.php
2. 抓包，在1.php后面加空格
3. 然后hex选中空格后编码改成0A，发包
4. 访问ip:8080/1.php%0A



### Tomcat Arbitrary Write-file Vulnerability through PUT Method (CVE-2017-12615)

https://vulhub.org/#/environments/tomcat/CVE-2017-12615/

环境：ip:8080 , Tomcat version: 8.5.19

1. 打开环境，抓包

2. 修改包为

   ```html
   PUT /1.jsp/ HTTP/1.1
   Host: your-ip:8080 
   Accept: */* Accept-Language: en User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0) 
   Connection: close 
   Content-Type: 
   application/x-www-form-urlencoded Content-Length: 5 
   shell(jsp后台命令)
   ```

3. 访问ip:8080/1.jsp?cmd=    自己想要的指令



### Weblogic 任意文件上传漏洞（CVE-2018-2894）

https://vulhub.org/#/environments/weblogic/CVE-2018-2894/

环境：ip:7001/console , oracle weblogic 12.2.1.3

1. 进入后台，kali “docker-compose logs | grep password” 查询账户密码
2. 在base_domain的高级中开启WEB服务测试页
3. 访问http://your-ip:7001/ws_utc/config.do，Work Home Dir设置为 /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css  (将home dir设置成静态css目录，访问无需权限)
4. 点击安全-->增加，上传webshell
5. 抓包查看时间戳
6. 访问  http://your-ip:7001/ws_utc/css/config/keystore/[时间戳]_[文件名]



### Nginx  1文件名逻辑漏洞（CVE-2013-4547）

https://vulhub.org/#/environments/nginx/CVE-2013-4547/

环境：ip:8080 Nginx 0.8.41 ~ 1.4.3 / 1.5.0 ~ 1.5.7

1. 页面黑名单验证，无法上传php
2. 更改php为jpg，抓包
3. 修改filename="1.jpg"处后面加**空格**，绕过验证
4. 访问http://your-ip:8080/uploadfiles/1.gif[0x20][0x00].php ,解析为php  [0x20]为空格，[0x00]为\0，或直接改hex，在1.gif后面改成20 00

### Nginx 空字节任意代码执行漏洞

环境：nginx 0.5.* nginx 0.6.* nginx 0.7 <= 0.7.65 nginx 0.8 <= 0.8.37

1. 在html下放置图片马1.jpg
2. URL输入图片马地址，抓包1.jpg..
3. 将GET改成1/jpg..php，在hex处将一个点改成00
4. forword绕过



### Nginx 文件解析漏洞复现

https://vulhub.org/#/environments/nginx/insecure-configuration/

环境:

- Nginx 1.x 最新版
- PHP 7.x最新版
- ip

1. 合成图片马 cmd : copy 1.png /b + 2.php /a 3.png (需要cmd，powershell无法定位目录)
2. 上传后，复制图片目录，http://192.168.124.27/uploadfiles/10fb15c77258a991b0028080a64fb42d.png/123.php   任意文件加/xxx.php即可解析
3. http://your-ip/uploadfiles/nginx.png   http://your-ip/uploadfiles/nginx.png/.php
4. 判断一个网站有无该漏洞可以直接复制图片然后加/.php后缀测试，乱码则有





## 编辑器漏洞

ckeditor,fckeditor,kindeditor,xxxxeditor

