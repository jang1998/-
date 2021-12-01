# JAVA基础知识

![](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210818182205571.png)



java se 面向桌面级

java ee针对web应用程序

java me面向移动端

基本概念：类、对象

特点一：封装，继承，多态

二：健壮性：垃圾回收

三：跨平台JVM

JDK java开发工具包，提供开发人员使用 jdk=jre+开发工具

jre java运行环境  jre=jvm+java se

运行  注释  声明

```
javac hello.java //编译
java hello  //运行
//单行注释

/*
多行注释
*/

<!--
多行注释
-->

/**
文档注释，可以被javadoc解析
*/
 在一个java源文件可以声明多个class，但只有一个类声明public，并且public类必须与源文件名相同
 编译后会生成一个或多个字节码文件，文件名和类名相同
 
```

![image-20210819095212131](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210819095212131.png)

![image-20210819100820220](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210819100820220.png)

![image-20210822151704745](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822151704745.png)

![image-20210822152136245](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822152136245.png)

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822152423990.png" alt="image-20210822152423990" style="zoom:67%;" />

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822153034877.png" alt="image-20210822153034877" style="zoom: 80%;" />

与“”string连接的出来全是字符串，不会做自动类型提升；用''声明的是ascii，做运算出来的是数字

![image-20210822153657566](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822153657566.png)

![image-20210822154303871](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822154303871.png)

二进制原码最前面为符号位，0正1负，反码为取反，补码为反码+1；**计算机底层都以补码方式存储数据**

![image-20210822223401829](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822223401829.png)



-- ++ += -= /=  *=  %=都不会改变变量本身数据类型，所以建议使用![image-20210822230721044](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822230721044.png)![image-20210822231255171](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822231255171.png)

==是判断符，而=是赋值

![image-20210822231909594](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822231909594.png)

![image-20210822231916929](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210822231916929.png)

短路与  短路或

![ ](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210823215509674.png)

if else 如果没有带括号就就近原则

Math.random()

![image-20210829211404289](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210829211404289.png)

 没有break会导致语句执行了继续执行下面的语句；如果多个case语句相同，可以合并，直接删除上面的

![image-20210829212621472](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210829212621472.png)

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210829214745375.png" alt="image-20210829214745375" style="zoom:80%;" />

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210829225658842.png" alt="image-20210829225658842" style="zoom:80%;" />

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210829225929353.png" alt="image-20210829225929353" style="zoom: 80%;" />

可以使用true for(;;) 和break配合跳出无限循环

![image-20210829230947146](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210829230947146.png)

System.currentTimeMillis()  获取距离1970毫秒数，新建两个对象相减得到程序运行时间

![image-20210830233843619](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210830233843619.png)

break默认跳出最近的一层，加上label可以结束指定标识

![image-20210908082754147](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908082754147.png)

int[] a = new int[5];//动态初始化  int[] b = new int[]{1,2,3}//静态初始化  a.length //获取长度

![image-20210908082732165](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908082732165.png)

![image-20210908085050762](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908085050762.png)

```java
int[][] arr1 = new int[][]{{1,2,3},{4,5}}; //静态
int[][] arr1 = new int[3][2]; //静态，3个元素构成数组，然后数组里面有2个元素
int[] arr1[] = new int[][]{{1,2,3},{4,5}};
int[][] arr1 = {{1,2,3},{4,5}}//类型推断
arr1[0][0] = 1;//调用
arr1[0] = {1,2,3};//调用
arr1.length;arr1[1].length;
输出(arr1[0])//当初始化未指定时，为一维数组地址值
输出(arr1[0][0])//同一维数组的默认值
```

![image-20210908090800474](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908090800474.png)

常见算法

1. 数组元素的**赋值**
2. 求数值型数组中元素最大、最小值、平均数、总和
3. 数组的复制、反转、**查找**
4. 数组元素**排序**



arr1=arr2 //只是地址值的复制，相当创建快捷方式，不能称为复制

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908105956329.png" alt="image-20210908105956329" style="zoom:80%;" />

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908195115903.png" alt="image-20210908195115903" style="zoom: 80%;" />

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908195448787.png" alt="image-20210908195448787" style="zoom: 80%;" />

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908203401400.png" alt="image-20210908203401400" style="zoom: 67%;" />

算法：输入、输出、有穷性、确定性、可行性

![image-20210908203737440](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908203737440.png)

冒泡：每次相邻对比，每轮选出一个极值

快排：以一个为中心，两数对比，每轮有一个中值

![image-20210908204923271](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908204923271.png)

import java.util.Arrays  //操作数组的工具类，定义了很多操作数组的方法

![image-20210908205426583](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908205426583.png)

空指针即无指向地址

## 面向对象

![image-20210908212109855](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908212109855.png)

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908212404703.png" alt="image-20210908212404703" style="zoom: 80%;" />

![image-20210908212536535](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908212536535.png)

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908213117358.png" alt="image-20210908213117358" style="zoom:80%;" />![image-20210908213238117](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210908213238117.png)

```java
class Person{
	string name;//属性
	public void eat(){ //方法
		sout();
	}
}
main{ 
	Person p1 = new Person(); //创建对象=类的实例化
	p1.name="asd";
	p1.eat();
}
```

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210911111829221.png" alt="image-20210911111829221" style="zoom:80%;" />

虚拟机栈存储局部变量；方法区存类信息、常量、静态变量、即时编译代码；堆存对象实例

<img src="C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210911112647868.png" alt="image-20210911112647868" style="zoom:80%;" />

局部变量没有默认赋值，需要显式赋值

方法的声明：权限修饰符 返回值 类型 方法名（形参列表）{

​	方法体

}

![image-20210912202149695](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210912202149695.png)

![image-20210912202816252](C:\Users\Jang\AppData\Roaming\Typora\typora-user-images\image-20210912202816252.png)



