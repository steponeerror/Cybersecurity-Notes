### 一、**sun.misc.Unsafe**

​		`sun.misc.Unsafe`是Java底层API(`仅限Java内部使用,反射可调用`)提供的一个神奇的Java类，`Unsafe`提供了非常底层的`内存、CAS、线程调度、类、对象`等操作、`Unsafe`正如它的名字一样它提供的几乎所有的方法都是不安全的，本节只讲解如何使用`Unsafe`定义Java类、创建类实例。(<font color="red">个人理解，Unsafe方法提供了除new 和反射，调用一个类的第三种方法</font>)

### 二、**如何获取Unsafe对象**

​	`Unsafe`是Java内部API，外部是禁止调用的，在编译Java类时如果检测到引用了`Unsafe`类也会有禁止使用的警告：`Unsafe是内部专用 API, 可能会在未来发行版中删除`。

​	

```java
import sun.reflect.CallerSensitive;
import sun.reflect.Reflection;

public final class Unsafe {
	//final属性让Unsafe类不能被继承
    private static final Unsafe theUnsafe;
	
    static {
        theUnsafe = new Unsafe();
        省去其他代码......
    }
	
    private Unsafe() {
    }
   	//private构造方法让其不能被实例化

    @CallerSensitive
    public static Unsafe getUnsafe() {
        Class var0 = Reflection.getCallerClass();
        if (var0.getClassLoader() != null) {
            throw new SecurityException("Unsafe");
        } else {
            return theUnsafe;
        }
    }

    省去其他代码......
}
```

​	由上代码片段可以看到，`Unsafe`类是一个不能被继承的类且不能直接通过`new`的方式创建`Unsafe`类实例，如果通过`getUnsafe`方法获取`Unsafe`实例还会检查类加载器，默认只允许`Bootstrap Classloader`（<font color="red">其中bootstrap classloader 引导类加载器使用C/C++语言实现，在jvm内部，用于加载java核心类库，不能继承ClassLoader。只加载名为java,javax,sun开头的类</font>）调用。

​	既然无法直接通过Unsafe.getUnsafe()的方式调用，那么可以使用反射的方式去获取Unsafe类实例。

​	

```java
// 反射获取Unsafe的theUnsafe成员变量
Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");

// 反射设置theUnsafe访问权限
theUnsafeField.setAccessible(true);

// 反射获取theUnsafe成员变量值
Unsafe unsafe = (Unsafe) theUnsafeField.get(null);
```



当然我们也可以用反射创建Unsafe类实例的方式去获取Unsafe对象：

```java
// 获取Unsafe无参构造方法
Constructor constructor = Unsafe.class.getDeclaredConstructor();

// 修改构造方法访问权限
constructor.setAccessible(true);

// 反射创建Unsafe类实例，等价于 Unsafe unsafe1 = new Unsafe();
Unsafe unsafe1 = (Unsafe) constructor.newInstance();
```

 此时通过Unsafe对象我们就可以调用内部的方法

### **三、allocateInstance无视构造方法创建类实例**

假设我们有一个叫`com.anbai.sec.unsafe.UnSafeTest`的类，因为某种原因我们不能直接通过反射的方式去创建`UnSafeTest`类实例，那么这个时候使用`Unsafe`的`allocateInstance`方法就可以绕过这个限制了。

**UnSafeTest代码片段：**

```java
public class UnSafeTest {

   private UnSafeTest() {
      // 假设RASP在这个构造方法中插入了Hook代码，我们可以利用Unsafe来创建类实例
      System.out.println("init...");
   }

}
```

**使用Unsafe创建UnSafeTest对象：**

```java
// 使用Unsafe创建UnSafeTest类实例
UnSafeTest test = (UnSafeTest) unsafe1.allocateInstance(UnSafeTest.class);
```

Google的`GSON`库在JSON反序列化的时候就使用这个方式来创建类实例，在渗透测试中也会经常遇到这样的限制，比如RASP限制了`java.io.FileInputStream`类的构造方法导致我们无法读文件或者限制了`UNIXProcess/ProcessImpl`类的构造方法导致我们无法执行本地命令等。

### **四、defineClass直接调用JVM创建类对象**

 	`ClassLoader`章节我们讲了通过`ClassLoader`类的`defineClass0/1/2`方法我们可以直接向JVM中注册一个类，如果`ClassLoader`被限制的情况下我们还可以使用`Unsafe`的`defineClass`方法来实现同样的功能。

​	<font color=red>Unsafe 提供了一个通过传入类名、类字节码的方式就可以定义类的defineClass方法：</font></font>上面这句话就是Unsafe的关键，给了我们另一种方式去实例化类。

```java
public native Class defineClass(String var1, byte[] var2, int var3, int var4);

public native Class<?> defineClass(String var1, byte[] var2, int var3, int var4, ClassLoader var5, ProtectionDomain var6);
```

使用Unsafe创建TestHelloWord对象 :

```java
// 使用Unsafe向JVM中注册com.anbai.sec.classloader.TestHelloWorld类
Class helloWorldClass = unsafe1.defineClass(TEST_CLASS_NAME, TEST_CLASS_BYTES, 0, TEST_CLASS_BYTES.length);
```



### **五、反射调用成员变量** 

​	java反射不但可以获取类所有的成员变量名称，还可以无视权限修饰符实现修改对应的值



获取当前类的所有成员变量:



```java
Field fields = clazz.getDeclaredFields();
```

###### 

获取当前类指定的成员变量：



```java
Field field  = clazz.getDeclaredField("变量名");
```

`getField`和`getDeclaredField`的区别同`getMethod`和`getDeclaredMethod`。



**获取成员变量值：**

```java
Object obj = field.get(类实例对象);
```

**修改成员变量值：**

```java
field.set(类实例对象, 修改后的值);
```



下面是gpt生成的例子（偷懒了）



```java
package com.anbai.sec.reflection;

import java.lang.reflect.Field;

public class testClass {
    private int myField;
    public testClass(int myField) {
        this.myField = myField;

    }

    public static void main(String[] args) throws Exception {
        testClass obj = new testClass(42);

        // 获取类的Class对象
        Class<?> clazz = obj.getClass();

        // 获取指定名称的成员变量
        Field field = clazz.getDeclaredField("myField");

        // 设置成员变量的可访问性
        field.setAccessible(true);

        // 获取成员变量的值
        int fieldValue = (int) field.get(obj);

        System.out.println("原始值：" + fieldValue);

        // 修改成员变量的值
        field.set(obj, 100);

        // 再次获取成员变量的值
        fieldValue = (int) field.get(obj);

        System.out.println("修改后的值：" + fieldValue);
    }
}

```





​     
