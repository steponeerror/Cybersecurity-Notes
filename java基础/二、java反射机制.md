### 一、**java反射机制**

​	Java反射(`Reflection`)是Java非常重要的动态特性，通过使用反射我们不仅可以获取到任何类的成员方法(`Methods`)、成员变量(`Fields`)、构造方法(`Constructors`)等信息，还可以动态创建Java类实例、调用任意的类方法、修改任意的类成员变量值等。Java反射机制是Java语言的动态性的重要体现，也是Java的各种框架底层实现的灵魂。

### 二、**获取Class对象**

​	class对象详解：在类加载时，jvm从磁盘或网络读取字节码文件，并将其转化为class对象，他用于表示一个类的实体，包括这个类的字段、方法、构造函数等信息。

​	

​	而获取Class对象的则是反射调用类的第一步，java反射操作的是java.lang.Class对象，所以我们需要先想办法获取到class对象，下面是常见三种方式：

1. `类名.class`，如:`com.anbai.sec.classloader.TestHelloWorld.class`。
2. `Class.forName("com.anbai.sec.classloader.TestHelloWorld")`。 
3. `classLoader.loadClass("com.anbai.sec.classloader.TestHelloWorld");`

### **三、反射调用java.lang.Runtime**

1.不使用反射执行命令

​	

```java
System.out.println(IOUtils.toString(Runtime.getRuntime().exec("whoami").getInputStream(), "UTF-8"));
```

2.使用反射Runtime执行本地命令代码片段

```
// 获取Runtime类对象
Class runtimeClass1 = Class.forName("java.lang.Runtime");

// 获取构造方法
Constructor constructor = runtimeClass1.getDeclaredConstructor();
constructor.setAccessible(true);

// 创建Runtime类示例，等价于 Runtime rt = new Runtime();
Object runtimeInstance = constructor.newInstance();

// 获取Runtime的exec(String cmd)方法
Method runtimeMethod = runtimeClass1.getMethod("exec", String.class);

// 调用exec方法，等价于 rt.exec(cmd);
Process process = (Process) runtimeMethod.invoke(runtimeInstance, cmd);

// 获取命令执行结果
InputStream in = process.getInputStream();

// 输出命令执行结果
System.out.println(IOUtils.toString(in, "UTF-8"));
```

反射调用`Runtime`实现本地命令执行的流程如下：

​	1.反射获取Runtime类对象（Class.forName("java.lang.Runtime")）,这里上面提到三种加载方式。

​	2.使用Runtime类的Class对象获取Runtime类的无参构造方法（getDeclaredConstructor()）,因为Runtime的构造方法是private的我们无法直接调用，所以我们需要通过反射区修改方法的访问权限（constructor.setAccessible(true)）。

​	3.获取Runtime类的exec(String)方法（runtimeClass1.getMethod("exec",String.class)）

​	4.调用exec(String)方法（runtimeMethod.invoke(runtimeInstance,cmd)）

### **四、反射调用类方法**

 class对象对象提供了一个获取某个类的所有的成员变量方法的方法，也可以通过方法名和方法参数类型来获取指定成员方法

 获取当前类所以的成员方法：

```java
Mehtod[] methods = clazz.getDeclaredMethods()
```

 获取当前类指定的成员方法：

```java
Method method = clazz.getDeclaredMethod("方法名");
Method method = clazz.getDeclaredMethod("方法名", 参数类型如String.class，多个参数用","号隔开);
```

`getMethod`和`getDeclaredMethod`都能够获取到类成员方法，区别在于`getMethod`只能获取到`当前类和父类`的所有有权限的方法(如：`public`)，而`getDeclaredMethod`能获取到当前类的所有成员方法(不包含父类)。

反射调用方法

​	获取到`java.lang.reflect.Method`对象以后我们可以通过`Method`的`invoke`方法来调用类方法。

调用类方法代码片段：

```java
method.invoke(方法实例对象, 方法参数值，多个参数值用","隔开);
```

`method.invoke`的第一个参数必须是类实例对象，如果调用的是`static`方法那么第一个参数值可以传`null`，因为在java中调用静态方法是不需要有类实例的，因为可以直接`类名.方法名(参数)`的方式调用。

`method.invoke`的第二个参数不是必须的，如果当前调用的方法没有参数，那么第二个参数可以不传，如果有参数那么就必须严格的`依次传入对应的参数类型`。

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





