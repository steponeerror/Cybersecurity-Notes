### 一、**前言**

还是对javasec.org项目的学习，项目涉及博大精深。此笔记开头是解释java类序列化的问题，后面是广为人知的cc1链

### 二、**java序列化和反序列化**

​	在Java中实现对象反序列化非常简单，实现`java.io.Serializable(内部序列化)`或`java.io.Externalizable(外部序列化)`接口即可被序列化，其中`java.io.Externalizable`接口只是实现了`java.io.Serializable`接口。

反序列化类对象时有如下限制：

1. 被反序列化的类必须存在。（不必多说要有反序列化的东西）

2. `serialVersionUID`值必须一致（serialVersionUID是Java中用于控制序列化版本的一个唯一标识符，它的作用是在反序列化时校验序列化对象的版本是否与当前类的版本一致。如果serialVersionUID值不一致，就会导致反序列化失败，抛出InvalidClassException异常。）

3. 反序列化类必须实现Serializable接口

   下面几条可以了解，不如上面三条关键

   1.反序列化的类的成员变量必须是可序列化的，否则会抛出NotSerializableException异常。如果成员变量是一个自定义类的对象，则该自定义类也必须实现Serializable接口。

   2.如果反序列化的类的成员变量是static或transient类型的，则这些成员变量不会被反序列化。

   3.如果反序列化的类的成员变量是一个数组，则数组元素的类型也必须是可序列化的。

   4.如果反序列化的类的成员变量是一个集合或映射类型的对象，则集合或映射中的元素也必须是可序列化的。

   5.如果反序列化的类的成员变量是一个枚举类型，则该枚举类型必须实现Serializable接口。

   6.如果反序列化的类的成员变量是一个外部类的内部类，则该内部类必须是静态的，即必须使用static关键字修饰

除此之外，**反序列化类对象是不会调用该类构造方法**的，因为在反序列化创建类实例时使用了`sun.reflect.ReflectionFactory.newConstructorForSerialization`创建了一个反序列化专用的`Constructor(反射构造方法对象)`，<font color=red>使用这个特殊的`Constructor`可以绕过构造方法创建类实例(前面章节讲`sun.misc.Unsafe` 的时候我们提到了使用`allocateInstance`方法也可以实现绕过构造方法创建类实例)</font>。也就是说这也是可以绕过waf检测的一种方式。有趣的是此类不许要被创建的类满足反序列化的条件。

**使用反序列化方式创建类实例代码片段：**

```java
package com.anbai.sec.serializes;

import sun.reflect.ReflectionFactory;

import java.lang.reflect.Constructor;

/**
 * 使用反序列化方式在不调用类构造方法的情况下创建类实例
 * Creator: yz
 * Date: 2019/12/20
 */
public class ReflectionFactoryTest {

    public static void main(String[] args) {
        try {
            // 获取sun.reflect.ReflectionFactory对象
            ReflectionFactory factory = ReflectionFactory.getReflectionFactory();

            // 使用反序列化方式获取DeserializationTest类的构造方法
            Constructor constructor = factory.newConstructorForSerialization(
                    DeserializationTest.class, Object.class.getConstructor()
            );

            // 实例化DeserializationTest对象
            System.out.println(constructor.newInstance());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

```



### **三、ObjectInputStream、ObjectOutputStream**

`java.io.ObjectOutputStream`类最核心的方法是`writeObject`方法，即序列化类对象。 <font color="red">（同时可以直接在idea中显示哪些对象使用了类来进行漏洞的判断）</font>

`java.io.ObjectInputStream`类最核心的功能是`readObject`方法，即反序列化类对象。 <font color="red">（同时可以直接在idea中显示哪些对象使用了类来进行漏洞的判断）</font>

所以，只需借助`ObjectInputStream`和`ObjectOutputStream`类我们就可以实现类的序列化和反序列化功能了。

#### java.io.Serializable

`java.io.Serializable`是一个空的接口,我们不需要实现`java.io.Serializable`的任何方法，代码如下:

```java
public interface Serializable {
}
```

您可能会好奇我们实现一个空接口有什么意义？其实实现`java.io.Serializable`接口仅仅只用于`标识这个类可序列化`。实现了`java.io.Serializable`接口的类原则上都需要生产一个`serialVersionUID`常量，反序列化时如果双方的`serialVersionUID`不一致会导致`InvalidClassException` 异常。如果可序列化类未显式声明 `serialVersionUID`，则序列化运行时将基于该类的各个方面计算该类的默认 `serialVersionUID`值。（<font color="red">简单来说我们实现了Serializable接口，java在类序列化时，会使用java虚拟机根据每个类的结构生成一个id值来确定这个类的唯一性。在序列化时确定此类并未发生结构性改变</font>）

```java
package com.anbai.sec.serializes;

import java.io.*;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2019/12/15
 */
public class DeserializationTest implements Serializable {

    private String username;

    private String email;

    // 省去get/set方法....

    public static void main(String[] args) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            // 创建DeserializationTest类，并类设置属性值
            DeserializationTest t = new DeserializationTest();
            t.setUsername("yz");
            t.setEmail("admin@javaweb.org");

            // 创建Java对象序列化输出流对象
            ObjectOutputStream out = new ObjectOutputStream(baos);

            // 序列化DeserializationTest类
            out.writeObject(t);
            out.flush();
            out.close();

            // 打印DeserializationTest类序列化以后的字节数组，我们可以将其存储到文件中或者通过Socket发送到远程服务地址
            System.out.println("DeserializationTest类序列化后的字节数组:" + Arrays.toString(baos.toByteArray()));

            // 利用DeserializationTest类生成的二进制数组创建二进制输入流对象用于反序列化操作
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

            // 通过反序列化输入流(bais),创建Java对象输入流(ObjectInputStream)对象
            ObjectInputStream in = new ObjectInputStream(bais);

            // 反序列化输入流数据为DeserializationTest对象
            DeserializationTest test = (DeserializationTest) in.readObject();
            System.out.println("用户名:" + test.getUsername() + ",邮箱:" + test.getEmail());

            // 关闭ObjectInputStream输入流
            in.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

}
```

输出结果如下：

```
DeserializationTest类序列化后的字节数组:[-84, -19, 0, 5, 115, 114, 0, 44, 99, 111, 109, 46, 97, 110, 98, 97, 105, 46, 115, 101, 99, 46, 115, 101, 114, 105, 97, 108, 105, 122, 101, 115, 46, 68, 101, 115, 101, 114, 105, 97, 108, 105, 122, 97, 116, 105, 111, 110, 84, 101, 115, 116, 74, 36, 49, 16, -110, 39, 13, 76, 2, 0, 2, 76, 0, 5, 101, 109, 97, 105, 108, 116, 0, 18, 76, 106, 97, 118, 97, 47, 108, 97, 110, 103, 47, 83, 116, 114, 105, 110, 103, 59, 76, 0, 8, 117, 115, 101, 114, 110, 97, 109, 101, 113, 0, 126, 0, 1, 120, 112, 116, 0, 17, 97, 100, 109, 105, 110, 64, 106, 97, 118, 97, 119, 101, 98, 46, 111, 114, 103, 116, 0, 2, 121, 122]
用户名:yz,邮箱:admin@javaweb.org
```

核心逻辑其实就是使用`ObjectOutputStream`类的`writeObject`方法序列化`DeserializationTest`类，使用`ObjectInputStream`类的`readObject`方法反序列化`DeserializationTest`类而已。

简化后的代码片段如下：

```java
// 序列化DeserializationTest类
ObjectOutputStream out = new ObjectOutputStream(baos);
out.writeObject(t);

// 反序列化输入流数据为DeserializationTest对象
ObjectInputStream in = new ObjectInputStream(bais);
DeserializationTest test = (DeserializationTest) in.readObject();
```

`ObjectOutputStream`序列化类对象的主要流程是首先判断序列化的类是否重写了`writeObject`方法，如果重写了就调用序列化对象自身的`writeObject`方法序列化，序列化时会先写入类名信息，其次是写入成员变量信息(通过反射获取所有不包含被`transient`修饰的变量和值)

### **四、java.io.Externalizable**

`java.io.Externalizable`和`java.io.Serializable`几乎一样，只是`java.io.Externalizable`接口定义了`writeExternal`和`readExternal`方法需要序列化和反序列化的类实现，其余的和`java.io.Serializable`并无差别。

**java.io.Externalizable.java:**

```java
public interface Externalizable extends java.io.Serializable {

  void writeExternal(ObjectOutput out) throws IOException;

  void readExternal(ObjectInput in) throws IOException, ClassNotFoundException;

}
```

 很显然，这个是继承了Serializable类，但是下面具体的接口中的方法实现。

```java
package com.anbai.sec.serializes;

import java.io.*;
import java.util.Arrays;

/**
 * Creator: yz
 * Date: 2019/12/15
 */
public class ExternalizableTest implements java.io.Externalizable {

    private String username;

    private String email;

    // 省去get/set方法....

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(username);
        out.writeObject(email);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        this.username = (String) in.readObject();
        this.email = (String) in.readObject();
    }

    public static void main(String[] args) {
        // 省去测试代码，因为和DeserializationTest一样...
    }

}
```

其使用方式于serializable一样，再次不过多赘述。

### **五、自定义序列化(writeObject)和反序列化(readObject)** 

 实现了`java.io.Serializable`接口的类，还可以定义如下方法(`反序列化魔术方法`)，这些方法将会在类序列化或反序列化过程中调用：

1. **`private void writeObject(ObjectOutputStream oos)`,自定义序列化。**
2. **`private void readObject(ObjectInputStream ois)`，自定义反序列化。**
3. `private void readObjectNoData()`。
4. `protected Object writeReplace()`，写入时替换对象。
5. `protected Object readResolve()`。

具体的方法名定义在`java.io.ObjectStreamClass#ObjectStreamClass(java.lang.Class<?>)`，其中方法有详细的声明。

**序列化时可自定义的方法示例代码：**

```java
public class DeserializationTest implements Serializable {

/**
     * 自定义反序列化类对象
     *
     * @param ois 反序列化输入流对象
     * @throws IOException            IO异常
     * @throws ClassNotFoundException 类未找到异常
     */
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        System.out.println("readObject...");

        // 调用ObjectInputStream默认反序列化方法
        ois.defaultReadObject();

        // 省去调用自定义反序列化逻辑...
    }

    /**
     * 自定义序列化类对象
     *
     * @param oos 序列化输出流对象
     * @throws IOException IO异常
     */
    private void writeObject(ObjectOutputStream oos) throws IOException {
        oos.defaultWriteObject();

        System.out.println("writeObject...");
        // 省去调用自定义序列化逻辑...
    }

    private void readObjectNoData() {
        System.out.println("readObjectNoData...");
    }

    /**
     * 写入时替换对象
     *
     * @return 替换后的对象
     */
    protected Object writeReplace() {
        System.out.println("writeReplace....");

        return null;
    }

    protected Object readResolve() {
        System.out.println("readResolve....");

        return null;
    }

}
```



