# Java FileSystem

在Java SE中内置了两类文件系统：`java.io`和`java.nio`，`java.nio`的实现是`sun.nio`，文件系统底层的API实现如下图：

![](https://oss.javasec.org/images/image-20201113121413510.png)

## Java IO 文件系统

Java抽象出了一个叫做文件系统的对象:`java.io.FileSystem`，不同的操作系统有不一样的文件系统,例如`Windows`和`Unix`就是两种不一样的文件系统： `java.io.UnixFileSystem`、`java.io.WinNTFileSystem`。

![image-20191203163038813](https://oss.javasec.org/images/image-20191203163038813.png)

`java.io.FileSystem`是一个抽象类，它抽象了对文件的操作，不同操作系统版本的JDK会实现其抽象的方法从而也就实现了跨平台的文件的访问操作。

![image-20191203164105238](https://oss.javasec.org/images/image-20191203164105238.png)

示例中的`java.io.UnixFileSystem`最终会通过JNI调用native方法来实现对文件的操作:

![image-20191203164635637](https://oss.javasec.org/images/image-20191203164635637.png)

由此我们可以得出Java只不过是实现了对文件操作的封装而已，最终读写文件的实现都是通过调用native方法实现的。

不过需要特别注意一下几点：

1. 并不是所有的文件操作都在`java.io.FileSystem`中定义,文件的读取最终调用的是`java.io.FileInputStream#read0、readBytes`、`java.io.RandomAccessFile#read0、readBytes`,而写文件调用的是`java.io.FileOutputStream#writeBytes`、`java.io.RandomAccessFile#write0`。
2. Java有两类文件系统API！一个是基于`阻塞模式的IO`的文件系统，另一是JDK7+基于`NIO.2`的文件系统。

## Java NIO.2 文件系统

Java 7提出了一个基于NIO的文件系统，这个NIO文件系统和阻塞IO文件系统两者是完全独立的。`java.nio.file.spi.FileSystemProvider`对文件的封装和`java.io.FileSystem`同理。

![image-20191203181206243](https://oss.javasec.org/images/image-20191203181206243.png)

NIO的文件操作在不同的系统的最终实现类也是不一样的，比如Mac的实现类是: `sun.nio.fs.UnixNativeDispatcher`,而Windows的实现类是`sun.nio.fs.WindowsNativeDispatcher`。

<font color="red">合理的利用NIO文件系统这一特性我们可以绕过某些只是防御了`java.io.FileSystem`的`WAF`/`RASP`。</font>



# Java IO/NIO多种读写文件方式

上一章节我们提到了Java 对文件的读写分为了基于阻塞模式的IO和非阻塞模式的NIO，本章节我将列举一些我们常用于读写文件的方式。

我们通常读写文件都是使用的阻塞模式，与之对应的也就是`java.io.FileSystem`。`java.io.FileInputStream`类提供了对文件的读取功能，Java的其他读取文件的方法基本上都是封装了`java.io.FileInputStream`类，比如：`java.io.FileReader`。

## FileInputStream

**使用FileInputStream实现文件读取Demo:**

```java
package com.anbai.sec.filesystem;

import java.io.*;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FileInputStreamDemo {

    public static void main(String[] args) throws IOException {
        File file = new File("/etc/passwd");

        // 打开文件对象并创建文件输入流
        FileInputStream fis = new FileInputStream(file);

        // 定义每次输入流读取到的字节数对象
        int a = 0;

        // 定义缓冲区大小
        byte[] bytes = new byte[1024];

        // 创建二进制输出流对象
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 循环读取文件内容
        while ((a = fis.read(bytes)) != -1) {
            // 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
            // 下标0开始截取，a表示输入流read到的字节数。
            out.write(bytes, 0, a);
        }

        System.out.println(out.toString());
    }

}
在上述代码中，a 在循环中的初始值为 0，这是因为在第一次循环中，如果文件的长度为 0，则 read() 方法将返回 0，而不是 -1。因此，为了正确处理这种情况，a 的初始值应该为 0。

在循环中，每次调用 read() 方法将读取缓冲区中的字节，并返回读取的字节数。如果读到文件末尾，则返回 -1。因此，循环条件中的 (a = fis.read(bytes)) != -1 表示只要读取到的字节数不为 -1，就继续循环读取文件内容。

需要注意的是，如果文件长度为 0，则 read() 方法将返回 0，但是此时并不表示已经读取到了文件末尾。因此，在循环中需要使用 a 的值来判断是否已经读取到了文件末尾。如果 a 的值为 0，则说明已经读取到了文件末尾，可以退出循环。
```

## FileOutputStream

使用FileOutputStream实现写文件Demo:

```java
package com.anbai.sec.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class FileOutputStreamDemo {

    public static void main(String[] args) throws IOException {
        // 定义写入文件路径
        File file = new File("/tmp/1.txt");

        // 定义待写入文件内容
        String content = "Hello World.";

        // 创建FileOutputStream对象
        FileOutputStream fos = new FileOutputStream(file);

        // 写入内容二进制到文件
        fos.write(content.getBytes());
        fos.flush();
        fos.close();
    }

}

```

代码逻辑比较简单: 打开文件->写内容->关闭文件，调用链和底层实现分析请参考`FileInputStream`。

## RandomAccessFile

Java提供了一个非常有趣的读取文件内容的类: `java.io.RandomAccessFile`,这个类名字面意思是任意文件内容访问，特别之处是这个类不仅可以像`java.io.FileInputStream`一样读取文件，而且还可以写文件。

RandomAccessFile读取文件测试代码:

```java
package com.anbai.sec.filesystem;

import java.io.*;

/**
 * Creator: yz
 * Date: 2019/12/4
 */
public class RandomAccessFileDemo {

    public static void main(String[] args) {
        File file = new File("/etc/passwd");

        try {
            // 创建RandomAccessFile对象,r表示以只读模式打开文件，一共有:r(只读)、rw(读写)、
            // rws(读写内容同步)、rwd(读写内容或元数据同步)四种模式。
            RandomAccessFile raf = new RandomAccessFile(file, "r");

            // 定义每次输入流读取到的字节数对象
            int a = 0;

            // 定义缓冲区大小
            byte[] bytes = new byte[1024];

            // 创建二进制输出流对象
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            // 循环读取文件内容
            while ((a = raf.read(bytes)) != -1) {
                // 截取缓冲区数组中的内容，(bytes, 0, a)其中的0表示从bytes数组的
                // 下标0开始截取，a表示输入流read到的字节数。
                out.write(bytes, 0, a);
            }

            System.out.println(out.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
```

## FileSystemProvider

前面章节提到了JDK7新增的NIO.2的`java.nio.file.spi.FileSystemProvider`,利用`FileSystemProvider`我们可以利用支持异步的通道(`Channel`)模式读取文件内容。

**FileSystemProvider读取文件内容示例:**

```

```

