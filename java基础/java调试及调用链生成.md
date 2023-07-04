要生成特定程序的调用链，可以在程序中捕获异常并打印堆栈跟踪信息，或者在程序中显式地调用Thread.currentThread().getStackTrace()方法并打印堆栈跟踪信息。例如，假设我们有一个名为MyProgram的Java程序，想要生成它的调用链，可以在程序中添加以下代码：

```
try {
    // MyProgram的代码
} catch (Exception e) {
    e.printStackTrace();
}
```

或者：

```
StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
for (StackTraceElement stackTraceElement : stackTraceElements) {
    System.out.println(stackTraceElement);
}
```

这些代码会在程序执行时输出堆栈跟踪信息，从而生成调用链。注意，堆栈跟踪信息只包含程序执行的方法调用信息，不包括其他类型的操作，比如I/O操作等。如果要生成完整的调用链，需要结合程序的源代码和其他相关信息进行分析。