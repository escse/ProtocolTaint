# ProtocolTaint

### 目标
ProtocolTaint通过代码动态分析的方法对二进制协议可执行文件进行分析，通过污点分析记录二进制代码处理各个协议数据报文字段的方式，得到二进制协议的格式

### 基础
基于Intel跨平台的动态二进制分析框架[Pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)，编写C/C++代码进行动态污点分析

### 结果
以二进制协议modbus作为简单测试例子，结果如下图
![结果](https://github.com/escse/ProtocolTaint/blob/master/graph.png)

可以从中总结出字段[00 01]{02 03 04 05}[06][07][08 09][10 11]


### 参考教程
污点分析 http://shell-storm.org/blog/Taint-analysis-and-pattern-matching-with-Pin/

LD_PRELOAD http://samanbarghi.com/blog/2014/09/05/how-to-wrap-a-system-call-libc-function-in-linux/

    https://www.technovelty.org/c/using-ld_preload-to-override-a-function.html