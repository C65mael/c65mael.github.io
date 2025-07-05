---
title: CrackEXT
cascade:
  type: docs
---

###### IDA修改错误

- 修改返回值是哪个寄存器：`int __usercall sub_401020<edx>()`

###### 壳

- 分类：
  1. 基于`PE`文件的保护：代码会在程序运行后原封不动的吐回去
  2. 基于代码的保护：吐回去的代码还是看不懂的代码

###### 反调试

分析一下，核心代码如下，需要获取`_TEB`所以要导入下面的头文件：

```c++
#include <winternl.h>

BOOL check()
{
	wchar_t *Buffer;
	int i;
	bool tmp;

	Buffer = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->CommandLine.Buffer;
	i = 256;
	do
	{
		if (!i)
			break;
		tmp = *Buffer++ == 0;
		--i;
	} while (!tmp);
	return *(Buffer - 2) != ' ';
}
```

通过`_TEB`里面的`_PEB`获取进程启动时的命令行缓冲区，应该是它的启动参数。之后检查倒数第二个字符，因为未调试时，某些加载器或启动配置可能会在命令行尾部保留一个空格；但是双击启动的程序后面不会有参数。

###### 伪调试

- 大致原理：

  不使用正常的`0xCC`或者硬件断点，自己定义一个断点方式（页异常，`hook`等），然后接管程序的所有的断点以及调试`API`调用等，转过来自己实现。

###### RSA

- 加密：`明文 ^ e mod n = 密文`

  解密：`密文 ^ d mod n = 明文`

  `n`的来源：任意两个互质数的乘积。比如`n = p * q`

  `e`的来源：随机取值，只需要满足`1<e<f(p,q)`

  `d`的来源：`e * d mod f(p,q) = 1`，可以推出`d`，欧几里得定理
