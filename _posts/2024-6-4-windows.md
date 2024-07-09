---
title: Windows
author: C65mael
date: 2024-06-04
category: Jekyll
layout: post
---

<p align="center">Liberty🗽, Equality⚖️, Fraternity💕</p>



### 那些拐弯抹角的小知识

###### switch语句

`switch`​语句在`case`​为小于3个时，与三个if else判断逻辑相同，当大于三个case时会生成一张"大表"，"大表"会通过偏移(减去最小的case做基础)生成地址表，再通过最小单元乘偏移找到要跳转表的地址进行跳转。不连续时也会生成"大表"，通过将不存在的case的对应地址写为跳出地址。比全部使用if else来判断更快~

###### for循环

`for(A;B;C){D}`​的执行顺序为ABDC BDC ... 汇编语言的书写顺序是ABDC  jmp A

###### 多维数组

底层逻辑就是连续存储，与相同数量的一维数组等效。区别仅仅是开发人员好找数组中的值，编译器找值是套公式的，假如在数组arr[5][4][3]中找`arr[1][2][1]`​，则是arr[1×4×3+2×3+1]

###### 指针

1、不带类型的变量， ++或者--都是加1 或者减1

2、带类型的变量， ++或者--新增(减少)的数量是去掉一个*后变量的宽度

3、指针类型的变量可以加、减一个整数，但不能乘或者除.

4、指针类型变量与其他整数相加或者相减时:指针类型变量+N =指针类型变量+N(去掉一个后类型的宽度)指针类型变量-N= 指针类型变量-N(去掉一个后类型的宽度)

###### &和*

&取地址符(但不一定是地址哦)，将原来的变量类型后加*，比如int变int *

*取值符，加上一个指针类型就是指针类型减去一个 * (与&是互逆操作)

###### 字符串操作

1.`int strlen (char* s)`​返回值是字符串s的长度。不包括结束符%0。

2.`char* stropy (char* dest, char* src);`​复制字符串src到dest中。返回指针为dest的值。

3.`char* strcat (char* dest, char* src);`​将字符串src添加到dest尾部。返回指针为dest的值。

4.`int strcmp (char* s1, char* s2);`​一样返回0 不一样返回非0

###### 指针取值操作

`*(p+i) =p[i]`​

`*( *(p+i)+k) = p[i][k]`​

`*( *( *(p+i)+k)+m) = p[i][k][m]`​

`*( *( *( *( *(p+i)+k)+m)+w)+t) = p[i][k][m][w][t]`​

*()与[]可以相互转换

### C++

```c++
类:
struct Student
{
	int a; 
	int b; 
	int c; 
	int d;

	int Plus()						<--------(封装)成员函数
	{
		return a+b+c+d;
	}
};
```

###### 概述

1、什么是封装：将函数定义到结构体内部,就是封装。

2、什么是类：带有函数的结构体，称为类。

3、什么是成员函数：结构体里面的函数，称为成员函数。

如果要调用成员函数时的规则：类.函数名(s.Plus())

###### this指针(结构体首地址)

```c++
struct Student
{
	int a; 
	int b; 
	int c; 
	int d;

	int Plus()						<--------
	{
		return a+b+c+d;
	}
};

s.Plus()							<--------Plus()函数中通过ecx传入结构体首地址(this指针)
```

```c++
struct Student
{
	int a; 
	int b; 
	int c; 
	int d;

	void init(int a,int b,int c,int d)							<--------可以通过成员函数对成员进行赋值
	{
		this->a = a;
		this->b = b;
		this->c = c;
		this->d = d;
	}
};

```

1、this指针是编译器默认传入的，通常都会使用ecx进行参数的传递。

2、成员函数都有this指针，无论是否使用。

3、this指针不能做++--等运算,不能重新被赋值。

4、this指针不占用结构体的宽度。

###### 构造函数

```c++
struct Sclass
{
	int a; 
	int b; 
	int c; 
	int d;

	Sclass()							<--------没有返回值，名称与类名称相同(无参构造函数)
	{
		printf（"无参构造函数\n");
	}

	Sclass(int a,int b,int c,int d)		<--------没有返回值，名称与类名称相同(有参构造函数)
	{
		this->a = a;					<--------可以进行初始化操作
		this->b = b;
		this->c = c;
		this->d = d;
		printf（"有参构造函数\n");
	}

	int Plus()
	{
		return a+b+c+d;
	}

};

Sclass s;								<--------调用无参构造函数

Sclass s();								<--------调用有参构造函数
```

1、与类同名且没有返回值

**2**、创建对象的时候执行/主要用于初始化

3、可以有多个(最好有一个无参的),称为重载其他函数也可以重载

4、编译器不要求必须提供

###### 析构函数

```c++
struct Person
{
	int age; 
	int level; 

	Person()
	{
		printf("无参构造函数执行了...");
	}

	Person(int age,int level)
	{
		printf("有参构造函数执行了...");
		this->age = age; 
		this->level =level;
	}

	~Person()							<--------析构函数,对象什么时候分配空间,就在相应的空间收回时执行(结束时)
	{
		printf("析构函数执行了...");
	}

	void Print()
	{
		printf("%d-%d\n",age,level);
	}
};
```

1、只能有一个析构函数，不能重载

2、不能带任何参数(因为是系统帮我们调用的，自然就没有参数了)

3、不能带返回值

**4**、主要用于清理工作

5、编译器不要求必须提供

###### 继承

格式：

```c++
struct Person
{
	int age;
	int sex;
};
struct Teacher
{
	int age; 
	int sex;
	int level; 
	int classld;
};
struct Teacher:Person 								<--------子类:父类
{
	int level; 
	int classld;
};

```

1、什么是继承？继承就是数据的复制

2、为什么要用继承？减少重复代码的编写

3、Person 称为父类或者基类(要复制)

4、Teacher称为子类或者派生类

‍

1.不局限与父类的继承：

```c++
struct X
{
	int a;
	int b;
};
struct Y:X
{
	int c; 
	int d;
};
struct Z:Y
{
	int e; 
	int f;
};
```

![image](https://c65mael.github.io/myassets/image-20231230133511-95nzlym.png)



2.多重继承：

```c++
struct X
{
	int a;
	int b;
};
struct Y
{
	int c; 
	int d;
};
struct Z:X,Y							<--------如果X在前面，则在内存中X也在前面
{
	int e; 
	int f;
};
```

![image](https://c65mael.github.io/myassets/image-20231230134009-b93hjmf.png)​

‍

##### new与delete

new = malloc + 构造函数

delete=free+析构函数

`delete p`​是只删除一个堆块，`delete[] p`​是将所有的堆块全部删除(都执行析构函数~)

###### 引用类型

```c++
Base* p=&b;
Base& ref = b;								<--------就是给对象附一个别名
ref = 4;									<--------实际上是对b进行赋值
```

1、引用必须赋初始值,且只能指向一个变量,“从一而终”。

2、对引用赋值,是对其指向的变量赋值,而并不是修改引用本身的值。

3、对引用做运算,就是对其指向的变量做运算,而不是对引用本身做运算。

4、引用类型就是一个“弱化了的指针”。

5、加const之后为常引用，不可改引用的值。

###### 虚函数

在函数前面加上`virtual`​

```c++
virtual double area()
{
	return(0)
}
```

如果这个虚函数连方法体都没有，那么称之为纯虚函数

```c++
virtual double area() = 0
```

虚函数目的是提供一个统一的接口，被继承的子类重载，以多态的形式被调用(让子类实现一个操作)。虚函数可以被直接使用，也可以被子类重载以后以多态的形式调用。而纯虚函数是因为父类没有实现这个操作的意义，如果父类有纯虚函数(抽象类)，那么子类必须要实现这个函数。

多态

定义：让父类指针有多种形态，通过虚函数实现多态性。

如何实现的呢？：在调用函数时call [ebx] 形成间接调用，并没有写死，便有了多态。

###### 虚表

现象：只要有虚函数在的类中，成员的大小会多出4个字节(不管虚函数有几个~)

原因：有虚函数时，会将虚表的**地址**存到对象的开始的位置，那么成员函数有几个，这个虚表就有几个虚函数的地址。虚表的内容就是成员函数的地址。

‍

子类没有重写时虚表里面的值	和	子类重写时虚表里面的值是什么样的？

chatgpt：

在 C++ 中，当子类没有重写父类的虚函数时，子类对象的虚表中的对应项将指向父类的实现。

具体来说，当父类定义了一个虚函数时，子类继承了该虚函数并得到了一个指向该虚函数的指针。如果子类没有对该虚函数进行重写，那么子类对象的虚表中的该项将指向父类的实现。

以下示例说明了这一点：

```c++
#include <iostream>

class Parent {
public:
    virtual void method() {
        std::cout << "Parent's method" << std::endl;
    }
};

class Child : public Parent {
public:
    // 没有重写父类的 method() 函数
};

int main() {
    Child child;
  
    // 调用子类对象的虚函数，实际上调用了父类中的 method() 函数
    child.method();  // 输出：Parent's method
  
    return 0;
}
```

在上述示例中，子类 `Child`​ 没有对父类 `Parent`​ 中的 `method()`​ 函数进行重写。因此，当调用子类对象 `child`​ 的 `method()`​ 函数时，实际上调用了父类中的 `method()`​ 函数，输出 "Parent's method"。

当子类对父类的虚函数进行重写时，子类对象的虚表中的该项将指向子类的实现。和上述示例相比，只需要在子类中重写父类的 `method()`​ 函数即可。

```c++
#include <iostream>

class Parent {
public:
    virtual void method() {
        std::cout << "Parent's method" << std::endl;
    }
};

class Child : public Parent {
public:
    void method() override {
        std::cout << "Child's method" << std::endl;
    }
};

int main() {
    Child child;
  
    // 调用子类对象的虚函数，实际上调用了子类中的 method() 函数
    child.method();  // 输出：Child's method
  
    return 0;
}
```

在上述示例中，子类 `Child`​ 重写了父类 `Parent`​ 中的 `method()`​ 函数，并将其覆盖为子类的实现。因此，当调用子类对象 `child`​ 的 `method()`​ 函数时，实际上调用了子类中的 `method()`​ 函数，输出 "Child's method"。

###### 运算符重载

就是重新定义运算符，让它有新的含义(就是给运算符宏定义一下bushi)。其实就是声明一个函数，然后在特定位置调用它

```c++
void operator ++()
{
	。。。。。。
}
x++
```

###### 模板

就是自己的函数只能处理一种类型的数据，使用模板后编译器会替你生成对应类型的函数。

函数模板的格式:

```c++
template <class形参名, class形参名, ......>返回类型函数名(参数列表)
{
	函数体
}
```

类模板的格式为：

```c++
template<class形参名, class形参名, ......> class类名 
{

}
```

###### 纯虚函数

父类定义规范，子类遵守规范并实现规范(同虚函数)

###### 对象拷贝

拷贝构造函数的调用：

```c++
CObject x(1,2);
<1> CObject y(x);
<2> CObject *p= new CObject(x);
```

1.就是相当于y就是x的一个副本，本质是内存的复制。

2.只复制成员的值，不复制成员是指针时指针指向的值

###### 友元

向面向过程的妥协

友元函数：

```c++
friend void Printobject(Cobject* pobject);
```

告诉编译器，这个函数是我的朋友，可以访问我的任何成员！

友元类：

```c++
friend class TestFriend（类名称）
```

TestFriend类中的函数都可以直接访问MyObject中的私有成员，但只是单向的。

###### 内部类

将一个类定义到另一个类里面,定义时需要在内部类前面写上外部类的名字。

外部类与内部类的关系：

1.彼此没有特权,互相独立

2.内部类受protected/private影响

###### 命名空间

符号`::`​是作用域的符号，`A::B`​为B属于A

```c++
namespace n1
{
	......
}

namespace n2
{
	......
}
```

如果函数在全局命名空间那么`::Test`​可以调用

###### static关键词

面向过程：

```c++
static char szBuffer[0x10]={0}
```

被static修饰的变量(在函数内定义的)转变为**私有的全局变量，**既只能供当前函数使用的全局变量。

面向对象：

在类中创建的static变量：只是这个类可以访问到的全局变量，这个类的大小不会因为static变量而改变(你仅仅只有访问和使用权，它不是你的)

‍

单子模式

有些时候我们希望定义的某些类只能有一个对象存在（因为一个对象就已经足够了），该如何进行限制呢？实现思路：

1、禁止对象随便被创建

2、保证对象只有一份存在

**总结：**

<1>出现在类体外的函数定义不能指定关键字static;

<2> 静态成员之间可以相互访问，包括静态成员函数访问静态数据成员和访问静态成员函数；

<3> 非静态成员函数可以任意地访问静态成员函数和静态数据成员；

<4> 静态成员函数不能访问非静态成员函数和非静态数据成员；

<5>调用类的静态成员函数的两种方式

###### 调试指令

**系统模块与PE文件检索：**

```sh
0:000> lm            // 列出所有模块对应的符号信息
0:000> lmv           // 列出所有模块对应的符号信息
0:000> lmt           // 列出所有模块的基地址和偏移
0:000> lmf           // 列出所有DLL的具体路径
0:000> lmvm ntdll    // 查看ntdll.dll的详细信息
0:000> !lmi ntdll    // 查看ntdll.dll的详细信息

0:000> !dlls -a               // 列出镜像文件PE结构的文件头
0:000> !dlls -l               // 按照顺序列出所有加载的模块
0:000> !dlls -c ntCreateFile  // 查询指定函数所在的模块
0:000> !dlls -c ntdll.dll     // 列出特定模块头信息
0:000> !dlls -s -c ntdll.dll  // 列出ntdll.dll的节区
0:000> !dlls -v -c ntdll      // 查看ntdll.dll的详细信息

0:000> ld *         // 为所有模块加载符号
0:000> ld kernel32 // 加载kernel32.dll的符号
0:000> x*!                    // 列出加载的所有符号信息
0:000> x ntdll!*              // 列出ntdll.dll中的所有符号
0:000> x ntdll!nt*            // 列出ntdll.dll模块中所有nt开头的符号
0:000> x /t /v ntdll!*        // 带数据类型、符号类型和大小信息列出符号
0:000> x kernel32!*Load*      // 列出kernel32模块中所有含Load字样的符号

```

**进程与线程操作**

```sh
| // 列出调试进程
!dml_proc             // 显示当前进程信息
.tlist -v             // 列出所有运行中的进程
~   // 列出线程
~.  // 查看当前线程
~*  // 所有线程
~0s // 查看主线程
~* k // 所有线程堆栈信息
~* r // 所有线程寄存器信息
~# // 查看导致当前事件或异常的线程
~N  // 查看序数为N的线程
~~[n]  // 查看线程ID为n的线程  n为16进制
~Ns   // 切换序数为N的线程为当前调试线程
~~[n]s  // 切换线程ID为n的线程为当前调试线程  n为16进制
~3f      //把三号线程冻住
~2u       //把二号线程解冻

~N n  // Suspend序数为N的线程
~N m // Resume序数为N的线程
!runaway  //显示当前进程的所有线程用户态时间信息
!runaway f  //显示当前进程的所有线程用户态、内核态、存活时间信息
!locks // 显示死锁
!cs  // 列出CriticalSection（临界段）的详细信息

0:000> .formats 1d78  // 格式化输出PID
!handle  // 查看所有句柄的ID
```

**反汇编指令与内存断点**

```sh
u   // 反汇编当前eip寄存器地址的后8条指令
ub  // 反汇编当前eip寄存器地址的前8条指令
u main.exe+0x10 L20 // 反汇编main.exe+0x10地址后20条指令
uf lyshark::add  // 反汇编lyshark类的add函数
uf /c main  // 反汇编main函数
ub 000c135d L20  // 查看地址为000c135d指令前的20条指令内容

r // 显示所有寄存器信息及发生core所在的指令
r eax, edx // 显示eax，edx寄存器信息
r eax=5, edx=6  // 对寄存器eax赋值为5，edx赋值为6

g  // Go 让程序跑起来
p    // 单步执行(F10)
p 2 // 2为步进数目
pc   // 执行到下一个函数调用处停下
pa 0x7c801b0b // 执行到7c801b0b地址处停下
t     // 停止执行

!address -summary  // 显示进程的内存统计信息
!address -f:stack  // 查看栈的内存信息
!address 0x77c000   // 查看该地址处的内存属性

bl   // 列出所有断点
bc * // 清除所有断点
be *  // 启用所有断点
bd *  // 禁用所有断点

bc 1 2 5  // 清除1号、2号、5号断点
be 1 2 5 // 启用1号、2号、5号断点
bd 1 2 5 // 禁用1号、2号、5号断点

bp main    // 在main函数开头设置一个断点
bp 0x7c801b00  // 在7c801b00地址处放置一个断点
bp main.exe+0x1032  // 在模块MyDll.dll偏移0x1032处放置一个断点
bp @$exentry  // 在进程的入口放置一个断点
bm message_*  // 匹配message_开头的函数，并在这些函数起始处都打上断点

```

**堆栈操作**

```sh
k  // 显示当前调用堆栈
kn // 带栈编号显示当前调用堆栈
kb  // 打印出前3个函数参数的当前调用堆栈
kb 5 // 只显示最上的5层调用堆栈

kv   // 在kb的基础上增加了函数调用约定、FPO等信息
kp  // 显示每一层函数调用的完整参数，包括参数类型、名字、取值
kd  // 打印堆栈的地址
kD  // 从当前esp地址处，向高地址方向搜索符号（注：函数是符号的一种）
dds 02a9ffec  // 从02a9ffec地址处，向高地址方向搜索符号（注：函数是符号的一种）
dds  // 执行完dds 02a9ffec后，可通过dds命令继续进行搜索

.frame // 显示当前栈帧
.frame n  // 显示编号为n的栈帧（n为16进制数）
.frame /r n // 显示编号n的栈帧（n为16进制数） 并显示寄存器变量
.frame /c n // 设置编号n的栈帧为当前栈帧（n为16进制数）
!uniqstack // 显示所有线程的调用堆栈
!findstack kernel32 2 // 显示包含kernel32模块（用星号标出）的所有栈的信息
!heap -s  // 显示进程堆的个数
dt _HEAP 00140000  // 选取一个堆的地址，打印该堆的内存结构
!heap -a 00140000 // 选取一个堆的地址，打印该堆的信息，比上面打印内存命令更详细直观

```

**其他命令:**

```sh
dt ntdll!* // 显示ntdll里的所有类型信息
dt -rv _TEB
dt -rv _PEB
dt -v _PEB @$PEB
dt _PEB_LDR_DATA
dt _TEB ny LastErrorValue // 只查看TEB（thread's environment block）结构成员LastErrorValue

dt _eprocess
dt _eprocess 0x510

!dh 773a0000                 显示文件PE头

*是通配符；显示所有peb打头的结构体名称；
dt ntdll!_peb*

0:000> dt -rv ntkrnlmp!*Object*  枚举ntkrnlmp中带"Object"的结构体名称；

.attach  PID  附加进程
.detach         结束会话

.dump  文件名  转存文件
.opendump     打开文件

dt -v ntdll!*           # 列出ntdll中的全部结构体，导出的函数名也会列出

dt ntdll!*file*           # 下面命令将列出ntdll导出的文件操作相关的函数名
dt _FILE_INFORMATION_CLASS      查看一个结构定义
dt ntdll!_*   列出ntdll中结构体
```

### PE文件结构

![pe](https://c65mael.github.io/myassets/pe.png)

###### 结构

![image](https://c65mael.github.io/myassets/image-20240124021409-650cwqy.png)​​

1.程序在内存中是分节的，每一个节存储不同的数据，硬盘对齐(200h)，内存对齐(1000h)。因为程序在硬盘上和内存中的状态可能略有不同(以前的程序在内存中与在硬盘上，在内存中节与节之间会有一个"拉伸"过程，节与节之间的空隙变大(填充0)。而现在的程序则并不会。)，这样做可以(1).节省硬盘空间。(2).实现多开(将只读的节保留，将可读可写的节多开，可以节省内存空间)。

![image](https://c65mael.github.io/myassets/image-20240124024811-j31e5w4.png)​

2.DOS头是十六位系统使用的，程序会解析DOS头的前两位(**pe指纹**WORD e_magic;)是不是MZ(4D 5A),之后通过DOS头去寻找程序真正开始的地方(**pe头的偏移**DWORD e_lfanew; 50 45 PE)。在e_lfanew与PE字符之间是垃圾数据。之后便到了IMAGE_NT_HEADERS(NT头)，NT结构体的第一个成员(DWORD Signature)是字符[50 45 00 00] (PE\0\0),第二个成员(IMAGE_FILE_HEADER FileHeader)是**标准PE头**(COFF 头)：

```c
typedef struct _IMAGE_FILE_HEADER {

	WORD	Machine；（目标机器类型）：表示该PE文件应该在哪种类型的处理器上运行。如果是0x0则可以在如何处理器上运行，如果是0x14C则在386后续处理器上运行。如果是0x8664则在x64处理器上运行

	WORD	NumberOfSections;（节表项数）：表示PE文件的节表中有多少个节。

	DWORD	TimeDateStamp;（时间戳）：编译或链接的日期和时间。1970

	DWORD	PointerToSymbolTable;（符号表的文件偏移）：如果不存在符号表，其值为 0。(调试相关)

	DWORD	NumberOfSymbols;（符号表中的符号数量）：由于字符串表紧跟在符号表之后，所有能通过该值定位字符串表。(调试相关)

	WORD	SizeOfOptionalHeader;（可选PE头大小）：可选PE头的长度，大小可以自定义。在 32-bit 机器上默认是 0x00E0，在 64-bit 机器上默认是 0x00F0。

	WORD	Characteristics;（用于标识文件属性）：指定PE文件的属性和特性，例如是否为可执行文件、是否支持调试等。

} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

| 标号 | Characteristics 标志位             |                        属性                        |
| :--- | :--------------------------------- | :------------------------------------------------: |
| 0    | IMAGE_FILE_RELOCS_STRIPPED         |  重定位信息已被剥离，意味着文件中不包含重定位信息  |
| 1    | IMAGE_FILE_EXECUTABLE_IMAGE        |      文件是可执行的，可以作为应用程序直接运行      |
| 2    | IMAGE_FILE_LINE_NUMS_STRIPPED      |    行号信息已被剥离，意味着文件中不包含行号信息    |
| 3    | IMAGE_FILE_LOCAL_SYMS_STRIPPED     |  符号信息已被剥离，意味着文件中不包含局部符号信息  |
| 4    | IMAGE_FILE_AGGRESIVE_WS_TRIM       |              调整工作集，优化内存使用              |
| 5    | IMAGE_FILE_LARGE_ADDRESS_AWARE     |        应用程序可以处理大于 2GB 的地址空间         |
| 6    |                                    |            此标志位保留，没有特定的属性            |
| 7    | IMAGE_FILE_BYTES_REVERSED_LO       | 字节顺序反转（低字节序），文件采用小尾方式存储数据 |
| 8    | IMAGE_FILE_32BIT_MACHINE           |                只在 32 位平台上运行                |
| 9    | IMAGE_FILE_DEBUG_STRIPPED          |                   不包含调试信息                   |
| 10   | IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP |                 不能从可移动盘运行                 |
| 11   | IMAGE_FILE_NET_RUN FROM_SWAP       |                   不能从网络运行                   |
| 12   | IMAGE_FILE_SYSTEM                  |         系统文件（如驱动程序),不能直接运行         |
| 13   | IMAGE_FILE_DLL                     |                 这是一个 DLL 文件                  |
| 14   | IMAGE_FILE_UP_SYSTEM_ONLY          |           文件不能在多处理器计算机上运行           |
| 15   | IMAGE_FILE_BYTES_REVERSED_HI       |                      大尾方式                      |

紧接着，就是可选(扩展)PE头(IMAGE_OPTIONAL_HEADER):

```c
	1、DOC头：										
											
	WORD   e_magic                *				"MZ标记" 用于判断是否为可执行文件.						
	DWORD  e_lfanew;              *				PE头相对于文件的偏移，用于定位PE文件						
											
											
	2、标准PE头：										
											
	WORD    Machine;              *				程序运行的CPU型号：0x0 任何处理器/0x14C 386及后续处理器						
	WORD    NumberOfSections;     *				文件中存在的节的总数,如果要新增节或者合并节 就要修改这个值.						
	DWORD   TimeDateStamp;        *				时间戳：文件的创建时间(和操作系统的创建时间无关)，编译器填写的.						
	DWORD   PointerToSymbolTable; 										
	DWORD   NumberOfSymbols; 										
	WORD    SizeOfOptionalHeader; *				可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h  大小可以自定义.						
	WORD    Characteristics;      *				每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1 						
											
	3、可选PE头：										
											
	WORD    Magic;      		  *		        说明文件类型：10B 32位下的PE文件     20B 64位下的PE文件						
	BYTE    MajorLinkerVersion;										
	BYTE    MinorLinkerVersion;										
	DWORD   SizeOfCode;*						所有代码节的和，必须是FileAlignment的整数倍 编译器填的  没用						
	DWORD   SizeOfInitializedData;*				已初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用						
	DWORD   SizeOfUninitializedData;*			未初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用						
	DWORD   AddressOfEntryPoint;*				程序入口						
	DWORD   BaseOfCode;*						代码开始的基址，编译器填的   没用						
	DWORD   BaseOfData;*						数据开始的基址，编译器填的   没用						
	DWORD   ImageBase;*							内存镜像基址						
	DWORD   SectionAlignment;*					 内存对齐						
	DWORD   FileAlignment;*						 文件对齐						
	WORD    MajorOperatingSystemVersion;										
	WORD    MinorOperatingSystemVersion;										
	WORD    MajorImageVersion;										
	WORD    MinorImageVersion;										
	WORD    MajorSubsystemVersion;										
	WORD    MinorSubsystemVersion;										
	DWORD   Win32VersionValue;										
	DWORD   SizeOfImage;*			 内存中整个PE文件的映射的尺寸，可以比实际的值大，但必须是SectionAlignment的整数倍						
	DWORD   SizeOfHeaders;*						所有头+节表按照文件对齐后的大小，否则加载会出错						
	DWORD   CheckSum;*							校验和，一些系统文件有要求.用来判断文件是否被修改.						
	WORD    Subsystem;										
	WORD    DllCharacteristics;										
	DWORD   SizeOfStackReserve;*				初始化时保留的堆栈大小 						
	DWORD   SizeOfStackCommit;*					初始化时实际提交的大小 					
	DWORD   SizeOfHeapReserve;*					初始化时保留的堆大小 				
	DWORD   SizeOfHeapCommit;*					初始化时实践提交的大小 				
	DWORD   LoaderFlags;								
	DWORD   NumberOfRvaAndSizes;*				目录项数目
```

‍

| 标志位 |             DllCharacteristics属性             |            说明            |
| ------ | :--------------------------------------------: | :------------------------: |
| 0      |                    Reserved                    |          必须为0           |
| 1      |                    Reserved                    |          必须为0           |
| 2      |                    Reserved                    |          必须为0           |
| 3      |                    Reserved                    |          必须为0           |
| 4      |                      null                      |            null            |
| 5      |                      null                      |            null            |
| 6      |     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE      |  DLL可以在加载时被重定位   |
| 7      |    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    |   强制代码实施完整性验证   |
| 8      |       IMAGE_DLLCHARACTERISTICS_NX_COMPAT       |       该映像兼容 DEP       |
| 9      |     IMAGE_DLLCHARACTERISTICS_NO_ISOLATION      | 可以隔离，但并不隔离此映像 |
| 10     |        IMAGE_DLLCHARACTERISTICS_NO_SEH         | 没有结构化异常处理（SEH）  |
| 11     |        IMAGE_DLLCHARACTERISTICS_NO_BIND        |         不绑定映像         |
| 12     |                    Reserved                    |          必须为0           |
| 13     |      IMAGE_DLLCHARACTERISTICS_WDM_DRIVER       |  该映像为一个 WDM driver   |
| 14     |                    Reserved                    |          必须为0           |
| 15     | IMAGE_DLLCHARACTERISTICS_TERMINAL SERVER_AWARE |      可用于终端服务器      |

###### ‍RVA与FOA的转换

因为运行的程序全局变量的初始值在未运行的程序中也存在，所以我们如何通过运行程序的地址的值，来推出程序在未运行时这个值对应的地址。

1. ‍RVA相对虚拟地址

   `‍RVA=address(程序运行时要找值的地址)-ImageBase`

2. FOA文件偏移地址(程序未运行要找的地址)

3. 对应关系(不过现在的程序运行和未运行是对齐都相等，所以直接FOA=RVA)：

   - 如果在头部(前面没有节的对齐) FOA=RVA

   - 不在头部(节内的差值是相同的)

```
RVA >=节.VirtualAddress

RVA <= 节.VirtualAddress + 当前节内存对齐后的大小

差值 = RVA - 节.VirtualAddress

FOA =节.PointerToRawData +差值
```

###### 实验：在编译好的程序执行前弹个窗口

1. 汇编对应硬编码6A 00 ：push 0	E8跳转值 ：call 要跳转的地址
2. 计算要跳转地址的硬编码：

跳转值=要跳转的地址-E8(call)指令当前的地址-5(对齐到下一个指令)

###### 扩大节

当我们想添加的代码或者shellcode比较多，程序没地方写的话可以选择扩大节，由于对齐的原因，扩大最后一个节对其他节的影响最小，是最优选择

扩大节的步骤：

1. 分配一块新的空间,大小为S

2. 将最后一个节的SizeOfRawData和VirtualSize改成N

   `N = (SizeOfRawData或者VirtualSize内存对齐后的值) + S`

3. 修改SizeOflmage大小

###### 新增节

新增节的步骤：

1. 判断是否有足够的空间,可以添加一个节表.
2. 在节表中新增一个成员.
3. 修改PE头中节的数量.
4. 修改sizeOflmage的大小.
5. 再原有数据的最后,新增一个节的数据(内存对齐的整数倍).
6. 修正新增节表的属性.

###### 导出表

一个程序是由多个配文件所组成，那么这个程序使用了哪些dll文件，会在一个表中记录，这就是导入表；同样的，有哪些程序使用了我这个程序的函数，也会记录在一个表内，这个表是导出表。

如何找到导出表：pe文件结构中最后一个结构中的第一个结构体，那里存放着导出表的地址(rva)和大小(size)

请注意，这个大小(size)指的是导出表中的指针指向的内容的和大小(比如name指针指向的字段以\x00截至，等等的所有字段和加上固定的40个字节，只是编译器填的值，无实际意义)

```c
IMAGE_DIRECTORY_ENTRY_EXPORT
    
struct_IMAGE_DATA_DIRECTORY { 
0x00 DWORD VirtualAddress; 
0x04 DWORD Size;
}
```

通过这个地址就可以找到导出表，结构如下：

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;        //未使用
    DWORD   TimeDateStamp;          //时间戳
    WORD    MajorVersion;           //未使用
    WORD    MinorVersion;           //未使用
    DWORD   Name;                   //指向改导出表文件名字符串
    DWORD   Base;                   //导出表的起始序号
    DWORD   NumberOfFunctions;      //导出函数的个数(更准确来说是AddressOfFunctions的元素数，而不是函数个数)
    DWORD   NumberOfNames;          //以函数名字导出的函数个数
    DWORD   AddressOfFunctions;     //导出函数地址表RVA:存储所有导出函数地址(表元素宽度为4，总大小NumberOfFunctions * 4)
    DWORD   AddressOfNames;         //导出函数名称表RVA:存储函数名字符串所在的地址(表元素宽度为4，总大小为NumberOfNames * 4)
    DWORD   AddressOfNameOrdinals;  //导出函数序号表RVA:存储函数序号(表元素宽度为2，总大小为NumberOfNames * 2)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

1.导出的函数要么用名字导出，要么用序号导出(隐藏),总数为NumberOfNames的值

一共有三个表，地址表，序号表，名称表

其中：序号表的数量与名称表的数量相同。

比如：

|    地址表     | 序号表(2字节) |   名称表    |
| :-----------: | :-----------: | :---------: |
| addr1(knameA) |       4       | ADDR1(AAAA) |
| addr2(knameB) |       1       | ADDR2(BBBB) |
| addr3(knameC) |       0       | ADDR3(CCCC) |
|   00000000    |               |             |
| addr4(knameD) |               |             |

**通过名字找函数时**：

1. 首先遍历名称表，比如找到名称AAAA函数，发现是表中的第0号成员。
2. 通过①中的0直接查询序号表中的0号成员，发现是数字4
3. 通过②中的4直接查找地址表中的第4号成员，为addr4(knameD)，所以knameD就是AAAA

**通过序号找函数时**：

1. 将导出序号减去导出表的起始序号(Base的值)。
2. 将这个值直接对应地址表，就没了。

###### 导入表

1. 依赖一个模块就会有一个导入表，所以导入表有很多。
2. 遇到连续20个\x00说明导入表结束了

结构如下：

```c
typedef struct_IMAGE_IMPORT_DESCRIPTOR 
union {
DWORD Characteristics;
DWORD OriginalFirstThunk;			  //RVA指向IMAGE_THUNK_DATA结构数组
};
DWORD TimeDateStamp;				 //时间戳
DWORD ForwarderChain;
DWORD Name;							 //RVA,指向dl名字，该名字已0结尾
DWORD FirstThunk;					 //RVA,指向IMAGE_THUNK_DATA结构数组
}IMAGE_IMPORT_DESCRIPTOR;
```

其中:

1. OriginalFirstThunk成员和FirstThunk成员又分别指向了INT(导入名称表)和IAT(导入地址表)，这两张表位置和名称都不同，但内容却相同，都能找到函数名称。
2. 当遇到全为\x00时，说明已经结束了。
3. 成员有多少个，该程序就使用了这个dll中的多少个函数。

![image](https://c65mael.github.io/myassets/daorubiao1.png)

```c
typedef struct_IMAGE_THUNK_DATA32
union{
	PBYTE ForwarderString;
	PDWORD Function;
	DWORD Ordinal;						//序号
	PIMAGE_IMPORT_BY_NAME AddressOfData;  //指向IMAGE_IMPORT_BY_NAME
}u1;
}IMAGE_THUNK_DATA32;

```

在OriginalFirstThunk中的IMAGE_THUNK_DATA32成员。判断最高是否为1，如果是，那么除去最高位的值就是函数的导出序号(按序号导入)；如果不是，那么这个值是一个RVA指向IMAGE_IMPORT_BY_NAME

```c
typedef struct_IMAGE_IMPORT_BY_NAME {
	WORD Hint;							//可能为空,编译器决定如果不为空是函数在导出表中的索引
	BYTE Name[1];						//函数名称，以0结尾
}IMAGE IMPORT BY NAME, *PIMAGE IMPORT BY NAME;
```

Hint成员如果不为空，则直接找导出表中地址表的索引，直接可以找到函数。

Hint成员如果为空，则通过Name[1]来确定函数叫说明名字，之所以是1字节，是因为函数不知道函数名称的长度，所以确定第一个字节之后一直找，遇到\x00结束，就是函数的名称。

确定函数地址：

![image](https://c65mael.github.io/myassets/daorubiao2.png)

1. 在使用其他dll中的函数，使用的call都是间接call。间接call会提供一个地址编号来存放函数的地址，那么这个地址所在的表就是导入地址表(IAT)。
2. pe文件加载前后IAT表会发生变化，会存放函数的地址(也就是通过函数的名称进而得到函数的地址)。
3. 为什么有两条线？如果IAT表的这条线被破坏，则可以通过INT表进行修正。

###### 重定位表

如果两个dll文件在导入内存时，导入在相同的ImageBase的偏移处，该怎么办？只需要修正其中一个dll文件的偏移在没有文件导入的内存偏移，即可。但这两个dll中的全局变量的硬编码可能会有相同的偏移。这时就需要使用重定位表了

数据目录项的第6个结构，就是重定位表(相对于映像基址的偏移量)。

结构如下：

```C
typedef struct _IMAGE_BASE_RELOCATION {
	DWORD VirtualAddress;
	DWORD SizeOfBlock; //字节为单位
} IMAGE_BASE_RELOCATION;
```

1. 这个结构体中的第二个成员SizeOfBlock是当前重定位块的总大小，就是加上VirtualAddress成员的大小。
2. 当遇到全为\x00时(8个)，说明已经结束了。

比如其中一个重定位块如下：

| Virtual  |          |          |          |
| :------: | :------: | :------: | :------: |
|   Size   |          |          |          |
| 0011#### | ######## | 0011#### | ######## |
| 0011#### | ######## | 0011#### | ######## |

说明：Virtual代表VirtualAddress成员，Size(0x10)代表SizeOfBlock成员，#代表一位的数据，一个框代表一个字节。

2^12=4096，即为一页对齐的数据，所以使用两个字节(16位其中的低12位)来存放地址，其中的高4位的作用是：当高4位的值为3(0011=3，不是3时就是垃圾！)时，说明该地址有意义重定位，应当重定位的值=VirtualAddress成员+低12位

###### 移动导出表，重定向表

1. 在DLL中新增一个节，并返回新增后的FOA
2. 复制AddressOfFunctions	长度：4*NumberOfFunctions*
3. *复制AddressOfNameOrdinals	长度：NumberOfNames*2
4. 复制AddressOfNames	长度：NumberOfNames*4
5. 复制所有的函数名	长度不确定，复制时直接修复AddressOfNames
6. 复制IMAGE_EXPORT_DIRECTORY结构
7. 修复IMAGE_EXPORT_DIRECTORY结构中的	AddressOfFunctions	AddressOfNameOrdinals	AddressOfNames
8. 修复目录项中的值，指向新的IMAGE_EXPORT_DIRECTORY











###### 注入shellcode

不依赖环境，放到任何地方都可以执行的机器码。

ShellCode的编写原则：①不能有全局变量②不能使用常量字符串③不能使用系统调用④不能嵌套调用其他函数

```c
char shellcode[] = {'S','h','e','l','l','C','o','d','e',0}; //不能使用常量字符串
```

后面那个不会



###### VirtualTable_Hook

①HOOK是用来获取、更改程序执行时的某些数据,或者是用于更改程序执行流程的一种技术。

② HOOK的两种主要形式：

1. 改函数代码	INLINE HOOK
2. 改函数地址IAT HOOK	SSDT HOOK	IDT HOOK	EAT HOOK	IRP HOOK



### win32

###### 字符编码

ASCII编码无法满足我们输入的中文文字。便引入了扩展ASCII表，原来的ASCII表进行扩展，将0x80~0xff的两个符号拼起来组成新的文字(GB2312)，就是中文。但是不同国家有不同的规则，那么中文文字发送过去会产生乱码。为了解决这个问题，就产生了unicode编码，unicode编码是将世界上所有的字符建立与0~0x10ffff的对应。但是unicode编码长度可能的1或2或3字节，这样不好存储。

**UTF-16:**

UTF-16编码以16位无符号整数为单位，注意是16位为一个单位,不表示一个字符就只有16位。这个要看字符的unicode编码处于什么范围而定,有可能是2个字节，也可能是4个字节现在机器上的unicode编码一般指的就是UTF-16。

**UTF-8:**

不同的16进制码用不同的UTF-8规则编码

| Unicode编码(6进制) |        UTF-8 字节流(二进制)         |
| :----------------: | :---------------------------------: |
|  000000 - 00007F   |              0xxxxxxx               |
|  000080 - 0007FF   |         110xxxxx  10xxxxxx          |
|  000800 - 00FFFF   |     1110xxxx 10xxxxxx  10xxxxxx     |
|   010000 -10FFFF   | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx |

**BOM(Byte Order Mark):**

放在UTF-8或UTF-16编码的前面，让计算机知道这是什么方式编码的

|      BOM       |          |
| :------------: | :------: |
|     UTF-8      | EF BB BF |
| UTF-16LE(小端) |  FF FE   |
| UTF-16BE(大端) |  FE FF   |

###### c语言中的宽字节

对比：

```c
char szStr[]= "中国";										2D 4E FD 56 00			(GB2312编码)
wchar_t swzStr]=L"中国";									D6 D0 B9 FA 00 00		(Unicode编码)宽字节
```

###### win32 api中的宽字节

- 在win32编程中都是见过的类型，只不过是换了一个名字而已。
- 在win32编程中函数一般都会有两个(比如：massageboxA messageboxW)，为了使ASCII编码和unicode编码有区分。

###### 进程

就是运行中的一个程序，进程提供程序所需要的资源，它提供数据和代码，是一种空间的概念

①进程内存空间的地址划分：

|     分区     |    x86 32位的windows    |
| :----------: | :---------------------: |
| 空指针赋值区 | 0x00000000 - 0x0000FFFF |
|  用户模式区  | 0x00010000 - 0x7FFEFFFF |
|  64KB禁入区  | 0x7FFF0000 - 0x7FFFFFFF |
|     内核     | 0x80000000 - 0xFFFFFFFF |

②进程的创建

<1>任何进程都是别的进程创建的：CreateProcess()

<2> 进程的创建过程

1. 映射EXE文件(将exe放到内存中)
2. 创建内核对象EPROCESS
3. 映射系统DLL(ntdll.dll)
4. 创建线程内核对象ETHREAD
5. 系统启动线程

​		映射DLL(ntdll.LdrlnitializeThunk)

​		线程开始执行

###### 创建进程

```c
BOOL CreateProcess(
	LPCSTR lpApplicationName,	//对象名称
	LPSTR lpCommandLine,		//命令行
	LPSECURITY_ATTRIBUTES lpProcessAttributes,	//不继承进程句柄
	LPSECURITY_ATTRIBUTES lpThreadAttributes,	//不继承线程句柄
	BOOL bInheritHandles,		//不继承句柄
	DWORD dwCreationFlags,		//没有创建标志
	LPVOID lpEnvironment,		//使用父进程环境变量
	LPCSTR lpCurrentDirectory,	//使用父进程自录作为当前目录，可以自己设置目录
	LPSTARTUPINFOA lpStartupInfo,	//STARTUPINFOW结构体详细信息
	LPPROCESS_INFORMATION lpProcessInformation	//PROCESS_INFORMATION结构体进程信息
    )
```

###### 句柄表

什么是内核对象：

像进程、线程、文件、互斥体、事件等在**内核**都有一个对应的**结构体**，这些结构体由内核负责管理。我们管这样的对象叫做内核对象。

![image](https://c65mael.github.io/myassets/nhdx.png)

一个进程有一个自己的内核对象(EPROCESS)，在这一个进程里面还有可能创建其他的内核对象(紫色的)，那么如何使用他们呢？可以将对应的内核对象的地址传回去就可以了，但是在用户层访问内核层的问题在于，如果这个内核对象的地址被修改，那么访问对应内核层的地址时就会内存无法访问。所以就产生了句柄表，句柄表是0环EPROCESS下的一个成员(蓝色的)，句柄表存在的目的就是解决上面的问题。在句柄表里面会存储进程里面所有内核对象的地址(0环)，所以将编号传回去，使用对应的内核对象时用编号来代替对应0环的地址。(相当于防火墙的存在，用户层没办法直接操作内核层)：

![image](https://c65mael.github.io/myassets/gbb1.png)

- 多个进程可以共享一个内核对象，但是索引值可能不太一样。
- 有几个进程打开或使用了这个内核对象，内核对象中的计数器就会变为几(紫色里面的红色小下标)。
- closehandle的api是让内核对象中的计数器的值减一。
- 如果想要关闭线程的内核对象，要使计数器的值为0且需要关闭这个线程，两个条件缺一不可。除了线程以外的内核对象只需要使计数器的值为0就可以关闭这个内核对象。

![image](https://c65mael.github.io/myassets/gbb2.png)























### MFC

本质是对win32api的封装

###### CWinApp类

派生Windows应用程序对象的基类。应用程序对象提供了用于初始化应用程序和运行应用程序的成员函数。

使用MFC的每个应用程序只能包含一个从CWinApp派生的对象。当您从CWinApp派生应用程序类时,覆盖InitInstance成员函数以创建应用程序的主窗口对象。它还有一个成员变量:m pMainWnd用来记录创建的主窗口的对象。

除了CWinApp成员函数之外, Microsoft基础类库还提供了以下全局函数来访问CWinApp对象和其他全局信息:

* AfxGetApp获取一个指向CWinApp对象的指针。
* AfxGetinstanceHandle获取当前应用程序实例的句柄。
* AfxGetResourceHandle获取应用程序资源的句柄。
* AfxGetAppName获取指向包含应用程序名称的字符串的指针。如果您有一个指向CWinApp对象的指针,请使用m pszExeName获取应用程序的名称。

###### CFrameWnd类

提供了Windows单文档界面(SDI)重叠或弹出框架窗口的功能,以及用于管理窗口的成员。

要为应用程序创建有用的框架窗口,请从CFrameWnd派生类。向派生类添加成员变量以存储特定于您的应用程序的数据。在派生类中实现消息处理程序成员函数和消息映射,以指定在将消息定向到窗口时会发生什么。

有三种方法来构造框架窗口：

* 使用Create直接构造它。（本节需要掌握的内容）
* 使用LoadFrame直接构造它。(后续课程讲解)
* 使用文档模板间接构建它。（后续课程讲解）

###### CFrameWnd :: Create 成员函数

如果类名为NULL,则以MFC内建的窗口类产生一个标准的外框窗口

```bash
BOOL Create(LPCTSTR IpszClassName

	LPCTSTR IpszWindowName,

	DWORD dwStyle = WS_OVERLAPPEDWINDOW,

	const RECT& rect = rectDefault,

	CWnd* pParentWnd = NULL, // != NULL for popups

	LPCTSTR IpszMenuName=NULL,

	DWORD dwExStylel=0,

	CCreateContext* pContext=NULL);
```

返回值:非零表示初始化成功,否则为0

备注：通过两个步骤构造一个CFrameWnd对象。首先调用构造函数,它构造CFrameWnd一对象,然后调用Create,创建Windows框架窗口并将其附加到CFrameWnd对象。创建初始化窗口的类名和窗口名称,并注册其样式,父级和关联菜单的默认值。

**总结：(就是根据如下操作就可以创建一个窗口😊)**

1. 基于MFC的窗口程序必须也只能有一个由从CWinApp派生的对象
2. 我们必须覆盖CWinApp的虚函数InitInstance在里面创建窗口.并把窗口对象保存在它的成员变量m pMainWnd.
3. 创建窗口是通过派生CFrameWnd对象.在它的构造函数里面调用成员函数create



### 保护模式

###### 保护模式概述

‍保护模式分为段机制和页机制。

理解：想象一下你家的电脑就像一个大厨房，里面有很多小帮手在做不同的事情，比如煮汤、炒菜等等。保护模式就是为了保证这个大厨房的秩序和安全。首先，保护模式就像是给每个小帮手配了一套专属的工具，他们不能随便用别人的工具，也不能乱碰别人的食材。这样做的好处是，即使其中一个小帮手犯错了，也不会影响到其他小帮手(**防止一个进程访问或修改另一个进程的内存数据**)。其次，保护模式给了每个小帮手一个身份证，分成两类：一类是高级厨师，一类是普通厨师。高级厨师有更多的权限，可以做更多的事情，比如烧开水等。而普通厨师的权限就少一些，不能做一些危险的事情。这样可以防止有人乱来，比如一个不懂规矩的小帮手想烧开水，但是他只是个普通厨师，就不能执行这个操作(**内核模式具有更高的特权级别，可以执行更多的操作，而用户模式受到更多的限制**)。再来，保护模式还给了每个小帮手一个梦幻厨房，虽然实际上只有一个大厨房，但是每个小帮手都觉得自己有一个属于自己的梦幻厨房。这样就不会出现争抢厨房的情况，大家都可以安心做自己的事情(**操作系统可以为每个进程提供虚拟内存，使得每个进程都认为自己拥有连续的内存空间**)。最后，保护模式还让这些小帮手轮流工作，每个人都有自己的时间段做事情，不会出现一个人霸占厨房不肯给别人机会的情况，这样大家都有机会工作，效率也更高(**操作系统可以同时运行多个进程，并实现进程之间的时间片轮转调度，使得多个程序可以并发执行**)。

###### 段寄存器结构

段寄存器一共有ES CS SS DS FS GS LDTR TR 共8个。

当我们用汇编读写某一个地址时：

```assembly
mov dword ptr ds:[0x123456],eax
```

我们真正读写的地址是：

```assembly
ds.base+0x123456
```

段寄存器结构体如下：

```c
struct Segment
{
  WORD Selecter;  //16位段选择子           可见部分.  使用OD 或者X64dbg看段寄存器只会显示16位的段选择子可见部分.
  WORD Attribute; //16位表示的段属性, 表示了当前段寄存器是可读的可写的还是可执行的
  DWORD Base;     //32位表示的基址,表示段从哪里开始
  DWORD limit;    //32位表示,表示的是基址的长度. base + limit 可以确定一个段的大小
}
```

结构如下图：

```
[---------------------------------> 可见部分 <-----------------------------------------] [-->不可见部分<---]
+--------------------------------------------------------------------------------------------------------+
|								|								|				|				|
|								|								|				|				|
|								|								|				|				|
|								|								|				|				|
+--------------------------------------------------------------------------------------------------------+
				^								^						^				^
				|								|						|				|
				|								|						|				|
			32位Base							32位limit				16位Attribute	16位Selecter

```

段寄存器属性如下：

| 寄存器名称                 | 段选择子(Select) | 段属性(Attributes) | 段基址(Base)   | 段长(Limit) |
| -------------------------- | ---------------- | ------------------ | -------------- | ----------- |
| ES(附加扩展段)             | **0x0023**       | 可读,可写          | 0x0000000      | 0xFFFFFFFF  |
| CS(代码段)                 | **0x001B**       | 可读,可执行        | 0x00000000     | 0xFFFFFFFF  |
| SS(堆栈段)                 | **0x0023**       | 可读,可写          | 0x00000000     | 0xFFFFFFFF  |
| DS(数据段)                 | **0x0023**       | 可读,可写          | 0x00000000     | 0xFFFFFFFF  |
| FS(分段机制)               | **0x003B**       | 可读,可写          | **0x7FFDF000** | 0xFFF       |
| GS(额，64位系统好像使用吧) | 未使用           | 未使用             | 未使用         | 未使用      |

###### 段描述符与段选择子

1. GDT(全局描述符表) LDT(局部描述符表)

   当我们执行类似`MOV DS,AX`指令时，CPU会查表，根据AX的值来决定查找GDT还是LDT，查找表的什么位置，查出多少数据。(AX就是可见的`Selector段选择子`的内容)

   GDTR(48位寄存器，表中存放了GDT表 的起始地址(32位)，外加存放GDT表的大小(16位))

2. 段描述符(8字节一组，64位)结构（记住结构）

   ![image](https://c65mael.github.io/myassets/xuanzazi.png)

   - **AVL**: 该位是用户位，可以被用户自由使用
   - **BASE**: 段基址，由上图中的两部分(BASE 31-24 和 BASE 23-0(图错了))组成
   - **D/B**: 该位为 0 表示这是一个 16 位的段，1 表示这是一个 32 位段
   - **DPL**：段权限
   - **G**：LIMIT的单位，该位 0 表示单位是字节，1表示单位是 4KB
   - **LIMIT**: 段的界限，单位由 G 位决定。数值上（经过单位换算后的值）等于段的长度（字节）- 1。
   - **P**: 段存在位，该位为 0 表示该段不存在，为 1 表示存在。
   - **S**: 该位为 1 表示这是一个数据段或者代码段。为 0 表示这是一个系统段（比如调用门，中断门等）
   - **TYPE**: 根据 S 位的结果，再次对段类型进行细分。

3. 段选择子（2字节，16位）

   段选择子是一个16位的段描述符，该描述符指向了定义该段的段描述符。

   ![image](https://c65mael.github.io/myassets/xz.png)

   `说明：`
   `MOV DS，AX`指令时，
   假如AX=1B，即001B，拆分为0000 0000 0001 1011

   去掉TI和RPL值，后剩下Index值为11，即3，则查GDT表索引值为3 （GDT表中索引值从0开始，索引值为0处的段描述符为0）的段描述符。

4. 加载段描述符至段寄存器

   除了MOV指令,我们还可以使用LES、LSS、LDS、LFS、 LGS指令修改寄存器。(L是Load的意思)

   CS不能通过上述的指令进行修改，CS为代码段，CS的改变会导致EIP的改变，要改CS，必须要保证CS与EIP一起改。

   ```c
   char buffer[6]; 
   asm{
       les ecx,fword ptr ds:[buffer] //高2个字节给es,低四个字节给ecx
   }
   //es也就是上面的段选择子，用00补全成4位，然后拆分……
   ```

   注意: RPL<=DPL(在数值上)	(以什么样的权限去访问段)

###### 段描述符的属性

**P**: 段存在位，该位为 0 表示该段不存在，为 1 表示存在。(**CPU后面就不检查别的位了**)

**LIMIT**: 段的界限，单位由 G 位决定。数值上（经过单位换算后的值）等于段的长度（字节）- 1。

![image](https://c65mael.github.io/myassets/xuanzazi.png)

- **Attribute** //16位 对应段描述符（高四字节） 第8位~第23位

- **Base** //32位 （高四字节）第24位 ~ 第31位 + （高四字节）第0位 ~ 第7位+（低四字节）第16位 ~ 第31位

- **Limit** //32位 （高四字节）第16位 ~ 第19位 +（低四字节）第0位 ~ 第15位 总共20位 最大值也就是FFFFF，此时分情况
  1.如果G位为0，那么Limit单位是字节，此时高位填0,即最大值也就是0x000fffff
  2.如果G位为1，那么Limit单位是4KB，4x1024=4096,4096代表有多少个，但是地址计算都是从0开始的，那么需要减1，即上限为4096-1=4095,刚好转为0xfff，如果此时Limit界限为1的话，那么此时为0x1FFF，则最大可以为0xffffffff

- 不理解：如果粒度 `G=0，LIMIT= 0x3ff`，这意味着该段的大小是 `0x3ff+1=0x400` 字节。如果 `G=1`，那意味着该段的大小是`(0x3ff+1)*4KB=0x400000`字节，所以换算后的 `limit = 0x400000-1=0x003fffff`.

  再举个例子。`LIMIT=0xfffff, G=1`,则该段的大小是 `(0xfffff+1)*4KB=0x100000*0x1000=0x100000000`字节，所以换算后的 `limit=0x100000000-1=0xffffffff`

```
总结：
如果 G = 0，把段描述符中的 20 bit LIMIT取出来，比如 0x003ff，然后在前面补 0 至32bit，即 limit = 0x000003ff
如果 G = 1，把段描述符中的 20 bit LIMIT取出来，比如 0x003ff，然后在后面补 f 至 32bit, 即 LIMIT = 0x003fffff
```

**S**: 该位为 1 表示这是一个**数据段**或者**代码段**。为 0 表示这是一个系统段（比如调用门，中断门等）

额我们先找**数据段**或者**代码段**，s位的不同会导致TYPE域发生变化。这张图是TYPE域满足什么条件下是数据段或代码段：

![image](https://c65mael.github.io/myassets/type.png)

1. 因为DPL的值只可能是全1或全0，所以16~12位如果是数据段或代码段的话只能为f(1111)或9(1001)。`那么在GDT中找第五位，如果是f或9就是数据段或代码段`。
2. 因为TYPE域的第11位只可能是1或0，而且全为1是代码段；全为0是数据段。`那么第六位大于8就是代码段，小于8就是数据段`。

来看数据段的标志位：

- A：如果为1，代表该数据段描述符已经被访问过了
- W：如果为1，代表该数据段描述符是可写的
- E：如果为1，表示向下扩展(右图)；E=0，表示向上扩展(左图)，windows只使用向上扩展，也就是E为0

![image](https://c65mael.github.io/myassets/ewei.png)

来看代码段的标志位：

- C：如果为1，表示一致代码段；如果为0，表示非一致代码段
- R：如果为1，表示可读；如果为0，表示不可读
- A：如果为1，表示段曾被访问；如果为0，表示段未被访问

系统段描述符(就是s为0的情况)如下图：

![image](https://c65mael.github.io/myassets/xtmsf.png)



DB位的影响大致如下：

情况一：对CS段的影响

- D=1 采用32位寻址方式

- D =0 采用16位寻址方式

  前缀67 改变寻址方式

情况二：对SS段的影响(这个隐式大概就是间接操作栈的指令，不像mov指令这样直接控制esp或ebp)

- D=1 隐式堆栈访问指令(如: PUSH POP CALL)使用32位堆栈指针寄存器ESP
- D=0 隐式堆栈访问指令(如:PUSH POP CALL)使用16位堆栈指针寄存器SP

情况三：向下拓展的数据段

- D=1段上线为4GB
- D=0段上线为64KB

![image](https://c65mael.github.io/myassets/db.png)

###### 段权限检查

cpu的分级：

![image](https://c65mael.github.io/myassets/cupqx.png)

如何查看程序处于几环：

- CPL(Current Privilege Level)：当前特权级(是几程序就在几环)
- CS和SS中存储的段选择子后2位.(二者相同的都是CPL)

DPL(Descriptor Privilege Level)描述符特权级别：

- DPL存储在段描述符中，规定了访问该段所需要的特权级别是什么。

- 通俗的理解：如果你想访问我，那么你应该具备什么特权。

- 举例说明：

  ```assembly
  mov DS,AX
  ```

  如果AX指向的段`DPL=0`但当前程序的`CPL=3`这行指令是不会成功的!

RPL(Request Privilege Level)请求特权级别举例说明：

- 比较`mov ax,0008`与`mov ax,000B`并且之后均执行`mov ds,ax`的区别

  (区别是8的二进制为`1000`，B的二进制为`1011`，无别就在于最后的两位所代表的RPL不同)

  将段描述指向的是同一个段描述符，但RPL是不一样的.

数据段的权限检查参考如下代码:

- 比如当前程序处于0环,也就是说CPL=0

  ```assembly
  mov ax,000B		//1011也就是RPL = 3 
  mov ds,ax		//ax指向的段描述符的DPL = 0
  ```

数据段的权限检查：

`CPL <= DPL` 并且 `RPL <= DPL` (数值E8比较)

注意：代码段和系统段描述符中的检查方式并不一样,具体请听下回分解。

总结一下：

```
CPL -> CPU当前的权限级别
DPL -> 如果你想访问我,你应该具备什么样的权限
RPL -> 用什么权限去访问一个段
为啥要有RPL?
我们本可以用“读 写”的权限去打开一个文件，但为了避免出错，有些时候我们使用“只读”的权限去打开。就是限制程序权限的使用，尽量规避提权漏洞(吧)。
```

###### 代码的跨段跳转流程

本质就是修改cs寄存器

代码间的跳转(段间跳转 非调用门之类的)

- 段间跳转有2种情况,即要跳转的段是一致代码段还是非一致代码段。

- 同时修改CS与EIP的指令`JMP FAR / CALL FAR / RETF / INT / IRETED` 

  注意：只改变EIP的指令`JMP / CALL / JCC / RET`

远跳(jmp far)的执行流程

jmp 0x20:0x004183D

1. 将前面的段寄存器拆成段选择子：

   ```
   0x20对应二进制形式 0000 0000 0010 0000
   RPL=00
   TI=0
   Index=4
   ```

2. 因为TI=0，所以要查GDT表，找对应Index的段描述符

   这四种情况可以跳转：代码段、调用门、TSS任务段、任务门

3. 权限检查

   如果是非一致代码段，要求：`CPL == DPL` 并且 `RPL <= DPL`

   如果是一致代码段，要求：`CPL>= DPL`

   解释一下：假设我可以用不同的权力去控制别人，我自己的权力和我所使用的权力会有区别。(权限越高越小)

   - `CPL == DPL`：我可以控制与自己的权力一样的人。
   - `RPL <= DPL`：我所使用大的权力，自然的可以控制权力比我小的人。
   - `CPL >= DPL`：我自己的权力小于别人的权力。

   **总结**：

   对于一致代码段:也就是共享的段

   - 特权级高的程序不允许访问特权级低的数据:核心态不允许访问用户态的数据
   - 特权级低的程序可以访问到特权级高的数据,但特权级不会改变：用户态还是用户态

   对于普通代码段:也就是非一致代码段

   - 只允许同级访问
   - 绝对禁止不同级别的访问:核心态不是用户态,用户态也不是核心态.

   **直接对代码段进行JMP或者CALL的操作，无论目标是一致代码段还是非一致代码段, CPL都不会发生改变。如果要提升CPL的权限，只能通过调用门。**

4. 加载段描述符

   通过上面的权限检查后，CPU会将段描述符加载到CS段寄存器中。

5. 代码执行

   CPU将 `CS.Base + Offset` (就是冒号后面的值)的值写入EIP 然后执行CS:EIP处的代码，段间跳转结束。

总结：

1. 为了对数据进行保护,普通代码段是禁止不同级别进行访问的。用户态的代码不能访问内核的数据,同样,内核态的代码也不能访问用户态的数据。
2. 如果想提供一些通用的功能，而且这些功能并不会破坏内核数据，那么可以选择一致代码段,这样低级别的程序可以在不提升CPL权限等级的情况下即可以访问。
3. 如果想访问普通代码段,只有通过'调用门'等提示CPL权限,才能访问。

###### 长调用与短调用

短调用：

- 指令格式：call 立即数 / 寄存器 / 内存
- 把call当前地址的下一个地址入栈，然后将eip跳到call后面跟的地址。执行到ret后返回(到入栈的地址)
- 发生改变的寄存器: esp eip

长调用(跨段不提权)：

- 指令格式: CALL CS:EIP (EIP是废弃的)

- 先入栈调用者的CS段选择子，再把当前地址的下一个地址入栈(返回地址)

  |  执行前  |      |       执行后       |
  | :------: | :--: | :----------------: |
  |          |      |                    |
  |          |      |      返回地址      |
  |          |      | 调用者的CS段选择子 |
  | xxxxxxxx |      |      xxxxxxxx      |

- 发生改变的寄存器: ESP EIP CS

长调用(跨段提权)：

- 指令格式: CALL CS:EIP (EIP是废弃的)

- 执行前的栈是3环的栈，执行后是0环的栈(CPL)，所以是在0环的栈里面压入的一系列参数。

  | 执行前(在3环) |      | 执行后(在0环) |
  | :-----------: | :--: | :-----------: |
  |               |      |               |
  |               |      |               |
  |               |      |               |
  |               |      |   返回地址    |
  |               |      |   调用者CS    |
  |               |      |   调用者ESP   |
  |               |      |   调用者SS    |
  |   xxxxxxxx    |      |   xxxxxxxx    |

总结：

1. 跨段调用时，一旦有权限切换，就会切换堆栈。
2. CS的权限一旦改变，SS的权限也要随着改变，CS与SS的等级必须一样。
3. `JMP FAR`只能跳转到同级非一致代码段，但`CALL FAR`可以通过调用门提权，提升CPL的权限。

###### 调用门

门描述符是系统段描述符的一类。所以门描述符`S=0`，`TYPE=1100`

![image](https://c65mael.github.io/myassets/dym.png)

调用门执行流程

- 指令格式：CALL CS:EIP(EIP是废弃的)

- 执行步骤：

  1. 根据CS的值查GDT表，找到对应的段描述符这个描述符是一个调用门。
  2. 在调用门描述符中存储另一个代码段的选择子。
  3. 选择子指向的段 `段.Base+ 偏移地址` 就是真正要执行的地址。、

- 结构说明：

  | 字段              | 内容                                                         |
  | ----------------- | ------------------------------------------------------------ |
  | offset in segment | 要跳转的函数的地址，或者是要跳转的地址  (两段组成了32位的地址，前高位后低位) |
  | segment selector  | 段选择子，要变成的段选择子（提权的关键）                     |
  | Param Count       | 函数参数个数                                                 |
  | 高位5-7           | 固定的三个0                                                  |
  | Type              | 系统段只能是1100（10进制的12）                               |
  | 高12地址          | 就是段描述符的S字段，就系统调用的必须是0                     |
  | DPL               | 肯定赋值为3呀，这样ring3才能。                               |
  | p                 | 和段描述符一样表示该段是否有效，当P为0时无效，1时有效。      |

调用门总结：

1. 当通过门，权限不变的时候，只会PUSH两个值: CS返回地址新的CS的值由调用门决定。
2. 当通过门，权限改变的时候，会PUSH四个值：`SS ESP CS 返回地址` 新的CS的值由调用门决定 新的SS和ESP由TSS提供。
3. 通过门调用时，要执行哪行代码有调用门决定，但使用`RETF`返回时，由堆栈中压人的值决定，这就是说，进门时只能按指定路线走，出门时可以翻墙（只要改变堆栈里面的值就可以想去哪去哪）。
4. 可不可以再建个门出去呢？也就是用Call 当然可以了 `前门进 后门出`。

###### 中断门

- Windows没有使用调用门，但是使用了中断门：<1> 系统调用	<2> 调试

- 调用门会去查GDT表，中断门却回去查IDT表(中断描述符表)。

  **IDT即中断描述符表，同GDT一样，IDT也是由一系列描述符组成的，每个描述符占8个字节。但要注意的是，IDT表中的第一个元素不是NULL。**

  - IDT表可以包含3种门描述符:	任务门描述符	中断门描述符	陷阱门描述符

  - 指令格式：`INT N (N为中断门索引号)`

  - 中断门如下：（图中的`D`表示是否为`32位`，如果是则为`1`）

    ![image](https://c65mael.github.io/myassets/zdm.png)

  - 与调用门类似会产生如下的情况：

    1. 在没有权限切换时，会向堆栈顺次压入`EFLAG`、`CS`和`EIP`；如果有权限切换，会向堆栈顺次压入`SS`、`ESP`、`EFLAG`、`CS`和`EIP`。
    2. `CPU`会索引到`IDT`表。后面的`N`表示查`IDT表`项的下标。对比调用门，中断门没有了`RPL`，故`CPU`只会校验`CPL`。
    3. 在中断门中,不能通过`RETF`返回，而应该通过`IRET`/`IRETD`指令返回。

###### 陷阱门

陷阱门的结构和中断门结构几乎一样，只是Type域不同而已（图中的`D`表示是否为`32位`，如果是则为`1`）

![image](https://c65mael.github.io/myassets/xjm.png)

与中断门的区别，中断门执行时，将`IF位`清零,但陷阱门不会。

解释：**如果IF位为零，则不再接收可屏蔽中断。**

1. **可屏蔽中断**就像是你房间里的门铃，你可以选择要不要打开门去接待访客。当你不想被打扰时，你可以把门铃关掉，这样就不会有人来敲门。可屏蔽中断就是你能够控制的，你可以决定何时接受这些中断，何时把它们忽略掉。
2. **不可屏蔽中断**就像是火警响了，这是一个紧急情况，你不能选择不管它。无论你在做什么，火警响了你都得立刻采取行动，确保安全。不可屏蔽中断就是这样，它们不受你的控制，系统必须对它们做出响应，因为它们可能表示了一个严重的问题。

###### 任务段

我们回顾一下之前所学内容，在调用门、中断门与陷阱门中，一旦出现权限切换，那么就会有堆栈的切换。而且，由于`CS`的`CPL`发生改变，也导致了`SS`也必须要切换。切换时，会有新的`ESP`和`SS`从哪里来的呢？那就是任务状态段提供的。任务状态段简称任务段，英文缩写为`TSS`，`Task-state segment`。

  `TSS`是一块内存，大小为`104`字节，内存结构如下图所示：

![image](https://c65mael.github.io/myassets/rwd.png)

TSS 的作用

  `Intel`的设计`TSS`目的，用官方的话说就是实现所谓的任务切换。`CPU`的任务在操作系统的方面就是线程。任务一切换，执行需要的环境就变了，即所有寄存器里面的值，需要保存供下一次切换到该任务的时候再换回去重新执行。
  说到底，**`TSS`的意义就在于可以同时换掉一堆寄存器**。本质上和所谓的任务切换没啥根本联系。而操作系统嫌弃`Intel`的设计过于麻烦，自己实现了所谓的任务切换，即线程切换。(应该有点像srop的感觉吧)

CPU 如何找到 TSS

  `TSS`是一个内存块，并不在`CPU`中，那么它是怎样找到正确的`TSS`呢？那就是之前提到的`TR`段寄存器，而`TR`寄存器里面的值是从段描述符里面加载的，也就是从`GDT`表里面的`TSS`段描述符加载的。`CPU`通过`TR`寄存器索引`TSS`是示意图如下图所示：

![image](https://c65mael.github.io/myassets/tr.png)

TSS段描述符

  `TSS段描述符`的结构和普通的段描述符没啥区别，就是系统段描述符，如果`Type`为9(B=0 `1001`)，则这个`TSS段描述符`没有加载到`TR`寄存器中，如果`Type`为B(B=1 `1011`)，就是加载了，如下图所示：

![image](https://c65mael.github.io/myassets/tss.png)

TR寄存器读写

1. 加载TSS
   - 指令：`LTR`
   - 说明：用`LTR`指令去装载，仅仅是改变`TR`寄存器的值（96位），并没有真正改变`TSS`。`LTR`指令只能在系统层使用，加载后`TSS`段描述符会状态位会发生改变。
2. 读取TR寄存器
   - 指令：`STR`
   - 说明：如果用`STR`去读的话，只读了`TR`的16位，即选择子。

修改TR寄存器途径

1. 在0环可以通过LTR指令去修改TR寄存器。
2. 在3环可以通过CALL FAR或者JMP FAR指令来修改。用JMP去访问一个任务段的时候，如果是TSS段描述符，先修改TR寄存器，在用TR.Base指向的TSS中的值修改当前的寄存器。

###### 任务门

IDT 中断描述符表:

IDT表可以包含3种门描述符：任务门描述符	中断门描述符	陷阱门描述符

任务门结构:

![image](https://c65mael.github.io/myassets/rwm.png)

执行过程：

1. 通过`INT N`的指令进行触发任务门
2. 查`IDT`表，找到任务门描述符
3. 通过任务门描述符，查`GDT`表，找到`TSS`段描述符
4. 使用`TSS`段中的值修改`TR`寄存器
5. `IRETD`返回

###### 10-10-12分页

- 虚拟地址空间是什么？

  每个进程都有一个“假想的”内存空间，大小是4GB。这并不是说每个进程都真的占用了4GB的内存，而是操作系统为每个进程提供了一个这样的“地址地图”。可以把它看作是一个巨大的图书馆目录，这个目录告诉进程可以在这些地址上“存放”数据。

- 这些虚拟地址就像地图上的标记，它们并不直接对应计算机硬件中的实际内存位置。实际的物理内存地址是计算机真正用来存储数据的地方。可以把物理地址想象成图书馆中的实际书架位置。

一个进程都有4GB的虚拟地址空间，它们并不是真正的地址，而是个索引。它通过某种方式进行转换，从而指向真正的物理地址：

![image](https://c65mael.github.io/myassets/nc.png)

如下指令：

`MOV eax,dword ptr ds:[0x12345678]`

其中，`0x12345678` 是有效地址，`ds.Base + 0x12345678`是线性地址

解释：这个`线性地址`实际上是不存在的，在执行时`CPU`会将`线性地址`转化为`物理地址`

![image](https://c65mael.github.io/myassets/nclz.png)

10-10-12拆分：假设我们有一个32位的虚拟地址。10-10-12拆分是把这个32位的地址分成三个部分，前10位中间10位和后12位

CPU得到线性地址之后经过10-10-12拆分成三份去找物理地址，CPU会去找CR3寄存器，CR3寄存器里面存的地址指向一个4kb的页这就是它的第一级，拆分的第一个10位决定了在第一级中的什么位置；这个位置里面的值又指向一个4kb的页这就是它的第二级，拆分的第二个10位决定了在第二级中的什么位置，而第三个12位决定了在物理页中的什么位置。

每个进程都有一个`CR3`，准确的说是都一个`CR3`的值。`CR3`本身是个寄存器，一核一套寄存器。`CR3`里面放的是一个真正的物理地址，指向一个物理页，一共`4096字节`，如下图所示：

![image](https://c65mael.github.io/myassets/cr3.png)

对于`10-10-12`分页来说，线性地址对应的物理地址是有对应关系的，它被分成了三个部分，每个部分都有它具体的含义。线性地址分配的结构如下图所示：

![image](https://c65mael.github.io/myassets/101012.png)

第一个部分指的是`PDE`在`PDT`的索引，第二部分是`PTE`在`PTT`的索引，第三个部分是在PTE指向的物理页的偏移。`PDT`被称为页目录表，`PTT`被称为页表。`PDE`和`PTE`分别是它们的成员，大小为4个字节。接下来将详细介绍每一个部分是咋用的。

###### PDE与PTE

![image](https://c65mael.github.io/myassets/pdepte.png)

分页并不是由操作系统决定的，而是由`CPU`决定的。只是操作系统遵守了`CPU`的约定来实现的。物理页是什么？物理页是操作系统对可用的物理内存的抽象，按照`4KB`的大小进行管理（`Intel`是按照这个值做的，别的`CPU`就不清楚了），和真实硬件层面上的内存有一层的映射关系，这个不是保护模式的范畴，故不介绍。

###### PDE与PTE属性

![image](https://c65mael.github.io/myassets/pdeptejg.png)

`物理页的属性 = PDE属性 & PTE属性`

P 位

  表示`PDE`或者`PTE`是否有效，如果有效为`1`，反之为`0`。

R/W 位

  如果`R/W = 0`，表示是只读的，反之为可读可写。

U/S 位

  如果`U/S = 0`，则为特权用户（super user），即非3环权限。反之，则为普通用户，即为3环权限。

PS位

  这个位只对`PDE`有意义。如果`PS == 1`，则`PDE`直接指向物理页，不再指向`PTE`，低22位是页内偏移。它的大小为`4MB`，俗称“大页”。

A 位

  是否被访问，即是否被读或者写过，如果被访问过则置`1`。即使访问了一字节也是1。

D 位

  脏位，指示是否被写过。若没有被写过为`0`，被写过为`1`。

###### 页目录表基址

如果系统要保证某个线性地址是有效的，必须为其填充正确的`PDE`与`PTE`，如果我们想填充`PDE`与`PTE`那么必须能够访问。有的人会想，直接拿`CR3`去填写就行了，还需要页目录表基址干嘛？这里我强调一下：操作系统只能用线性地址，不能用物理地址。`CR3`存储的是物理地址，这个是给`CPU`看的，不是给操作系统看的。操作系统访问它就必须知道它的线性地址才行。`CPU`可不帮我们挂物理页，它做不到这点，只能提供要求标准，而操作系统按照标准进行办事。于是乎页目录表基址与页表基址这两个东西就出现了。
  通过页目录表基址，操作系统可以帮我们程序挂上正确的`PDE`，通过页表基址挂上正确的`PTE`，然后指向正确的物理页。

1. 通过0xC0300000找到的物理页就是页目录表，这个物理页即是页目录表本身也是页表
2. 页目录表是一张特殊的页表,每一项PTE指向的不是普通的物理页，而是指向其他的页表
3. 结论：0xC0300000存储的值就是PDT，如果我们要访问第N个PDE，那么有如下公式:0xC0300000 +N*4

![image](https://c65mael.github.io/myassets/xml.png)





















### 驱动

