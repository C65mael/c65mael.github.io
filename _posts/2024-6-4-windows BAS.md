---
title: Windows BAS
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

**特性**：

1. 带有 * 的变量类型的标准写法：变量类型 * 变量名

2. 任何类型都可以带 * ，加上 * 以后是新的类型

3.  * 可以是任意多个

4. 带 * 类型的变量赋值时只能使用 “完整写法” .

   带 * 类型的变量宽度永远是4字节、无论类型是什么，无论有几个 * .

5. 不带 * 类型的变量，++或者--  都是假1 或者减1
   带 * 类型的变量，可是进行++ 或者 --的操作
   带* 类型的变量，++ 或者 -- 新增(减少)的数量是去掉一个 * 后变量的宽度

6. 带 * 类型的变量可以加、减一个整数，但不能乘或者除.

   带 * 类型变量与其他整数相加或者相减时：

   - 带 * 类型变量 + N = 带 * 类型变量 + N * (去掉一个 * 后类型的宽度)
   - 带 * 类型变量 - N = 带 * 类型变量 - N * (去掉一个 * 后类型的宽度)

7. 两个类型相同的带 * 类型的变量可以进行减法操作.

   想减的结果要除以去掉一个 * 的数据的宽度.

8. 带 * 的变量，如果类型相同，可以做大小的比较。

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

- 什么是封装：将函数定义到结构体内部,就是封装。
- 什么是类：带有函数的结构体，称为类。
- 什么是成员函数：结构体里面的函数，称为成员函数。

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

1. this指针是编译器默认传入的，通常都会使用ecx进行参数的传递。
2. 成员函数都有this指针，无论是否使用。
3. this指针不能做++--等运算,不能重新被赋值。
4. this指针不占用结构体的宽度。

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

1. 与类同名且没有返回值
2. 创建对象的时候执行/主要用于初始化
3. 可以有多个(最好有一个无参的),称为重载其他函数也可以重载
4. 编译器不要求必须提供

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

1. 只能有一个析构函数，不能重载
2. 不能带任何参数(因为是系统帮我们调用的，自然就没有参数了)
3. 不能带返回值
4. 主要用于清理工作
5. 编译器不要求必须提供

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

1. 什么是继承？继承就是数据的复制
2. 为什么要用继承？减少重复代码的编写
3. Person 称为父类或者基类(要复制)
4. Teacher称为子类或者派生类

区别：

1. 不局限与父类的继承：

   ```c
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

2. 多重继承：

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

   ![image](https://c65mael.github.io/myassets/image-20231230134009-b93hjmf.png)

###### new与delete

new = malloc + 构造函数

delete=free+析构函数

`delete p`​是只删除一个堆块，`delete[] p`​是将所有的堆块全部删除(都执行析构函数~)

###### 引用类型

```c++
Base* p=&b;
Base& ref = b;								<--------就是给对象附一个别名
ref = 4;									<--------实际上是对b进行赋值
```

1. 引用必须赋初始值,且只能指向一个变量,“从一而终”。
2. 对引用赋值,是对其指向的变量赋值,而并不是修改引用本身的值。
3. 对引用做运算,就是对其指向的变量做运算,而不是对引用本身做运算。
4. 引用类型就是一个“弱化了的指针”。
5. 加const之后为常引用，不可改引用的值。

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

**多态**

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

1. 就是相当于y就是x的一个副本，本质是内存的复制。
2. 只复制成员的值，不复制成员是指针时指针指向的值

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

1. 彼此没有特权,互相独立
2. 内部类受protected/private影响

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

1. 禁止对象随便被创建
2. 保证对象只有一份存在

**总结：**

1. 出现在类体外的函数定义不能指定关键字static;
2. 静态成员之间可以相互访问，包括静态成员函数访问静态数据成员和访问静态成员函数；
3. 非静态成员函数可以任意地访问静态成员函数和静态数据成员；
4. 静态成员函数不能访问非静态成员函数和非静态数据成员；
5. 调用类的静态成员函数的两种方式
