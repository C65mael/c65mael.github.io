---
title: Homework
author: C65mael
date: 2024-06-04
category: Jekyll
layout: post
---

<p align="center">Liberty🗽, Equality⚖️, Fraternity💕</p>

### 保护模式

#### 段描述符与段选择子

1. 在windbg中查看GDT表的基址和长度

   查看xp的GDT表

   ```asm
   0: kd> r gdtr
   gdtr=8003f000		#基址
   0: kd> r gdtl
   gdtl=000003ff		#长度
   ```

2. 分别使用`dd dq`指令查看GDT表

   ```
   0: kd> dd 8003f000
   ReadVirtual: 8003f000 not properly sign extended
   8003f000  00000000 00000000 0000ffff 00cf9b00
   8003f010  0000ffff 00cf9300 0000ffff 00cffb00
   8003f020  0000ffff 00cff300 200020ab 80008b04
   8003f030  f0000001 ffc093df 00000fff 0040f300
   8003f040  0400ffff 0000f200 00000000 00000000
   8003f050  27000068 80008955 27680068 80008955
   8003f060  2f40ffff 00009302 80003fff 0000920b
   8003f070  700003ff ff0092ff 0000ffff 80009a40
   0: kd> dq 8003f000
   ReadVirtual: 8003f000 not properly sign extended
   8003f000  00000000`00000000 00cf9b00`0000ffff
   8003f010  00cf9300`0000ffff 00cffb00`0000ffff
   8003f020  00cff300`0000ffff 80008b04`200020ab
   8003f030  ffc093df`f0000001 0040f300`00000fff
   8003f040  0000f200`0400ffff 00000000`00000000
   8003f050  80008955`27000068 80008955`27680068
   8003f060  00009302`2f40ffff 0000920b`80003fff
   8003f070  ff0092ff`700003ff 80009a40`0000ffff
   
   ```

3. 段描述符查分实验：拆5个

   ![image](https://c65mael.github.io/myassets/xuanzazi.png)

   - 00cf9b00`0000ffff

     ```
     Base=00 00
     23~20 [c]= 1101
     G=1
     D/B=1
     AVL=1
     Limit=f ffff
     16~12 [9]=1001
     p=1
     DPL=00
     s=1
     Type=1011
     Address=0000
     ```

   - 00cf9300`0000ffff

     ```
     Base=00 00
     23~20 [c]= 1101
     G=1
     D/B=1
     AVL=1
     Limit=f ffff
     16~12 [9]=1001
     p=1
     DPL=00
     s=1
     Type=0011
     Address=0000
     ```

   - 00cffb00`0000ffff

     ```
     Base=00 00
     23~20 [c]= 1101
     G=1
     D/B=1
     AVL=1
     Limit=f ffff
     16~12 [f]=1111
     p=1
     DPL=11(3)
     s=1
     Type=1011
     Address=0000
     ```

   - 00cff300`0000ffff

     ```
     Base=00 00
     23~20 [c]= 1101
     G=1
     D/B=1
     AVL=1
     Limit=f ffff
     16~12 [f]=1111
     p=1
     DPL=11(3)
     s=1
     Type=0011
     Address=0000
     ```

   - 80008b04`200020ab

     ```
     Base=80 04
     23~20 [0]= 0000
     G=0
     D/B=0
     AVL=0
     Limit=0 20ab
     16~12 [8]=1000
     p=1
     DPL=00
     s=0
     Type=1011
     Address=2000
     ```

4. 段选择子拆分实验：

   ![image](https://c65mael.github.io/myassets/xz.png)

   - 23

     ```
     0010 0011
     RPL=11(3)
     TI=0
     Index=0010 0(4)
     ```

   - 2B

     ```
     0010 1011
     RPL=11(3)
     TI=0
     Index=0010 1(5)
     ```

   - 30

     ```
     0011 0000
     RPL=00
     TI=0
     Index=0011 0(6)
     ```

   - 3B

     ```
     0011 1011
     RPL=11(3)
     TI=0
     Index=0011 1(7)
     ```

   - 53

     ```
     0101 0011
     RPL=11(3)
     TI=0
     Index=0101 0(10)
     ```

5. 使用LES，LDS等指令修改段寄存器

   `LES ebx, [SI]`就是高两字节给es，低4字节给ebx

#### 段描述符属性P位_G位

1. 查GDT表，如何快速确定哪个描述符的P位为0或者为1

   可以检测段描述符的第5位，如果大于等于8则P为1，否则P为0

   比如：00cf**9**b00`0000ffff

2. 查GDT表，如何快速确定哪个描述符的G位为0或者为1

   可以检测段描述符的第3位，如果大于等于8则G为1，否则G为0

   比如：00**c**f9b00`0000ffff

3. 将段描述符填写到段寄存器结构体中（每人填一个）(段选择子：23 2B 30 3B 53)

   比如我用xp的GDT表做一下：

   ```
   8003f000  00000000`00000000 00cf9b00`0000ffff
   8003f010  00cf9300`0000ffff 00cffb00`0000ffff
   8003f020  00cff300`0000ffff 80008b04`200020ab
   8003f030  ffc093df`f0000001 0040f300`00000fff
   8003f040  0000f200`0400ffff 00000000`00000000
   8003f050  80008955`27000068 80008955`27680068
   8003f060  00009302`2f40ffff 0000920b`80003fff
   8003f070  ff0092ff`700003ff 80009a40`0000ffff
   ```

   - ```
     23
     0010 0011
     Index=00100(4)    --> 00cff300`0000ffff
     
     00cff300`0000ffff
     Base=00 00
     23~20 [c]= 1101
     G=1
     D/B=1
     AVL=1
     Limit=f ffff
     16~12 [f]=1111
     p=1
     DPL=11(3)
     s=1
     Type=0011
     Address=0000
     ```

#### 段描述符属性S位_TYPE域

![image](https://c65mael.github.io/myassets/type.png)

1. 判断哪些是系统段描述符?哪些是代码或者数据段描述符?

   因为DPL的值只可能是全1或全0，所以16~12位如果是数据段或代码段的话只能为f(1111)或9(1001)。**那么在段描述符中找第五位，如果是f或9就是数据段或代码段。**

2. 判断哪些是代码段描述符？哪些是数据段描述符？

   因为TYPE域的第11位只可能是1或0，而且全为1是代码段；全为0是数据段。**那么在段描述符中第六位大于8就是代码段，小于8就是数据段。**

3. 查分几个数据段: E W A

   ```
   00009302`2f40ffff 
   Base=00 02
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 ffff
   16~12 [9]=1001
   p=1
   DPL=00(0)
   s=1
   Type=0011    -->可读写，访问过
   Address=2f40
   
   0000920b`80003fff
   Base=00 0b
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 3fff
   16~12 [9]=1001
   p=1
   DPL=00(0)
   s=1
   Type=0010    -->可读写
   Address=8000
   ```

   

4. 查分几个代码段:C R A

   ```
   80009a80`0000ffff
   Base=80 80
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 ffff
   16~12 [9]=1001
   p=1
   DPL=00(0)
   s=1
   Type=1010    -->可读执行
   Address=0000
   
   00cffb00`0000ffff
   Base=00 00
   23~20 [c]= 1100
   G=1
   D/B=1
   AVL=0
   Limit=f ffff
   16~12 [f]=1111
   p=1
   DPL=11(3)
   s=1
   Type=1011    -->可读执行，访问过
   Address=0000
   ```

   

5. 查分几个系统段描述符

   ```
   80008955`27000068
   Base=80 55
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 0068
   16~12 [8]=1000
   p=1
   DPL=00(0)
   s=0
   Type=1001    -->386以上CPU的TSS，type第3位为1
   Address=2700
   
   80008955`27680068
   Base=80 55
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 0068
   16~12 [8]=1000
   p=1
   DPL=00(0)
   s=0
   Type=1001    -->386以上CPU的TSS，type第3位为1
   Address=2768
   ```

#### 段权限检查

1. 在3环能加载的数据段有哪些？

   `CPL=3`是最低权限，那么只能加载更低权限或相同权限的数据段，所以可以加载`DPL=3`的数据段

2. 在0环能加载的数据段有哪些?

   `CPL=0`，和第一题一样，所以可以加载`DPL=0 / 1 / 2 / 3`的数据段

3. 详细描述这下面代码的执行过程:

   ```asm
   mov ax,0x23    #0x23=0010 0011那么rpl为11(3)，index=00100(4)，在GDT表中找索引为4，接着去检查该段描述符是否为有效，然后看S位是否是数据/代码段还是系统段，然后再看TYPE域，比如我找的为00cff300`0000ffff，dpl就为3
   
   mov ds,ax
   ```

#### 代码间的跳转

**后面的实验虚拟机一定要使用单核单处理器，不然实验会失败的！！！**

1. 记住代码段间跳转的执行流程

   ```
   1、段选择子拆分
   2、查表得到段描述符
   3、权限检查
   4、加载段描述符
   5、代码执行
   ```

2. 自己实现一致代码段的段间跳转。

   要求：`CPL >= DPL`

   1. 通过windbg的指令`eq 地址 内容`(`eq 8003f048 00c9fc00 0000ffff`)，构建段描述符`00C9FC00·0000FFFF`，并且记好索引位置
   2. 执行指令`jmp far xx:xxxxxxxx`
   3. 如果成功就会修改`cs`和`eip`

3. 自己实现非一致代码段的段间跳转。

   要求： `CPL == DPL` 并且 `RPL <= DPL`

#### 调用门

1. 自己实现调用门（提权、无参数、EAX、ECX。存不存？）

   - 调用门描述符为：`0000EC00·00080000`

   - 代码如下：

     ```c
     #include <windows.h>
     #include <stdio.h>
     void __declspec(naked) GetRegister() {
     	_asm {
     		int 3
     		retf
     	}
     }
     void main()
     {
     	char buff[6];
     	*(DWORD*)&buff[0] = 0x12345678; // EIP, 废弃
     	*(WORD*)&buff[4] = 0x48; // 段选择子
     	_asm {
     		call far fword ptr[buff]
     	}
     	getchar();
     }
     ```

   - 在windbg中可以断下

   - 发现SS、ESP、CS寄存器都发生了变化

2. 自己实现调用门（提权、有参数）

   需要看一下调用门：

   ![image](https://c65mael.github.io/myassets/dym.png)

   - 调用门描述符为：`0000EC03·00080000`

   - 代码如下：

     ```c
     #include <windows.h>
     #include <stdio.h>
     
     DWORD x;
     DWORD y;
     DWORD z;
     
     void __declspec(naked) GetRegister() {
         _asm {
     		pushad
     		pushfd
     
     		mov eax,[esp+0x24+0x8+0x8]
     		mov dword ptr ds:[x],eax
     		mov eax,[esp+0x24+8+4]
     		mov dword ptr ds:[y],eax
     		mov eax,[esp+0x24+8+0]
     		mov dword ptr ds:[z],eax
     
     		popfd
     		popad
     		retf 0xC
         }
     }
     
     void Printfall()
     {
     	printf("%x %x %x\n",x,y,z);
     }
     
     
     void main()
     {
         char buff[6];
         *(DWORD*)&buff[0] = 0x12345678; // EIP, 废弃
         *(WORD*)&buff[4] = 0x48; // 段选择子
         _asm {
     		push 1
     		push 2
     		push 3
     		call far fword ptr[buff]
         }
         Printfall();
         getchar();
     }
     ```

3. 如何通过实验论证0环堆栈存储哪些数据，顺序是什么？

4. 这几行代码有什么意义？是必须的吗？

   ```asm
   pushad
   pushfd
   ……
   popfd
   popad
   ```

   用于保存和恢复寄存器的状态，也就是保护现场，防止其他寄存器被修改。

5. 这几行代码在做什么？

   ```asm
   mov eax,[esp+0x24+0x8+0x8]
   mov eax,[esp+0x24+0x8+0x8]
   mov eax,[esp+0x24+8+0]
   ```

   访问我在栈中存的参数，查看栈的内容如下：

   ```asm
   kd> dd b1ba6da0
   ReadVirtual: b1ba6da0 not properly sign extended
   b1ba6da0  00000212 0012ff80 00000000 0012ff80
   b1ba6db0  b1ba6dc4 7ffde000 00380df8 00000000
   b1ba6dc0  cccccccc 004010ee 0000001b 00000003
   b1ba6dd0  00000002 00000001 0012ff1c 00000023
   b1ba6de0  805470de b12221f0 8a31b970 00000000
   b1ba6df0  0000027f 00000000 00000000 00000000
   b1ba6e00  00000000 ffff0000 00001f80 00000000
   b1ba6e10  00000000 00000000 00000000 00000000
   ```

   那么，`esp+0x24+8`就是`b1ba6dcc`的位置，就是访问参数3，2，1。

   更直观一点，不加`pushad，pushfd`，如下：

   ```asm
   kd> dd bad7fdc4
   ReadVirtual: bad7fdc4 not properly sign extended
   bad7fdc4  004010ee 0000001b 00000003 00000002    #004010ee是返回地址，0000001b是旧cs，0012ff1c是旧esp，23是旧ss
   bad7fdd4  00000001 0012ff1c 00000023 805470de
   bad7fde4  ba60eb85 8a25cd00 00000000 0000027f
   bad7fdf4  00000000 00000000 00000000 00000000
   bad7fe04  ffff0000 00001f80 00000000 00000000
   bad7fe14  00000000 00000000 00000000 00000000
   bad7fe24  00000000 00000000 00000000 00000000
   bad7fe34  00000000 00000000 00000000 00000000
   ```


#### 测试

**要求：代码正常执行不蓝屏**

1. 构造一个调用门，实现3环读取高2G内存。

   - 调用门描述符为：`0000EC00·00080000`

   - 代码如下：

     ```c
     #include <windows.h>
     #include <stdio.h>
     
     DWORD x;
     DWORD y;
     DWORD z;
     
     void __declspec(naked) GetRegister() {
         _asm {
     		pushad
     		pushfd
     
     		mov eax,0x8003f008
     		mov ebx,[eax]
              mov x,ebx
              mov ecx,4
              add eax,ecx
              mov ebx,[eax]
              mov y,ebx
              add eax,ecx
              mov ebx,[eax]
              mov z,ebx
     
     		popfd
     		popad
     		retf
         }
     }
     
     void Printfall()
     {
     	printf("%x %x %x\n",x,y,z);
     }
     
     
     void main()
     {
         char buff[6];
         *(DWORD*)&buff[0] = 0x12345678; // EIP, 废弃
         *(WORD*)&buff[4] = 0x48; // 段选择子
         _asm {
     		call far fword ptr[buff]
         }
         Printfall();
         getchar();
     }
     ```

     ```
     输出结果：ffff cf9b00 ffff
     ```

2. 在第一题的基础上进行修改，实现通过翻墙的方式返回到其他地址。

   - 调用门描述符为：`0000EC00·00080000`

   - 代码如下：

     ```c
     #include <windows.h>
     #include <stdio.h>
     
     void __declspec(naked) GetRegister() {
         _asm {
     		pop eax
              mov eax,0x401070     //函数Printfall()的地址
              push eax
     		retf
         }
     }
     
     void Printfall()
     {
     	printf("okokokokokokok");
     }
     
     void main()
     {
         char buff[6];
         *(DWORD*)&buff[0] = 0x12345678; // EIP, 废弃
         *(WORD*)&buff[4] = 0x48; // 段选择子
         _asm {
     		call far fword ptr[buff]
         }
         getchar();
     }
     ```

     ```
     输出结果：okokokokokokok
     ```

3. 在第一题的基础上进行修改，在门中再建一个门跳转到其他地址。

   - 调用门描述符为：`0000EC00·00080000`

   - 代码如下：

     ```c
     #include <windows.h>
     #include <stdio.h>
     
     int x=0;
     int y=0;
     
     char buff[6] = {0,0,0,0,0x48,0};
     char buff1[6] = {0,0,0,0,0x90,0};
     
     void __declspec(naked) GetRegister() {
         _asm {
     		mov x,1
     		mov eax,0x00081070
     		mov ebx,0x8003f090
     		mov [ebx],eax
     		mov eax,0x0040ec00
     		mov ebx,0x8003f094
     		mov [ebx],eax
              call far fword ptr[buff1]
     		retf
         }
     }
     
     void __declspec(naked) two() {
         _asm {
     		mov y,1
     		retf
         }
     }
     
     void main()
     {
         _asm {
     		call far fword ptr[buff]
         }
         printf("%x %x",x,y);
         getchar();
     }
     ```

     ```
     输出结果：1 1
     ```

#### 中断门

1. 自己实现中断门

   - 调用门描述符为：`0000EE00·00080000`

   - 代码如下：

     ```c
     #include<stdio.h>
     #include<windows.h>
      
     DWORD H
      
     void __declspec(naked) test(){
     	__asm{
     		pushad
     		pushfd
     		mov eax,0x8003f008
     		mov ebx,[eax]
              mov H,ebx
     		popfd
     		popad
     		iretd
     	}
     }
      
      
     int main(){	
     	__asm{
     		int 0x20;
     	}
     	printf("%X", H);
     	return 0;
     }
     ```

     ```
     输出结果：FFFF
     ```

2. 在调用门中实现使用IRETD返回

   - 调用门描述符为：`0000EC00·00080000`

   - 代码如下：

     ```c
     #include <windows.h>
     #include <stdio.h>
     
     char buff[6] = {0,0,0,0,0x48,0};
     
     void __declspec(naked) GetRegister() {
         _asm {
     		pop eax
              pop ebx
              mov ecx,0x11111111
              push ecx
              push ebx
              push eax
     		iretd
         }
     }
     
     void main()
     {
         _asm {
     		call far fword ptr[buff]
         }
         printf("okokokokokokok");
         getchar();
     }
     ```

     ```
     输出结果：okokokokokokok
     ```

3. 在中断门中实现用RETF返回

   - 调用门描述符为：`0000EE00·00080000`

   - 代码如下：

     ```c
     #include<stdio.h>
     #include<windows.h>
     
     void __declspec(naked) test(){
     	__asm{
     		pop eax
     		pop ebx
     		popfd
     		push ebx
     		push eax
     		retf
     	}
     }
      
      
     int main(){	
     	__asm{
     		int 0x20;
     	}
     	printf("okokokokokokok");
         getchar();
     	return 0;
     }
     ```

     





