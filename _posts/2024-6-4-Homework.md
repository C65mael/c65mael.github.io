---
title: Homework
description: 课后练习题
date: 2024-06-04 00:00:00
categories:
- Experiment
---

### PE结构

#### 内存分配—文件读写

- 将记事本的.exe文件读取到内存，并返回读取后在内存中的地址
- 将内存中的数据存储到一个文件中，(.exe格式)，然后双击打开，看是否能够使用

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

   - 中断门描述符为：`0000EE00·00080000`

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

   - 中断门描述符为：`0000EE00·00080000`

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


#### 陷阱门

- 构造陷阱门
  - 陷阱门描述符为：`0000EF00·001b0000`
  
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
  
    ```
    输出结果：okokokokokokok
    ```

#### 任务段

1. 找出GDT表中所有的TSS段描述符

   ```
   8003f000  00000000`00000000 00cf9b00`0000ffff
   8003f010  00cf9300`0000ffff 00cffb00`0000ffff
   8003f020  00cff300`0000ffff 80008b04`200020ab
   8003f030  ffc093df`f0000001 0040f300`00000fff
   8003f040  0000f200`0400ffff 00000000`00000000
   8003f050  80008955`27000068 80008955`27680068
   8003f060  00009302`2f40ffff 0000920b`80003fff
   8003f070  ff0092ff`700003ff 80009a40`0000ffff
   8003f080  80009240`0000ffff 00009200`00000000
   ```

   结尾为68，`8003f050`与`8003f058`

2. 实现任务切换

   注：使用指令`!process 0 0`获取`Cr3`的值（对应调试程序的`Cr3`，比如`DirBase: 0aac0380`）

   - 门描述符为：`0000e900·00000068`

   - 代码如下：

     ```c
     #include <Windows.h>
     #include <stdlib.h>
     
     DWORD dwOK;
     DWORD dwESP;
     DWORD dwCS;
     
     void __declspec(naked) test()
     {
         dwOK=1;
         __asm
         {
             mov eax,esp;
             mov dwESP,eax;
             mov word ptr [dwCS],ax;
             iretd;
         }
     }
     
     int main(int argc,char * argv[])
     {
         char stack[100]={0};    //自己构造一个堆栈使用
         DWORD cr3=0;
         DWORD addr=0;
         char buffer[6]={0};    //构造任务段
     
         DWORD tss[0x68]={
             0x0,        //link
             0x0,        //esp0
             0x0,        //ss0
             0x0,        //esp1
             0x0,        //ss1
             0x0,        //esp2
             0x0,        //ss2
             0,        //cr3 *
             (DWORD)addr,        //eip *
             0,        //eflags
             0,        //eax
             0,        //ecx
             0,        //edx
             0,        //ebx
             ((DWORD)stack) + 100,        //esp *
             0,        //ebp
             0,        //esi
             0,        //edi
             0x23,        //es *
             0x08,        //cs *
             0x10,        //ss *
             0x23,        //ds *
             0x30,        //fs *
             0,        //gs
             0,        //idt
             0x20ac0000        //IO权限位图，VISTA之后不再用了，从其他结构体拷贝出来。
             };
         printf("Target:\n");
         scanf("%x",&addr);
         tss[8]=addr;
         
         printf("tss：%x\n",tss);
     
         printf("CR3:\n");
         scanf("%x",&cr3);    //看准了DirBase:
     
         tss[7]=cr3;
     
         *(WORD*)(&buffer[4])=0x93;
     
         __asm
         {
             call fword ptr [buffer];
         }
     
         printf("dwESP=%x\tdwCS=%x\n",dwESP,dwCS);
         system("pause");
         return 0;
     }
     ```

     ```
     输出结果：dwESP=12ff80      dwCS=ff80
     ```


#### 任务门

1. 自己实现一个任务门。

   - 门描述符为：`0000e900·00000068`

   - 代码如下：

     ```c
     #include <Windows.h>
     #include <stdlib.h>
     
     void __declspec(naked) test()
     {
         __asm
         {
             iretd;
         }
     }
     
     int main(int argc,char * argv[])
     {
         char stack[100]={0};    //自己构造一个堆栈使用
         DWORD cr3=0;
         DWORD addr=0;
     
         DWORD tss[0x68]={
             0x0,        //link
             0x0,        //esp0
             0x0,        //ss0
             0x0,        //esp1
             0x0,        //ss1
             0x0,        //esp2
             0x0,        //ss2
             0,        //cr3 *
             (DWORD)addr,        //eip *
             0,        //eflags
             0,        //eax
             0,        //ecx
             0,        //edx
             0,        //ebx
             ((DWORD)stack) + 100,        //esp *
             0,        //ebp
             0,        //esi
             0,        //edi
             0x23,        //es *
             0x08,        //cs *
             0x10,        //ss *
             0x23,        //ds *
             0x30,        //fs *
             0,        //gs
             0,        //idt
             0x20ac0000        //IO权限位图，VISTA之后不再用了，从其他结构体拷贝出来。
             };
         printf("Target:\n");
         scanf("%x",&addr);
         tss[8]=addr;
         
         printf("tss：%x\n",tss);
     
         printf("CR3:\n");
         scanf("%x",&cr3);    //看准了DirBase:
     
         tss[7]=cr3;
     
         __asm
         {
             int 20;
         }
     //kd > eq 8003f048 0000e912·ff140068 写入TSS段描述符到GDT
     //kd > eq 8003f500 0000e500·004b0000 写入任务门到 IDT
         system("pause");
         return 0;
     }
     ```

     ```
     成功执行🥲
     ```

2. 在保护模式中，当CPU检测到异常的时候，会根据异常的类型来查找对应的异常处理函数，比如：当指令检测到除零异常时，将默认执行0号中断，请列出处理除零异常函数的地址。

   ```
   80548e00`000831a0    address:0x805431a0
   ```

   ```asm
   ffffffff`805431a0 6a00             push    0
   ffffffff`805431a2 66c74424020000   mov     word ptr [esp+2], 0
   ffffffff`805431a9 55               push    ebp
   ffffffff`805431aa 53               push    ebx
   ffffffff`805431ab 56               push    esi
   ffffffff`805431ac 57               push    edi
   ffffffff`805431ad 0fa0             push    fs
   ffffffff`805431af bb30000000       mov     ebx, 30h
   ffffffff`805431b4 668ee3           mov     fs, bx
   ffffffff`805431b7 648b1d00000000   mov     ebx, dword ptr fs:[0]
   ffffffff`805431be 53               push    ebx
   ffffffff`805431bf 83ec04           sub     esp, 4
   ffffffff`805431c2 50               push    eax
   ffffffff`805431c3 51               push    ecx
   ffffffff`805431c4 52               push    edx
   ffffffff`805431c5 1e               push    ds
   ffffffff`805431c6 06               push    es
   ffffffff`805431c7 0fa8             push    gs
   ffffffff`805431c9 66b82300         mov     ax, 23h
   ffffffff`805431cd 83ec30           sub     esp, 30h
   ffffffff`805431d0 668ed8           mov     ds, ax
   ffffffff`805431d3 668ec0           mov     es, ax
   ffffffff`805431d6 8bec             mov     ebp, esp
   ffffffff`805431d8 f744247000000200 test    dword ptr [esp+70h], 20000h
   ffffffff`805431e0 7596             jne     ntkrpamp!V86_kit0_a (80543178)
   ffffffff`805431e2 fc               cld     
   ffffffff`805431e3 8b5d60           mov     ebx, dword ptr [ebp+60h]
   ffffffff`805431e6 8b7d68           mov     edi, dword ptr [ebp+68h]
   ffffffff`805431e9 89550c           mov     dword ptr [ebp+0Ch], edx
   ffffffff`805431ec c74508000ddbba   mov     dword ptr [ebp+8], 0BADB0D00h
   ffffffff`805431f3 895d00           mov     dword ptr [ebp], ebx
   ffffffff`805431f6 897d04           mov     dword ptr [ebp+4], edi
   ffffffff`805431f9 64f60550000000ff test    byte ptr fs:[50h], 0FFh
   ffffffff`80543201 0f85edfeffff     jne     ntkrpamp!Dr_kit0_a (805430f4)
   ffffffff`80543207 f7457000000200   test    dword ptr [ebp+70h], 20000h
   ffffffff`8054320e 753d             jne     ntkrpamp!_KiTrap00+0xad (8054324d)
   ffffffff`80543210 f6456c01         test    byte ptr [ebp+6Ch], 1
   ffffffff`80543214 7407             je      ntkrpamp!_KiTrap00+0x7d (8054321d)
   ffffffff`80543216 66837d6c1b       cmp     word ptr [ebp+6Ch], 1Bh
   ffffffff`8054321b 751d             jne     ntkrpamp!_KiTrap00+0x9a (8054323a)
   ffffffff`8054321d fb               sti     
   ffffffff`8054321e 55               push    ebp
   ffffffff`8054321f e87c040600       call    ntkrpamp!_Ki386CheckDivideByZeroTrap@4 (805a36a0)
   ffffffff`80543224 8b5d68           mov     ebx, dword ptr [ebp+68h]
   ffffffff`80543227 e9ebfdffff       jmp     ntkrpamp!Kei386EoiHelper@0+0x16b (80543017)
   ffffffff`8054322c fb               sti     
   ffffffff`8054322d 8b5d68           mov     ebx, dword ptr [ebp+68h]
   ffffffff`80543230 b8940000c0       mov     eax, 0C0000094h
   ffffffff`80543235 e9ddfdffff       jmp     ntkrpamp!Kei386EoiHelper@0+0x16b (80543017)
   ffffffff`8054323a 648b1d24010000   mov     ebx, dword ptr fs:[124h]
   ffffffff`80543241 8b5b44           mov     ebx, dword ptr [ebx+44h]
   ffffffff`80543244 83bb5801000000   cmp     dword ptr [ebx+158h], 0
   ffffffff`8054324b 74df             je      ntkrpamp!_KiTrap00+0x8c (8054322c)
   ffffffff`8054324d 6a00             push    0
   ffffffff`8054324f e8a42c0000       call    ntkrpamp!_Ki386VdmReflectException_A@4 (80545ef8)
   ffffffff`80543254 0ac0             or      al, al
   ffffffff`80543256 74d4             je      ntkrpamp!_KiTrap00+0x8c (8054322c)
   ffffffff`80543258 e94ffcffff       jmp     ntkrpamp!Kei386EoiHelper@0 (80542eac)
   ffffffff`8054325d 8d4900           lea     ecx, [ecx]
   ffffffff`80543260 c74568c8245480   mov     dword ptr [ebp+68h], 805424C8h
   ffffffff`80543267 806571fe         and     byte ptr [ebp+71h], 0FEh
   ffffffff`8054326b e93cfcffff       jmp     ntkrpamp!Kei386EoiHelper@0 (80542eac)
   ```

3. 在保护模式中，当CPU检测到异常的时候，会根据异常的类型来查找对应的异常处理函数，比如:当指令检测到除零异常时，将默认执行0号中断所指定的异常处理程序,但是,异常处理程序本身任然可能出现异常,如果异常处理程序出现异常时候（双重错误） ,CPU会默认执行8号中断，请分析8号中断是什么？做了什么事情？替换了哪些寄存器？替换后的值是多少？为什么这样设计？

   ```
   00008500`00501198    
   50 = 0101 0  000
   index = 10
   门如下：
   80008955`87000068    address=80558700
   kd> dd 80558700
   ReadVirtual: 80558700 not properly sign extended
   80558700  00000000 80555700 00000010 00000000
   80558710  00000000 00000000 00000000 00039000
   80558720  804e0891 00000000 00000000 00000000
   80558730  00000000 00000000 80555700 00000000
   80558740  00000000 00000000 00000023 00000008
   80558750  00000010 00000023 00000030 00000000
   80558760  00000000 20ac0000 00000028 80555700
   80558770  00000010 00000000 00000000 00000000
   可以看到，改了ESP0 = 80555700，SS0 = 10，EIP = 804e0891，ESP = 80555700，ES = 23，CS = 8，SS = 10，DS = 23，FS = 30
   将eip放到反汇编窗口可以看到如下:
   nt!KiTrap08:
   ffffffff`804e0891 fa             cli     
   ffffffff`804e0892 648b0d3c000000 mov     ecx, dword ptr fs:[3Ch]
   ……
   这就是8号中断的执行的位置
   ```
   

#### 考试

- 将某一代码片运行到1环

  - 门描述符为：`0000e900·00000068`

  - 代码如下：

    ```c
    //eq 8003f0d8 0040E912`FD6C0068    ;TSS描述符 D9，注意正确
    //eq 8003f0b0 00CFBB00`0000FFFF    ;cs:B1
    //eq 8003f0b8 00CFB300`0000FFFF    ;ss:B9
    //eq 8003f0c0 FFC0B3DF`F0000001    ;fs:C1，这个东西是关键，运气不好容易因线程切换蓝屏
    #include <Windows.h>
    #include <stdlib.h>
    
    DWORD dwOK;
    DWORD dwESP;
    DWORD dwCS;
    
    void __declspec(naked) test()
    {
        __asm
        {
            mov eax,esp;
            mov dwESP,eax;
            mov word ptr [dwCS],cs;
            iretd;
        }
    }
    
    int main(int argc,char * argv[])
    {
        char stack[100]={0};    //自己构造一个堆栈使用
        DWORD cr3=0;
        DWORD addr=0;
        char buffer[6]={0};    //构造任务段
    
        DWORD tss[0x68]={
            0x0,        //link
            0x0,        //esp0
            0x0,        //ss0
            0x0,        //esp1
            0x0,        //ss1
            0x0,        //esp2
            0x0,        //ss2
            0,        //cr3 *
            (DWORD)addr,        //eip *
            0,        //eflags
            0,        //eax
            0,        //ecx
            0,        //edx
            0,        //ebx
            ((DWORD)stack) + 100,        //esp *
            0,        //ebp
            0,        //esi
            0,        //edi
            0x23,        //es *
            0xB1,        //cs *
            0xB9,        //ss *
            0x23,        //ds *
            0xC1,        //fs *
            0,        //gs
            0,        //idt
            0x20ac0000        //IO权限位图，VISTA之后不再用了，从其他结构体拷贝出来。
            };
        printf("Target:\n");
        scanf("%x",&addr);
        tss[8]=addr;
        
        printf("tss：%x\n",tss);
    
        printf("CR3:\n");
        scanf("%x",&cr3);    //看准了DirBase:
    
        tss[7]=cr3;
    
        *(WORD*)(&buffer[4])=0xDB;
        
        __asm
        {
            call fword ptr [buffer];
        }
        printf("dwESP=%x\tdwCS=%x\n",dwESP,dwCS);
        system("pause");
        return 0;
    }
    ```


#### 10-10-12分页

- 找物理地址

  1. 使用ce查找记事本进程中的字符串，修改记事本中的字符串以找到真正的字符串的地址。

  2. 先将这个地址进行10-10-12分页（比如我的地址是：000AB3A0）

     - 转成二进制：0000 0000 00|00 1010 1011 3A0 

     - 那么这两组的值为：0，AB 加上后面的 3A0

     - 将第二组值×4：0，AB*4，3A0

       这三组就是三个页的`offset`

  3. 在`windbg`中使用指令`！process 0 0`，查看notepad的`Cr3`，就是那个`DirBase`的值

  4. 使用指令`！dd [地址]` 读取线性地址，这个地址就是`Cr3`的值加上第一个`offset`，找到的是第二个页的地址（后三位067改为0才是地址，067是属性），第二个页的地址加上第二个`offset`，找到的是物理页的地址（后三位067改为0才是地址），物理页的地址加上第三个`offset`，找到的就是字符串的物理地址。
  
- 创建两个进程，申请一个相同的内存地址，比如: 0x401234，并存储不同的内容，分别找到这2个进程相对应的物理地址，看内容是什么？说说你的理解

#### PDE_PTE

- 线性地址0为什么不能访问？将0地址设置为可读可写。

  比如我观察一个进程的`Cr3`，`PDT`与`PTT`，如下：

  ```asm
  PROCESS 89c25be0  SessionId: 0  Cid: 0674    Peb: 7ffd9000  ParentCid: 05c4
      DirBase: 1cd3e000  ObjectTable: e2848690  HandleCount:  50.
      Image: notepad.exe
  
  kd> !dd 1cd3e000
  #1cd3e000 1cdb0867 1d261867 1cfb1867 00000000
  #1cd3e010 1cfe3867 00000000 00000000 00000000
  #1cd3e020 00000000 00000000 00000000 00000000
  #1cd3e030 00000000 00000000 00000000 00000000
  #1cd3e040 00000000 00000000 00000000 00000000
  #1cd3e050 00000000 00000000 00000000 00000000
  #1cd3e060 00000000 00000000 00000000 00000000
  #1cd3e070 00000000 00000000 00000000 00000000
  kd> !dd 1cdb0000
  #1cdb0000 00000000 00000000 00000000 00000000
  #1cdb0010 00000000 00000000 00000000 00000000
  #1cdb0020 00000000 00000000 00000000 00000000
  #1cdb0030 00000000 00000000 00000000 00000000
  #1cdb0040 1ce71867 00000000 00000000 00000000
  #1cdb0050 00000000 00000000 00000000 00000000
  #1cdb0060 00000000 00000000 00000000 00000000
  #1cdb0070 00000000 00000000 00000000 00000000
  ```

  ![image](https://c65mael.github.io/myassets/pdeptejg.png)

  可以看到，进程中线性地址0的`PTT`为0，也就是`PTE`中的`P`位为0，表示`PTE`无效，所以不能被访问，但是`PDE`是有效的，所以可以重新改一个有效的`PTE`就可以访问了吧。

  代码如下：

  ```c
  #include <Windows.h>
  #include <stdlib.h>
  
  int main()
  {
  	int x=1;
  	printf("x：%x\n",&x);
  	getchar();
  	//向0地址写入数据
  	*(int*)0 = 123;
  	printf("x地址数据:%x\n",*(int*)0);
  	getchar();
  	return 0;
  }
  ```

  过程如下：

  ```
  0012ff7c
  0000 0000 0001 0010 1111 f7c
  1：0
  2：4BC
  3：f7c
  ```

  ```asm
  Failed to get VadRoot
  PROCESS 89b9f558  SessionId: 0  Cid: 05b8    Peb: 7ffdd000  ParentCid: 0180
      DirBase: 27943000  ObjectTable: e1085490  HandleCount:  12.
      Image: 111.exe
  
  kd> !dd 27943000
  #27943000 27872867 27971867 00000000 00000000
  #27943010 00000000 00000000 00000000 00000000
  #27943020 00000000 00000000 00000000 00000000
  #27943030 00000000 00000000 00000000 00000000
  #27943040 00000000 00000000 00000000 00000000
  #27943050 00000000 00000000 00000000 00000000
  #27943060 00000000 00000000 00000000 00000000
  #27943070 00000000 00000000 00000000 00000000
  kd> !dd 27872000
  #27872000 00000000 00000000 00000000 00000000
  #27872010 00000000 00000000 00000000 00000000
  #27872020 00000000 00000000 00000000 00000000
  #27872030 00000000 00000000 00000000 00000000
  #27872040 279f3867 00000000 00000000 00000000
  #27872050 00000000 00000000 00000000 00000000
  #27872060 00000000 00000000 00000000 00000000
  #27872070 00000000 00000000 00000000 00000000
  kd> !dd 27872000+4BC
  #278724bc 27877867 16360025 16361025 00000000
  #278724cc 00000000 00000000 00000000 00000000
  #278724dc 00000000 00000000 00000000 00000000
  #278724ec 00000000 00000000 00000000 00000000
  #278724fc 00000000 279fb867 27abc867 27c7d867
  #2787250c 00000000 00000000 00000000 00000000
  #2787251c 00000000 00000000 00000000 00000000
  #2787252c 00000000 00000000 00000000 00000000
  kd> !ed 27872000 27877867
  ```

  ```
  输出结果：x地址数据:7b
  ```

- 为变量x再映射一个线性地址，并通过这个新的地址读取x的值。

  代码如下：

  ```c
  #include <Windows.h>
  #include <stdlib.h>
  
  int main()
  {
  	int x=1;
      int y[1024]={0};
  	printf("x：%x\n",&x);
      printf("y：%x\n",&y);
  	getchar();
  	printf("x地址数据:%x\n",x);
  	getchar();
  	return 0;
  }
  ```

  ```
  x:0012ff7c
  0000 0000 0001 0010 1111 f7c
  1：0
  2：4BC
  3：f7c
  ```

  ```
  y:0012ef7c
  0000 0000 0001 0010 1110 f7c
  1：0
  2：4B8
  3：f7c
  ```

  将x的`PDE`改为y的，过程如下：

  ```asm
  Failed to get VadRoot
  PROCESS 89c1d7e8  SessionId: 0  Cid: 052c    Peb: 7ffd3000  ParentCid: 079c
      DirBase: 20ff4000  ObjectTable: e28b0ad8  HandleCount:  12.
      Image: 111.exe
  
  kd> !dd 20ff4000
  #20ff4000 20e5d867 20d9c867 00000000 00000000
  #20ff4010 00000000 00000000 00000000 00000000
  #20ff4020 00000000 00000000 00000000 00000000
  #20ff4030 00000000 00000000 00000000 00000000
  #20ff4040 00000000 00000000 00000000 00000000
  #20ff4050 00000000 00000000 00000000 00000000
  #20ff4060 00000000 00000000 00000000 00000000
  #20ff4070 00000000 00000000 00000000 00000000
  kd> !dd 20e5d000+4b8
  #20e5d4b8 210c8867 20ffb867 163df025 16420025
  #20e5d4c8 00000000 00000000 00000000 00000000
  #20e5d4d8 00000000 00000000 00000000 00000000
  #20e5d4e8 00000000 00000000 00000000 00000000
  #20e5d4f8 00000000 00000000 20dff867 21300867
  #20e5d508 20f81867 00000000 00000000 00000000
  #20e5d518 00000000 00000000 00000000 00000000
  #20e5d528 00000000 00000000 00000000 00000000
  kd> !ed 20e5d4bc 210c8867
  ```

  但是不知道为什么，修改完，执行后会蓝屏＞︿＜

- 10-10-12分页模式物理内存能够识别的最多范围是多少?

  1024 *1024 *4096 ==一共4GB

- 如何判断2个线性地址是否在同一个物理页？

  物理地址除了最后三位以外其他的位数都相等，就是同一物理页

#### PDE_PTE属性

-  在VC6中定义一个字符串常量 通过另外一个线性地址修改这个常量的值

  代码如下：

  ```c
  #include <Windows.h>
  #include <stdlib.h>
  char* a="c65mael";
  int main(int argc, char* argu[])
  {
  	printf("%x",a); 
      getchar();
  	a[1]='a'; 
  	printf("%s",a);
      getchar();
  	return 0;
  }
  ```

  ```
  a:0042201c
  0000 0000 0100 0010 0010 01c
  1：1*4
  2：22*4
  3：01c
  ```

  过程如下：

  ```asm
  Failed to get VadRoot
  PROCESS 89e63020  SessionId: 0  Cid: 0520    Peb: 7ffd9000  ParentCid: 07cc
      DirBase: 2ff55000  ObjectTable: e1babc00  HandleCount:  12.
      Image: 111.exe
  
  kd> !dd 2ff55000+4
  #2ff55004 2ffd9867 00000000 00000000 00000000
  #2ff55014 00000000 00000000 00000000 00000000
  #2ff55024 00000000 00000000 00000000 00000000
  #2ff55034 00000000 00000000 00000000 00000000
  #2ff55044 00000000 00000000 00000000 00000000
  #2ff55054 00000000 00000000 00000000 00000000
  #2ff55064 00000000 00000000 00000000 00000000
  #2ff55074 00000000 00000000 00000000 00000000
  kd> !dd 2ffd9000+88
  #2ffd9088 30085025 00000000 301d2867 30488225
  #2ffd9098 00000000 3024b867 3040d867 30413867
  #2ffd90a8 303f2825 00000000 00000000 00000000
  #2ffd90b8 00000000 00000000 00000000 00000000
  #2ffd90c8 00000000 00000000 00000000 00000000
  #2ffd90d8 00000000 00000000 00000000 00000000
  #2ffd90e8 00000000 00000000 00000000 00000000
  #2ffd90f8 00000000 00000000 00000000 00000000
  kd> !ed 2ffd9088 30085027
  ```

- 修改0x8003F00C这个地址的PDE PTE属性使之可以在3环访问

  代码如下：

  ```c
  #include <Windows.h>
  #include <stdlib.h>
  int main(int argc, char* argu[])
  {
      int x=0x8003F00C;
      getchar();
  	printf("%x",*(int*)a); 
  	return 0;
  }
  ```

  ```
  8003F00C
  1000 0000 0000 0011 1111 00c
  1：200*4
  2：3f*4
  3：00c
  ```

  过程如下：

  ```asm
  Failed to get VadRoot
  PROCESS 897b1518  SessionId: 0  Cid: 032c    Peb: 7ffd9000  ParentCid: 02dc
      DirBase: 227cc000  ObjectTable: e28a8448  HandleCount:  12.
      Image: 111.exe
  
  kd> !dd 227cc000+800
  #227cc800 0003b163 004009e3 0003e163 0003c163
  #227cc810 010009e3 014009e3 018009e3 01c009e3
  #227cc820 020009e3 024009e3 028009e3 02c009e3
  #227cc830 030009e3 034009e3 038009e3 03c009e3
  #227cc840 040009e3 044009e3 048009e3 04c009e3
  #227cc850 050009e3 054009e3 058009e3 05c009e3
  #227cc860 060009e3 064009e3 068009e3 06c009e3
  #227cc870 070009e3 074009e3 078009e3 07c009e3
  kd> !ed 227cc800 0003b167
  kd> !dd 0003b0fc
  #   3b0fc 0003f167 00040103 00041103 00042163
  #   3b10c 00043163 00044163 00000000 00000000
  #   3b11c 00000000 00000000 00000000 00000000
  #   3b12c 00000000 00000000 00000000 00000000
  #   3b13c 00000000 00000000 00000000 00000000
  #   3b14c 00000000 00000000 00000000 00000000
  #   3b15c 00000000 00000000 00000000 00000000
  #   3b16c 00000000 00000000 00000000 00000000
  kd> !ed 3b0fc 0003f867
  ```

- 思考题：一个线性地址如果可以访问，一定要填上正确的PDE和PTE，但PDE与PTE是物理地址，如果我们想填充，那又必须要通过线性地址才能去访问，谁为访问PDE与PTE的线性地址填充争取的PDE与PTE呢?

  ```
  CPU通过“页表”来找到内存中的数据，而“页表”本身也放在内存里。你想访问页表时，也得先通过页表来找到页表的位置。这听起来像是“先有鸡还是先有蛋”的问题。
  实际上，系统有个聪明的办法：它把“页表”自己也放到它管理的地址里面！就好像给“页表”留了一面镜子，这样你就可以通过这个镜子（一个特殊的地址）看到并访问页表本身。这样，CPU就可以通过这个自带的“镜子”来先找到页表，然后再去管理其他的内存数据。
  所以，是操作系统给页表设置了一个特殊的“镜子”地址，这样即使你要找页表，它也能让你找到。
  PDT:0xc0300000
  ```
  
- 创建2个进程，以页为代码拆分0-4G线性地址

  结果：
  
  1. 低2G（`0-7FFFFFFF`）几乎不同
  2. 高2G（`80000000-FFFFFFFF`）几乎相同
  3. `0-7FFFFFFF`的前`64K`和后`64k`都是没有映射的
  

#### PDT_PTT基址

逆向分析`MmIsAddressValid`函数

```asm
804e2f46 8bff            mov     edi,edi
804e2f48 55              push    ebp    ;保护现场
804e2f49 8bec            mov     ebp,esp
804e2f4b 8b4d08          mov     ecx,dword ptr [ebp+8]    ;取一个栈上的值做参数(VirtualAddress)
804e2f4e 8bc1            mov     eax,ecx    ;eax=VirtualAddress
804e2f50 c1e814          shr     eax,14h    ;eax右移20位，保留高12位
804e2f53 bafc0f0000      mov     edx,0FFCh    ;edx=0xffc(1111 1111 1100)
804e2f58 23c2            and     eax,edx    ;不要低两位，也就是第一个10
804e2f5a 2d0000d03f      sub     eax,-0C0300000h    ;eax+0xC0300000，页目录表
804e2f5f 8b00            mov     eax,dword ptr [eax]    ;取eax地址的值。也就是PDE
804e2f61 a801            test    al,1    ;判断p位是否为1
804e2f63 0f844e3e0100    je      nt!MmIsAddressValid+0x4f (804f6db7)
804e2f69 84c0            test    al,al    ;判断ps位,是否为大页(因为第7位为1时会被认为负数)
804e2f6b 7824            js      nt!MmIsAddressValid+0x53 (804e2f91)
804e2f6d c1e90a          shr     ecx,0Ah    ;ecx右移10位,保留高20位
804e2f70 81e1fcff3f00    and     ecx,3FFFFCh    ;去高两位与低两位
804e2f76 81e900000040    sub     ecx,-0C0000000h    ;eax+0xC0000000，页表
804e2f7c 8bc1            mov     eax,ecx
804e2f7e 8b08            mov     ecx,dword ptr [eax]    ;取eax地址的值。也就是PTE
804e2f80 f6c101          test    cl,1    ;判断p位是否为1
804e2f83 0f842e3e0100    je      nt!MmIsAddressValid+0x4f (804f6db7)
804e2f89 84c9            test    cl,cl    ;判断PAT位
804e2f8b 0f88d5410400    js      nt!MmIsAddressValid+0x3f (80527166)
804e2f91 b001            mov     al,1
804e2f93 5d              pop     ebp
804e2f94 c20400          ret     4
```

#### 2-9-9-12分页

- 在2-9-9-12分页模式下进行线性地址到物理地址的转换

  代码如下：

  ```c
  #include <Windows.h>
  #include <stdio.h>
  int main(int argc, char* argu[])
  {
      int a=10;
      printf("%x",&a);
      getchar();
      printf("%x",a);
  	return 0;
  }
  ```

  ```
  0x0012ff7c
  0000 0000 00|01 0010 1111 f7c
  1:0
  2:12f*8（一定注意）
  3:f7c
  ```

  过程如下：

  ```asm
  Failed to get VadRoot
  PROCESS 8a316be0  SessionId: 0  Cid: 017c    Peb: 7ffda000  ParentCid: 0584
      DirBase: 0aac0380  ObjectTable: e272aec0  HandleCount:  12.
      Image: 111.exe
  
  kd> !dd 0aac0380
  # aac0380 225ad801 00000000 226ee801 00000000（这个就是PDPTE，不是只有4个吗？）
  # aac0390 227af801 00000000 2236c801 00000000
  # aac03a0 bae713c0 00000000 21da9801 00000000
  # aac03b0 21bea801 00000000 21ca7801 00000000
  # aac03c0 bae713e0 00000000 00000000 00000000
  # aac03d0 00000000 00000000 00000000 00000000
  # aac03e0 bae71400 00000000 00000000 00000000
  # aac03f0 00000000 00000000 00000000 00000000
  kd> !dd 225ad000
  #225ad000 22471867 00000000 227d4867 00000000
  #225ad010 225f0867 00000000 00000000 00000000
  #225ad020 00000000 00000000 00000000 00000000
  #225ad030 00000000 00000000 00000000 00000000
  #225ad040 00000000 00000000 00000000 00000000
  #225ad050 00000000 00000000 00000000 00000000
  #225ad060 00000000 00000000 00000000 00000000
  #225ad070 00000000 00000000 00000000 00000000
  kd> !dd 22471000+12f*8
  #22471978 2270d867 80000000 16fff025 80000000
  #22471988 17400025 80000000 00000000 00000000
  #22471998 00000000 00000000 00000000 00000000
  #224719a8 00000000 00000000 00000000 00000000
  #224719b8 00000000 00000000 00000000 00000000
  #224719c8 00000000 00000000 00000000 00000000
  #224719d8 00000000 00000000 00000000 00000000
  #224719e8 00000000 00000000 00000000 00000000
  kd> !dd 2270d000+f7c
  #2270df7c 0000000a 0012ffc0 00401299 00000001
  #2270df8c 00380d60 00380df8 00000000 00000000
  #2270df9c 7ffda000 00000001 00000001 0012ff94
  #2270dfac b13f8d08 0012ffe0 00404440 00423130
  #2270dfbc 00000000 0012fff0 7c817067 00000000
  #2270dfcc 00000000 7ffda000 8054c6ed 0012ffc8
  #2270dfdc 8a162980 ffffffff 7c839ac0 7c817070
  #2270dfec 00000000 00000000 00000000 004011b0
  kd> !ed 2270df7c 9
  kd> !dd 2270d000+f7c
  #2270df7c 00000009 0012ffc0 00401299 00000001
  #2270df8c 00380d60 00380df8 00000000 00000000
  #2270df9c 7ffda000 00000001 00000001 0012ff94
  #2270dfac b13f8d08 0012ffe0 00404440 00423130
  #2270dfbc 00000000 0012fff0 7c817067 00000000
  #2270dfcc 00000000 7ffda000 8054c6ed 0012ffc8
  #2270dfdc 8a162980 ffffffff 7c839ac0 7c817070
  #2270dfec 00000000 00000000 00000000 004011b0
  ```

- 给0线性地址挂上物理页。

  代码如下：

  ```c
  #include <Windows.h>
  #include <stdio.h>
  int main(int argc, char* argu[])
  {
      int *a=0;
  	int b = 8888;
      printf("%x",&b);
      getchar();
      printf("%x",*a);
  	getchar();
  	return 0;
  }
  ```

  ```
  0x12ff78
  0000 0000 0001 0010 1111 f78
  1:0
  2:12f*8
  3:f78
  ```

  过程如下：

  ```asm
  Failed to get VadRoot
  PROCESS 8a3f68d8  SessionId: 0  Cid: 0210    Peb: 7ffd3000  ParentCid: 06fc
      DirBase: 0aac03a0  ObjectTable: e1396468  HandleCount:  12.
      Image: 111.exe
  
  kd> !dd 0aac03a0
  # aac03a0 3071b801 00000000 3095c801 00000000
  # aac03b0 3075d801 00000000 3085a801 00000000
  # aac03c0 bae713e0 00000000 00000000 00000000
  # aac03d0 00000000 00000000 00000000 00000000
  # aac03e0 bae71400 00000000 00000000 00000000
  # aac03f0 00000000 00000000 00000000 00000000
  # aac0400 bae71420 00000000 00000000 00000000
  # aac0410 00000000 00000000 00000000 00000000
  kd> !dd 3071b000
  #3071b000 3079d867 00000000 30a69867 00000000
  #3071b010 3099c867 00000000 00000000 00000000
  #3071b020 00000000 00000000 00000000 00000000
  #3071b030 00000000 00000000 00000000 00000000
  #3071b040 00000000 00000000 00000000 00000000
  #3071b050 00000000 00000000 00000000 00000000
  #3071b060 00000000 00000000 00000000 00000000
  #3071b070 00000000 00000000 00000000 00000000
  kd> !dd 3079d000+12f*8
  #3079d978 307e2867 80000000 16cae025 80000000
  #3079d988 16caf025 80000000 00000000 00000000
  #3079d998 00000000 00000000 00000000 00000000
  #3079d9a8 00000000 00000000 00000000 00000000
  #3079d9b8 00000000 00000000 00000000 00000000
  #3079d9c8 00000000 00000000 00000000 00000000
  #3079d9d8 00000000 00000000 00000000 00000000
  #3079d9e8 00000000 00000000 00000000 00000000
  kd> !dd 307e2000+f78
  #307e2f78 000022b8 00000000 0012ffc0 004012a9
  #307e2f88 00000001 00380d60 00380df8 00000000
  #307e2f98 00000000 7ffd3000 00000001 00000001
  #307e2fa8 0012ff94 b1de6d08 0012ffe0 00404450
  #307e2fb8 00423130 00000000 0012fff0 7c817067
  #307e2fc8 00000000 00000000 7ffd3000 8054c6ed
  #307e2fd8 0012ffc8 8a402da8 ffffffff 7c839ac0
  #307e2fe8 7c817070 00000000 00000000 00000000
  kd> !dd 0aac03a0
  # aac03a0 3071b801 00000000 3095c801 00000000
  # aac03b0 3075d801 00000000 3085a801 00000000
  # aac03c0 bae713e0 00000000 00000000 00000000
  # aac03d0 00000000 00000000 00000000 00000000
  # aac03e0 bae71400 00000000 00000000 00000000
  # aac03f0 00000000 00000000 00000000 00000000
  # aac0400 bae71420 00000000 00000000 00000000
  # aac0410 00000000 00000000 00000000 00000000
  kd> !dd 3079d000
  #3079d000 00000000 00000000 00000000 00000000
  #3079d010 00000000 00000000 00000000 00000000
  #3079d020 00000000 00000000 00000000 00000000
  #3079d030 00000000 00000000 00000000 00000000
  #3079d040 00000000 00000000 00000000 00000000
  #3079d050 00000000 00000000 00000000 00000000
  #3079d060 00000000 00000000 00000000 00000000
  #3079d070 00000000 00000000 00000000 00000000
  kd> !ed 3079d000 307e2867
  ```

- 逆向分析MmisAddressValid函数，找到PAE分页模式下页目录表、页表基址。

  ```asm
  80514928 8bff            mov     edi,edi
  8051492a 55              push    ebp
  8051492b 8bec            mov     ebp,esp
  8051492d 51              push    ecx
  8051492e 51              push    ecx
  8051492f 8b4d08          mov     ecx,dword ptr [ebp+8]
  80514932 56              push    esi
  80514933 8bc1            mov     eax,ecx
  80514935 c1e812          shr     eax,12h    #右移18位
  80514938 bef83f0000      mov     esi,3FF8h
  8051493d 23c6            and     eax,esi    #进行与运算，0011 1111 1111 1000 剩11位
  8051493f 2d0000a03f      sub     eax,3FA00000h    #eax+0xC0600000
  80514944 8b10            mov     edx,dword ptr [eax]    #取PDE低四字节
  80514946 8b4004          mov     eax,dword ptr [eax+4]    #取PDE高四字节
  80514949 8945fc          mov     dword ptr [ebp-4],eax
  8051494c 8bc2            mov     eax,edx
  8051494e 57              push    edi
  8051494f 83e001          and     eax,1
  80514952 33ff            xor     edi,edi
  80514954 0bc7            or      eax,edi
  
  80514956 7461            je      nt!MmIsAddressValid+0x91 (805149b9)
  80514958 bf80000000      mov     edi,80h
  8051495d 23d7            and     edx,edi
  8051495f 6a00            push    0
  80514961 8955f8          mov     dword ptr [ebp-8],edx
  80514964 58              pop     eax
  80514965 7404            je      nt!MmIsAddressValid+0x43 (8051496b)
  80514967 85c0            test    eax,eax
  80514969 7452            je      nt!MmIsAddressValid+0x95 (805149bd)
  
  8051496b c1e909          shr     ecx,9    #右移9位
  8051496e 81e1f8ff7f00    and     ecx,7FFFF8h    #进行与运算，0111 1111 1111 1111 1111 1000 剩20位
  80514974 8b81040000c0    mov     eax,dword ptr [ecx-3FFFFFFCh]    #mov eax, [ecx+0xC0000004]
  8051497a 81e900000040    sub     ecx,40000000h    #ecx+0xC0000000
  80514980 8b11            mov     edx,dword ptr [ecx]    #取PTE低四字节
  80514982 8945fc          mov     dword ptr [ebp-4],eax    #高4位在栈上
  80514985 53              push    ebx
  80514986 8bc2            mov     eax,edx
  80514988 33db            xor     ebx,ebx
  8051498a 83e001          and     eax,1
  8051498d 0bc3            or      eax,ebx
  8051498f 5b              pop     ebx
  80514990 7427            je      nt!MmIsAddressValid+0x91 (805149b9)
  80514992 23d7            and     edx,edi
  80514994 6a00            push    0
  80514996 8955f8          mov     dword ptr [ebp-8],edx
  80514999 58              pop     eax
  8051499a 7421            je      nt!MmIsAddressValid+0x95 (805149bd)
  8051499c 85c0            test    eax,eax
  8051499e 751d            jne     nt!MmIsAddressValid+0x95 (805149bd)
  805149a0 23ce            and     ecx,esi
  805149a2 8b89000060c0    mov     ecx,dword ptr [ecx-3FA00000h]
  805149a8 b881000000      mov     eax,81h
  805149ad 23c8            and     ecx,eax
  805149af 33d2            xor     edx,edx
  805149b1 3bc8            cmp     ecx,eax
  805149b3 7508            jne     nt!MmIsAddressValid+0x95 (805149bd)
  805149b5 85d2            test    edx,edx
  805149b7 7504            jne     nt!MmIsAddressValid+0x95 (805149bd)
  805149b9 32c0            xor     al,al
  805149bb eb02            jmp     nt!MmIsAddressValid+0x97 (805149bf)
  805149bd b001            mov     al,1
  805149bf 5f              pop     edi
  805149c0 5e              pop     esi
  805149c1 c9              leave
  805149c2 c20400          ret     4
  ```

- 修改页属性，实现应用层读写高2G内存地址。

  测试代码如下：

  ```c
  #include <stdio.h>
  #include<windows.h>
  
  char buf[6]={0,0,0,0,0x48,0};
  
  DWORD *GetPDE(DWORD addr)
  {
      //return (DWORD *)(0xc0600000 + ((addr >> 18) & 0x3ff8));
      DWORD PDPTI = addr >> 30;
      DWORD PDI = (addr >> 21) & 0x000001FF;
      DWORD PTI = (addr >> 12) & 0x000001FF;
      return (DWORD *)(0xC0600000 + PDPTI * 0x1000 + PDI * 8);
  }
  
  DWORD *GetPTE(DWORD addr)
  {
      //return (DWORD *)(0xc0000000 + ((addr >> 9) & 0x7ffff8));
      DWORD PDPTI = addr >> 30;
      DWORD PDI = (addr >> 21) & 0x000001FF;
      DWORD PTI = (addr >> 12) & 0x000001FF;
      return (DWORD *)(0xC0000000 + PDPTI * 0x200000 + PDI * 0x1000 + PTI * 8);
  }
  
  __declspec(naked) void func()
  {
      __asm
      {
          pushad
          pushfd
      }
  
      *GetPDE(0x8003f048) |=0x00000004;
      *GetPTE(0x8003f048) |=0x00000004;
  
      *GetPTE(0x8003f048) &= 0xFFFFFEFF;
  
      __asm
      {
          popad
          popfd
          iretd
      }
  }
  
  
  
  int main(int argc, char* argv[])
  {
      printf("%x",(DWORD)func);
  
      getchar();
  
      __asm int 0x20;
      printf("0x8003f048 U/S,G位修改成功.\n");
      printf("*(PDWORD)0x8003f048 = %08x\n", *(PDWORD)0x8003f048);
      *(PDWORD)0x8003f048 = 0x12345678;
      printf("*(PDWORD)0x8003f048 = %08x\n", *(PDWORD)0x8003f048);
      getchar();
  
      return 0;
  }
  ```

#### TLB

- 测试这个结构

  代码如下：

  ```c
  //10-10-12下的
  #include <windows.h>
  #include <stdio.h>
  DWORD TempFnAddress;
  void __declspec(naked) Proc()//401030
  {
      _asm
      {
          mov dword ptr ds:[0xc0000000],0x1234967
          mov dword ptr ds:[0],0x12345876
          
          //INVLPG dword ptr ds:[0]
          
          //mov eax,cr3
          //mov cr3,eax
          mov dword ptr ds:[0xc0000000],0x0234567
          mov eax,dword ptr ds:[0]
          mov TempFnAddress,eax
              
          retf
      }
  }
  
  int main(int argc, char* argv[])
  {
  	char buff[6];
  	*(DWORD*)&buff[0] = 0x12345678; // EIP, 废弃
  	*(WORD*)&buff[4] = 0x48; // 段选择子
  	_asm {
  		call far fword ptr[buff]//eq 8003f048 0040EC00`00081030
  	}
      printf("%x\n",TempFnAddress);
  	getchar();
      return 0;
  }
  ```

#### 中断与异常

```
kd> dq idtr
8003f400  804d8e00`0008f50e 804d8e00`0008f68d
8003f410  00008500`0058113e 804dee00`0008faa1
8003f420  804dee00`0008fc24 804d8e00`0008fd89
8003f430  804d8e00`0008ff0a 804e8e00`00080583
8003f440  00008500`00501198 804e8e00`00080988
8003f450  804e8e00`00080aa6 804e8e00`00080be3
8003f460  804e8e00`00080e40 804e8e00`0008113c
8003f470  804e8e00`00081867 804e8e00`00081b9c
kd> dq gdtr
8003f000  00000000`00000000 00cf9b00`0000ffff
8003f010  00cf9300`0000ffff 00cffb00`0000ffff
8003f020  00cff300`0000ffff 80008b04`200020ab
8003f030  ffc093df`f0000001 7f40f3fd`f0000fff
8003f040  0000f200`0400ffff 0040ec00`00081020
8003f050  80008955`87000068 80008b55`87680068
8003f060  00009302`2f40ffff 0000920b`80003fff
8003f070  ff0092ff`700003ff 80009a40`0000ffff
```

师傅说这个`FS`寄存器里面有一个结构体如下：

```c
dt _KPCR ffdff000
nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : 0xffdff000 _KPCR
   +0x020 Prcb             : 0xffdff120 _KPRCB
   +0x024 Irql             : 0x1c ''
   +0x028 IRR              : 0
   +0x02c IrrActive        : 0
   +0x030 IDR              : 0xffff20f8
   +0x034 KdVersionBlock   : 0x80546ab8 Void
   +0x038 IDT              : 0x8003f400 _KIDTENTRY
   +0x03c GDT              : 0x8003f000 _KGDTENTRY
   +0x040 TSS              : 0x80042000 _KTSS
   +0x044 MajorVersion     : 1
   +0x046 MinorVersion     : 1
   +0x048 SetMember        : 1
   +0x04c StallScaleFactor : 0x64
   +0x050 DebugActive      : 0 ''
   +0x051 Number           : 0 ''
   +0x052 Spare0           : 0 ''
   +0x053 SecondLevelCacheAssociativity : 0 ''
   +0x054 VdmAlert         : 0
   +0x058 KernelReserved   : [14] 0
   +0x090 SecondLevelCacheSize : 0
   +0x094 HalReserved      : [16] 0
   +0x0d4 InterruptMode    : 0
   +0x0d8 Spare1           : 0 ''
   +0x0dc KernelReserved2  : [17] 0
   +0x120 PrcbData         : _KPRCB
```

- 分析`IDT`表中`0x2`号中断的执行流程。

  ```
  00008500`0058113e
  58 = 0101 1 000
  index = 11(找gdt表的索引)
  80008b55`87680068    address = 80558768
  kd> dd 80558768
  80558768  00000028 80555700 00000010 00000000
  80558778  00000000 00000000 00000000 00039000
  80558788  804df780 00000000 00000000 00000000
  80558798  00000000 00000000 80555700 00000000
  805587a8  00000000 00000000 00000023 00000008
  805587b8  00000010 00000023 00000030 00000000
  805587c8  00000000 20ac0000 00000000 00000000
  805587d8  80555668 00000000 00000001 0000000a
  这个是个任务段，找到在TSS里面的eip，那么eip = 804df780，在反汇编窗口看一下地址
  ```

  ```asm
      nt!KiTrap02:
  ffffffff`804df780 fa                     cli    ;屏蔽可屏蔽中断
  ffffffff`804df781 64ff3540000000         push    dword ptr fs:[40h]    ;TSS
  ffffffff`804df788 64a13c000000           mov     eax, dword ptr fs:[0000003Ch]    ;GDT
  ffffffff`804df78e 8a685f                 mov     ch, byte ptr [eax+5Fh]
  ffffffff`804df791 8a485c                 mov     cl, byte ptr [eax+5Ch]
  ffffffff`804df794 c1e110                 shl     ecx, 10h
  ffffffff`804df797 668b485a               mov     cx, word ptr [eax+5Ah]
  ffffffff`804df79b 64890d40000000         mov     dword ptr fs:[40h], ecx    ;改TSS
  ffffffff`804df7a2 9c                     pushfd  
  ffffffff`804df7a3 812424ffbfffff         and     dword ptr [esp], 0FFFFBFFFh
  ffffffff`804df7aa 9d                     popfd   
  ffffffff`804df7ab 648b0d3c000000         mov     ecx, dword ptr fs:[3Ch]
  ffffffff`804df7b2 8d4158                 lea     eax, [ecx+58h]
  ffffffff`804df7b5 c6400589               mov     byte ptr [eax+5], 89h
  ffffffff`804df7b9 8b0424                 mov     eax, dword ptr [esp]
  ffffffff`804df7bc 6a00                   push    0
  ffffffff`804df7be 6a00                   push    0
  ffffffff`804df7c0 6a00                   push    0
  ffffffff`804df7c2 6a00                   push    0
  ffffffff`804df7c4 ff7050                 push    dword ptr [eax+50h]
  ffffffff`804df7c7 ff7038                 push    dword ptr [eax+38h]
  ffffffff`804df7ca ff7024                 push    dword ptr [eax+24h]
  ffffffff`804df7cd ff704c                 push    dword ptr [eax+4Ch]
  ffffffff`804df7d0 ff7020                 push    dword ptr [eax+20h]
  ffffffff`804df7d3 6a00                   push    0
  ffffffff`804df7d5 ff703c                 push    dword ptr [eax+3Ch]
  ffffffff`804df7d8 ff7034                 push    dword ptr [eax+34h]
  ffffffff`804df7db ff7040                 push    dword ptr [eax+40h]
  ffffffff`804df7de ff7044                 push    dword ptr [eax+44h]
  ffffffff`804df7e1 ff7058                 push    dword ptr [eax+58h]
  ffffffff`804df7e4 64ff3500000000         push    dword ptr fs:[0]
  ffffffff`804df7eb 6aff                   push    0FFFFFFFFh
  ffffffff`804df7ed ff7028                 push    dword ptr [eax+28h]
  ffffffff`804df7f0 ff702c                 push    dword ptr [eax+2Ch]
  ffffffff`804df7f3 ff7030                 push    dword ptr [eax+30h]
  ffffffff`804df7f6 ff7054                 push    dword ptr [eax+54h]
  ffffffff`804df7f9 ff7048                 push    dword ptr [eax+48h]
  ffffffff`804df7fc ff705c                 push    dword ptr [eax+5Ch]
  ffffffff`804df7ff 6a00                   push    0
  ffffffff`804df801 6a00                   push    0
  ffffffff`804df803 6a00                   push    0
  ffffffff`804df805 6a00                   push    0
  ffffffff`804df807 6a00                   push    0
  ffffffff`804df809 6a00                   push    0
  ffffffff`804df80b 6a00                   push    0
  ffffffff`804df80d 6a00                   push    0
  ffffffff`804df80f 6a00                   push    0
  ffffffff`804df811 6a00                   push    0
  ffffffff`804df813 ff7020                 push    dword ptr [eax+20h]
  ffffffff`804df816 ff703c                 push    dword ptr [eax+3Ch]
  ffffffff`804df819 8bec                   mov     ebp, esp
  ffffffff`804df81b 33db                   xor     ebx, ebx
  ffffffff`804df81d 648a1d51000000         mov     bl, byte ptr fs:[51h]
  ffffffff`804df824 391ddc875580           cmp     dword ptr ds:[805587DCh], ebx
  ffffffff`804df82a 7414                   je      ntkrnlmp!_KiTrap02+0xc0 (804df840)
  ffffffff`804df82c 8d05d8875580           lea     eax, ds:[805587D8h]
  ffffffff`804df832 50                     push    eax
  ffffffff`804df833 6a00                   push    0
  ffffffff`804df835 8bcc                   mov     ecx, esp
  ffffffff`804df837 8bd5                   mov     edx, ebp
  ffffffff`804df839 e8979f0500             call    ntkrnlmp!@KiAcquireQueuedSpinLockCheckForFreeze@8 (805397d5)
  ffffffff`804df83e eb24                   jmp     ntkrnlmp!_KiTrap02+0xe4 (804df864)
  ffffffff`804df840 833de087558008         cmp     dword ptr ds:[805587E0h], 8
  ffffffff`804df847 721b                   jb      ntkrnlmp!_KiTrap02+0xe4 (804df864)
  ffffffff`804df849 7517                   jne     ntkrnlmp!_KiTrap02+0xe2 (804df862)
  ffffffff`804df84b 803d40ca558000         cmp     byte ptr ds:[8055CA40h], 0
  ffffffff`804df852 750e                   jne     ntkrnlmp!_KiTrap02+0xe2 (804df862)
  ffffffff`804df854 803d41ca558000         cmp     byte ptr ds:[8055CA41h], 0
  ffffffff`804df85b 7405                   je      ntkrnlmp!_KiTrap02+0xe2 (804df862)
  ffffffff`804df85d e8c17f0500             call    ntkrnlmp!_KeEnterKernelDebugger@0 (80537823)
  ffffffff`804df862 ebfe                   jmp     ntkrnlmp!_KiTrap02+0xe2 (804df862)
  ffffffff`804df864 891ddc875580           mov     dword ptr ds:[805587DCh], ebx
  ffffffff`804df86a ff05e0875580           inc     dword ptr ds:[805587E0h]
  ffffffff`804df870 6a00                   push    0
  ffffffff`804df872 ff158c904d80           call    dword ptr ds:[804D908Ch]
  ffffffff`804df878 ff0de0875580           dec     dword ptr ds:[805587E0h]
  ffffffff`804df87e 754a                   jne     ntkrnlmp!_KiTrap02+0x14a (804df8ca)
  ffffffff`804df880 c705dc875580ffffffff   mov     dword ptr ds:[805587DCh], 0FFFFFFFFh
  ffffffff`804df88a 8bcc                   mov     ecx, esp
  ffffffff`804df88c e8933c0000             call    ntkrnlmp!@KeReleaseQueuedSpinLockFromDpcLevel@4 (804e3524)
  ffffffff`804df891 83c408                 add     esp, 8
  ffffffff`804df894 64a140000000           mov     eax, dword ptr fs:[00000040h]
  ffffffff`804df89a 66833858               cmp     word ptr [eax], 58h
  ffffffff`804df89e 742a                   je      ntkrnlmp!_KiTrap02+0x14a (804df8ca)
  ffffffff`804df8a0 81c48c000000           add     esp, 8Ch
  ffffffff`804df8a6 648f0540000000         pop     dword ptr fs:[40h]
  ffffffff`804df8ad 648b0d3c000000         mov     ecx, dword ptr fs:[3Ch]
  ffffffff`804df8b4 8d4128                 lea     eax, [ecx+28h]
  ffffffff`804df8b7 c640058b               mov     byte ptr [eax+5], 8Bh
  ffffffff`804df8bb 9c                     pushfd  
  ffffffff`804df8bc 810c2400400000         or      dword ptr [esp], 4000h
  ffffffff`804df8c3 9d                     popfd   
  ffffffff`804df8c4 cf                     iretd   
  ```

- 分析`IDT`表中`0x8`号中断的执行流程。

  ```
  kd> dd 80558700
  ReadVirtual: 80558700 not properly sign extended
  80558700  00000000 80555700 00000010 00000000
  80558710  00000000 00000000 00000000 00039000
  80558720  804e0891 00000000 00000000 00000000
  80558730  00000000 00000000 80555700 00000000
  80558740  00000000 00000000 00000023 00000008
  80558750  00000010 00000023 00000030 00000000
  80558760  00000000 20ac0000 00000028 80555700
  80558770  00000010 00000000 00000000 00000000
  eip = 804e0891
  ```

  ```asm
      nt!KiTrap08:
  ffffffff`804e0891 fa             cli    ;屏蔽可屏蔽中断
  ffffffff`804e0892 648b0d3c000000 mov     ecx, dword ptr fs:[3Ch]
  ffffffff`804e0899 8d4150         lea     eax, [ecx+50h]
  ffffffff`804e089c c6400589       mov     byte ptr [eax+5], 89h
  ffffffff`804e08a0 9c             pushfd  
  ffffffff`804e08a1 812424ffbfffff and     dword ptr [esp], 0FFFFBFFFh
  ffffffff`804e08a8 9d             popfd   
  ffffffff`804e08a9 64a13c000000   mov     eax, dword ptr fs:[0000003Ch]
  ffffffff`804e08af 8a6857         mov     ch, byte ptr [eax+57h]
  ffffffff`804e08b2 8a4854         mov     cl, byte ptr [eax+54h]
  ffffffff`804e08b5 c1e110         shl     ecx, 10h
  ffffffff`804e08b8 668b4852       mov     cx, word ptr [eax+52h]
  ffffffff`804e08bc 64a140000000   mov     eax, dword ptr fs:[00000040h]
  ffffffff`804e08c2 64890d40000000 mov     dword ptr fs:[40h], ecx
  ffffffff`804e08c9 6a00           push    0
  ffffffff`804e08cb 6a00           push    0
  ffffffff`804e08cd 6a00           push    0
  ffffffff`804e08cf 50             push    eax
  ffffffff`804e08d0 6a08           push    8
  ffffffff`804e08d2 6a7f           push    7Fh
  ffffffff`804e08d4 e811720500     call    ntkrnlmp!_KeBugCheck2@24 (80537aea)
  ffffffff`804e08d9 ebee           jmp     ntkrnlmp!_KiTrap08+0x38 (804e08c9)
  ffffffff`804e08db 90             nop     
  ```


#### 阶段测试

- 给定一个线性地址，和长度，读取内容；

  `int ReadMemory(OUT BYTE* buffer，IN DWORD dwAddr，IN DWORD dwLeght)` 

  要求：

  1. 可以自己指定分页方式。
  2. 页不存在，要提示，不能报错。
  3. 可以正确读取数据。

  

- 申请长度为`100`的`DWORD`的数组，且每项用该项的地址初始化；

  把这个数组所在的物理页挂到`0x1000`的地址上；定义一个指针，指向`0x1000`这个页里的数组所在的地址，用`0x1000`这个页的线性地址打印出这数组的值；

  要求：数组所在的物理页，是同一个页

  ```c
  #include<windows.h>
  #include <stdio.h>
  DWORD* arr;
  
  DWORD* GetPDE(DWORD addr)
  {
      return (DWORD*)(0xc0600000+((addr>>18)&0x3ff8));
  }
  
  DWORD* GetPTE(DWORD addr)
  {
      return (DWORD*)(0xc0000000+((addr>>9)&0x7ffff8));
  }
  
  __declspec(naked) void func()
  {
      __asm
      {
          pushad
          pushfd
      }
      *GetPTE(0x1000)|=*GetPTE((DWORD)arr);
      __asm
      {
          popfd
          popad
          iretd
      }
  }
  
  int main(int argc, char* argv[])
  {
      int i=0;
      unsigned long* p;
      char buff[6];
  	*(DWORD*)&buff[0] = 0x12345678; // EIP, 废弃
  	*(WORD*)&buff[4] = 0x48; // 段选择子
      arr=(DWORD*)VirtualAlloc(0,0x1000,MEM_COMMIT,PAGE_READWRITE);
      if (arr == NULL) {
          printf("Memory allocation failed.\n");
          return 1;
      }
      
      for(i=0;i<100;i++)
      {
          arr[i]=(DWORD)(arr);
      }
      printf("eq 8003f500 %04xee00`0008%04x",(DWORD)func>>16,(DWORD)func&0x0000ffff);//调用门描述符为：0000EC00`00080000
      getchar();
      //__asm int 0x20
  	_asm {
  		call far fword ptr[buff]
  	}
  
      p=(DWORD*)(0x1000);
  
      //printf("%x\n",p);
  
      for(i=0;i<100;i++)
      {
          printf("%x:%x\n",i,p[i]);
      }
      getchar();
      return 0;
  }
  ```

### 驱动

#### 01

- 申请一块内存，并在内存中存储`GDT`，`IDT`的所有数据。然后在`debugview`中显示出来，最后释放内存。

  ```c
  #include <ntddk.h>
  
  //卸载函数
  VOID DriverUnload(PDRIVER_OBJECT driver)
  {
  	DbgPrint("驱动程序停止运行了\n");
  }
  
  //入口函数，相当于main
  NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
  {
  	//驱动程序入口
  	//内核开辟空间
  	PULONG AddrTemp = 0;
  	ULONG StartAddr = 0x8003F000;
  	ULONG i= 0;
  	PULONG Addr = (PULONG)ExAllocatePool(NonPagedPool,0x10000);
  	//初始化
  	RtlFillMemory(Addr,0x10000,0);
  	//从GDT和IDT拷贝数据
  	//GDT 0x8003F000 0x3FF 0x8003F000 0x7FF
  	RtlMoveMemory(Addr,(CONST VOID UNALIGNED*)StartAddr,0xBFE);
  
  	AddrTemp = (PULONG)Addr;
  	
  	for (i=0;i<0x40;i++)
  	{
  		DbgPrint("%08X  %08X %08X %08X %08X",StartAddr,*(AddrTemp+1),*AddrTemp,*(AddrTemp+3),*(AddrTemp+2));	
  		AddrTemp+=4; //为什么1和3在前面? 为了和windbg显示一样，换了一下次序
  		StartAddr+=0x10;
  	}
  	DbgPrint("GDT表打印完毕");
  	for (i=0;i<0x80;i++)
  	{
  		DbgPrint("%08X  %08X %08X %08X %08X",StartAddr,*(AddrTemp+1),*AddrTemp,*(AddrTemp+3),*(AddrTemp+2));
  		AddrTemp+=4;
  		StartAddr+=0x10;
  	}
  
  	DbgPrint("IDT表打印完毕");
  	
  	//free释放
  	ExFreePool(Addr);
  
  	//设置一个卸载函数，便于退出
  	driver->DriverUnload = DriverUnload;
  	return STATUS_SUCCESS;
  }
  ```

- 编写代码，实现如下功能：
  1.  初始化一个字符串
  2.  拷贝一个字符串
  3.  比较两个字符串是否相等
  4.  `ANSI_STRING`与`UNICODE_STRING`字符串相互转换
  
  ```c
  #include <ntddk.h>
  
  //卸载函数
  VOID DriverUnload(PDRIVER_OBJECT driver)
  {
  	DbgPrint("驱动程序停止运行了");
  }
  
  //入口函数，相当于main
  NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)
  {
  	ANSI_STRING ANString1;
  	ANSI_STRING ANString2;
  	UNICODE_STRING StrUnicode;
  	RtlInitAnsiString(&ANString1,"ANString1");
  	RtlInitAnsiString(&ANString2,"ANString2");
  	RtlInitUnicodeString(&StrUnicode,L"StrUnicode");
  	
  	DbgPrint("ANString1 = %Z\n",&ANString1);
  	DbgPrint("ANString2 = %Z\n",&ANString2);
  	DbgPrint("StrUnicode = %wZ\n",&StrUnicode);
  
  	if (RtlCompareString(&ANString1,&ANString2,TRUE) == 0)
  	{
  		DbgPrint("ANString1 = ANString2");
  	}
  	else
  	{
  		DbgPrint("字符串不相等.\r\n");
  	}
  
  	RtlCopyString(&ANString2,&ANString1);
  
  	DbgPrint("ANString1 = %Z\n",&ANString1);
  	DbgPrint("ANString2 = %Z\n",&ANString2);
  	DbgPrint("StrUnicode = %wZ\n",&StrUnicode);
  
  	if (RtlAnsiStringToUnicodeString(&StrUnicode,&ANString1,TRUE) == STATUS_SUCCESS)
  	{
  		DbgPrint("ANString1 = %Z\n",&ANString1);
  		DbgPrint("ANString2 = %Z\n",&ANString2);
  		DbgPrint("StrUnicode = %wZ\n",&StrUnicode);
  	}
  	driver->DriverUnload = DriverUnload;
  	return STATUS_SUCCESS;
  }
  ```

#### 02

- 遍历内核模块，输出模块名称，基址以及大小。

  ```c
  #include <ntddk.h>    //驱动程序必备头文件
  
  NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
  {
      DbgPrint("Unloaded Successfully!");
  }
  
  NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
  {
      LIST_ENTRY* list = (LIST_ENTRY*)DriverObject->DriverSection;
      LIST_ENTRY* item = list;
      DRIVER_OBJECT obj;
  	while (1)
      {
          PUNICODE_STRING name = (PUNICODE_STRING)(((UINT32)item) + 0x2c);
          UINT32 DllBase = *(UINT32*)(((UINT32)item) + 0x18);
          UINT32 ImgSize= *(UINT32*)(((UINT32)item) + 0x20);
          DbgPrint("DriverName : %wZ\nDllBase : %x\nImgSize : %x\n======\n", name, DllBase, ImgSize);
  
          item = item->Blink;
          if (item == list)
          {
              break;
          }
      }
  
      DriverObject->DriverUnload = UnloadDriver;
      return STATUS_SUCCESS;
  }
  ```

- 编写一个函数，通过特征码搜索一个未导出的函数，并调用。

  例子:找到`PspTerminateProcess`，通过调用这个函数结束记事本进程。（注意`10-10-12`分页是`ntoskrnl.exe`，`2-9-9-12`是`ntkrnlpa.exe`）

  ```c
  #include <ntddk.h>    //驱动程序必备头文件
  #include <wdm.h>
  
  NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject)
  {
      DbgPrint("Unloaded Successfully!");
  }
  
  PVOID Search( PVOID featureCode,  UINT32 featureCodeeLen,  PVOID BeginAddress,  PVOID EndAddress)
  {
       PVOID pCur = BeginAddress;
       while (pCur != EndAddress)
       {
           if (RtlCompareMemory(featureCode, pCur, featureCodeeLen) == featureCodeeLen)
           {
               // 指向函数首地址
               return ( PUINT32 )(( UINT32 )pCur - 6);
           }
           (( UINT32 )pCur)++;
       }
       return 0;
  }
  
  typedef NTSTATUS(*_PspTerminateProcess)(PEPROCESS pEprocess, NTSTATUS ExitCode);
  _PspTerminateProcess PspTerminateProcess;
  PEPROCESS GetPROCESS( PCHAR processName)
  {
       PEPROCESS pEprocess, pCurProcess;
       PCHAR ImageFileName;
   
       // 获取当前进程的EPROCESS
       __asm
       {
           mov eax, fs: [0x124] ;       // 获取指向 _KTHREAD 的指针
           mov eax, [eax + 0x44];       // 获取指向 _KPROCESS 的指针， 即EPROCESS 的首地址
           mov pEprocess, eax;
       }
   
       pCurProcess = pEprocess;
   
       // 遍历EPROCESS
       do
       {
           ImageFileName = ( PCHAR )pCurProcess + 0x174;      // 进程名
           if ( strcmp (ImageFileName, processName) == 0)
           {   
               return pCurProcess;
           }
           pCurProcess = (PEPROCESS)(*( PULONG )(( ULONG )pCurProcess + 0x88) - 0x88);   // 更新进程
   
       }  while (pEprocess != pCurProcess);
   
       return 0;
  }
  
  NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
  {
      LIST_ENTRY* lethis = (LIST_ENTRY*)DriverObject->DriverSection;
      LIST_ENTRY* item = lethis;
  	UINT32 DllBase = 0;
  	UINT32 ImgSize = 0;
  	UNICODE_STRING krnl;
  	PEPROCESS Extprocess;
  
  	RtlInitUnicodeString(&krnl, L"ntoskrnl.exe");
  
  	while (1)
      {
          PUNICODE_STRING name = (PUNICODE_STRING)(((UINT32)item) + 0x2c);
          UINT32 ImgSize= *(UINT32*)(((UINT32)item) + 0x20);
          if (!RtlCompareUnicodeString(name,&krnl,FALSE))
          {
              DllBase = *(UINT32*)(((UINT32)item) + 0x18);
              break;
          }
  
          item = item->Blink;
          if (item == lethis)
          {
  			DbgPrint( "not found\n");
              break;
          }
  
      }
  
  	Extprocess = GetPROCESS( "notepad.exe" );
      DbgPrint( "process：%p.\n" , Extprocess);
      if (Extprocess == 0)
      {
  		DbgPrint( "error\n");
  		DriverObject->DriverUnload = UnloadDriver;
  		return STATUS_SUCCESS;
      }
  
  if (DllBase)
      {
          PspTerminateProcess = (_PspTerminateProcess)(DllBase + 0xF1DA4);    //0xF1DA4 就是偏移
          PspTerminateProcess(Extprocess, 0); 
      }
  
  	DbgPrint( "关了\n" );
  
      DriverObject->DriverUnload = UnloadDriver;
      return STATUS_SUCCESS;
  }
  ```
  
  
