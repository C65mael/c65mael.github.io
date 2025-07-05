---
title: Obfu
cascade:
  type: docs
---

### VM

###### 代码块与变异

- 代码块定义：由程序执行流程中发生跳转的指令作为分隔线划分出来的代码内容，代码块不等于函数块，因为函数块具有一定的格式。（`vm`中分隔代码块的分隔线是变异）

  循环代码块（`vm`指令）：是虚拟机分配任务的一种处理程序。

- 代码变异：改变代码的执行顺序但是逻辑是不变的，就是改变了位置

  `jmp xxx`属性：不影响标志位、重定位、栈
  
  简单的代码通过加`jmp`的方式使流程变复杂了：
  
  ```mermaid
  graph TB
      A[L1:\nmov eax,eax\nadd eax,ecx\njmp L2]
      B[L3:\npop esp\nretf]
      C[push ebp\npush ecx\njmp L1]
      D[L2:\nadd ecx,eax\npop ebp\njmp L3]
      A ~~~ B ~~~ C ~~~ D
      A --> D
      C --> A
      D --> B
  ```
  
  处理指令大致流程如下：
  
  ```mermaid
  graph TB
      A[vcpu循环结构（代码执行）]
      B[读取v指令]
      C[vADD]
      
      A --> B
      B --> A
      A --> C
      C --> A
  ```
  

###### 函数调用流程

![image](/myassets-Obfu/vm1.png)

- 退出虚拟机寄存器保持一致，恢复到原`x86CPU`或`x64CPU`。`eflag`也是。
- 特点：
  1. 虚拟化一个函数，调用函数肯定会退出虚拟机（或者把调用的`API`也给`VM`了）
  2. 虚拟机执行到一个函数时，指令也随之结束
  3. 函数调用与退出的时候会重新进入虚拟机
  4. 遇到无法模拟的指令则会退出虚拟机，执行完无法模拟的指令后重新进入虚拟机

###### 流程结构

虚拟机流程结构大致如下：

![image](/myassets-Obfu/vm2.png)

###### 参数转移

- 应该是`VM`两个不同的函数后如果参数（细节）相同，那么就会将这两个函数变成一个函数进行无缝执行。

  流程大致如下：

  ![image](/myassets-Obfu/vm3.png)

- 当程序无缝执行后（比如上图）是无法捕捉到`vfunc2`的特征的，只能捕捉的就是`vfunctotal`执行后的返回值等属性。

- 之前说过`虚拟化一个函数，调用函数肯定会退出虚拟机`，但是无缝执行中的函数调用不会退出虚拟机。

###### 合流



###### 代码漂移

- 

###### 栈机

- 栈机指的是一种计算机体系结构，在这种体系结构中，大部分操作都依赖于一个操作数栈来完成。

- 不同解释：

  - 正常我们遇到的大多数是寄存器机，用寄存器传递参数，比如两个数字相加：

    ```asm
    mov eax, 0x1145
    mov ebx, 0x14    ;之后取值就直接使用寄存器取值了
    add eax, ebx
    ```

  - 栈机则是通过栈传参数（与`pwn`的`ROP`传参有点类似）

    ```asm
    push 0x1145
    push 0x14    ;取值可以通过esp加偏移取值，操作性更强
    mov eax,[esp+4]
    add eax,[esp]
    pop ebx    ;平栈
    pop ebx
    ```

###### 堆机

- 堆的特点：

  1. 地址不固定（可能需要处理重定位）
  2. 需要动态分配（`alloc`）

- 实现如下：

  ```mermaid
  graph TB
      A[进入虚拟机]
      B[进入栈模式架构的虚拟机（栈机）]
      C[栈模式架构分配一定空间（GetModuleHandle（））]
      D[经过重定位处理的shellcode写入堆]
      E[vEIP转移]
      A --> B
      B --> C
      C --> D
      D --> E
  ```

- 可以动态修复地址：

  ```asm
  call Lab1
  
  Lab1：
  pop eax
  ;eax为call的下一行的地址，可以算出重定位地址
  ```


###### opcode

参考代码如下，实现弹两个信息框：

```asm
.386
option casemap:none
.model flat,stdcall

include user32.inc
includelib user32.lib


.data

	g_MessageBoxMy db 00,00,00,00,00,\
					00,00,00,00,00,\
					00,00,00,00,00,\
					00,00,00,00,00,
					00
					g_offsetMessage dd 00
					db 01

.data
	g_handletable dd offset vPush,offset vCall
	g_dispatchFun dd ?

.code

vPush proc

	mov eax,dword ptr [esi]
	push eax
	add esi,4
	jmp g_dispatchFun

vPush endp

vCall proc

	mov eax,dword ptr [esp]
	add esp,4
	push offset vEntry
	jmp eax
	jmp g_dispatchFun

vCall endp

vEntry proc

	ret

vEntry endp

Main proc uses esi

	mov g_offsetMessage,OFFSET MessageBoxA
	mov g_dispatchFun,LOOP_OPCODE
	
	mov esi,offset g_MessageBoxMy
	LOOP_OPCODE:
	movzx edx,byte ptr [esi]
	inc esi

	jmp dword ptr [g_handletable + edx * 4]

	ret

Main endp

end Main
```

大概逻辑如下：

1. 首先获取`opcode`的第一位，判断是什么虚拟指令
2. 如果是`00`，则为`vPush`，则进入`vPush`进行处理
3. 在`vPush`里面会将`4`字节压入栈中，然后将`opcode`加`4`。如此循环直到压入`g_offsetMessage`就是`MessageBoxA`的地址。
4. 之后取出`01`，为`vCall`（`edx=1`，跳转到`g_handletable`的第二个），进入`vCall`进行处理
5. 在`vCall`里面会取出`esp`位置的值，将栈降低`4`字节（相当于`Push eax`），之后压入返回地址`vEntry`，就跳到`eax`执行`MessageBoxA`。

###### 代码变形

- 一条指令可能由多条指令组合，每次编译都不同
- 可以实现一堆等价的汇编代码构成一个库，然后通过随机数去替换原理的汇编代码，达到变形

###### 膨胀

- 将一行汇编指令等价的变（替换）为多行汇编指令，增大代码量

- 自膨胀需要一定的媒介（比如栈）

  ```asm
  mov eax, ecx
  
  
  膨胀0：
  push ecx
  pop eax
  
  
  膨胀1：
  sub esp, 4
  mov [esp], ecx
  
  mov eax, [esp]
  add esp, 4
  
  
  膨胀2：
  mov ebx, 2
  shl ebx, 1
  sub esp, ebx
  
  lea edi, [esp]
  mov edx, ecx
  mov [edi], edx
  
  lea edi, [esp]
  mov edx, [edi]
  mov eax, edx
  
  mov ebx, 8
  shr ebx, 1
  add esp, ebx
  ```

- 保证：

  - 保证寄存器、标志位、栈不被影响
  - 保证异常的顺序正常
  - 自膨胀过程中优先使用寄存器膨胀（因为寄存器的效率大于栈）

###### 分发

- `vmp2.x`的流程分发为`vm_dispatch`

  `vmp3.x`的流程方法为`vm_handle`，也就是只有执行了上一个`handle`才会确定并执行下一个`handle`

###### 万用门

- `vmp2.x`：`nor`

  `vmp3.x`：`nor`（或非门），`nand`（与非门）

- 与非门：

  ```c++
  //根据德摩根律推导
  not(a) = nand(a)
  and(a,b) = nand(nand(a,b),nand(a,b))
  or(a,b) = nand(nand(a,a),nand(b,b))
  xor(a,b) = nand(nand(nand(a,a),b),nand(a,nand(b,b)))
      
  nand(1,0) = !(1 & 0) = 1
  nand(1,1) = !(1 & 1) = 0
  ```

- 或非门：

  ```c++
  //根据德摩根律推导
  not(a) = nor(a)
  and(a,b) = nor(nor(a,a),nor(b,b))
  or(a,b) = nor(nor(a,b),nor(a,b))
  xor(a,b) = nor(nor(nor(a,a),nor(b,b)),nor(a,b))
  ```

  
