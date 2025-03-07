---
title: Windows EXT
description: kernel
date: 2024-06-04 00:00:00
categories:
- Kernel
---

### 保护模式

###### 保护模式概述

‍保护模式分为段机制和页机制。

理解：想象一下你家的电脑就像一个大厨房，里面有很多小帮手在做不同的事情，比如煮汤、炒菜等等。保护模式就是为了保证这个大厨房的秩序和安全。首先，保护模式就像是给每个小帮手配了一套专属的工具，他们不能随便用别人的工具，也不能乱碰别人的食材。这样做的好处是，即使其中一个小帮手犯错了，也不会影响到其他小帮手(**防止一个进程访问或修改另一个进程的内存数据**)。其次，保护模式给了每个小帮手一个身份证，分成两类：一类是高级厨师，一类是普通厨师。高级厨师有更多的权限，可以做更多的事情，比如烧开水等。而普通厨师的权限就少一些，不能做一些危险的事情。这样可以防止有人乱来，比如一个不懂规矩的小帮手想烧开水，但是他只是个普通厨师，就不能执行这个操作(**内核模式具有更高的特权级别，可以执行更多的操作，而用户模式受到更多的限制**)。再来，保护模式还给了每个小帮手一个梦幻厨房，虽然实际上只有一个大厨房，但是每个小帮手都觉得自己有一个属于自己的梦幻厨房。这样就不会出现争抢厨房的情况，大家都可以安心做自己的事情(**操作系统可以为每个进程提供虚拟内存，使得每个进程都认为自己拥有连续的内存空间**)。最后，保护模式还让这些小帮手轮流工作，每个人都有自己的时间段做事情，不会出现一个人霸占厨房不肯给别人机会的情况，这样大家都有机会工作，效率也更高(**操作系统可以同时运行多个进程，并实现进程之间的时间片轮转调度，使得多个程序可以并发执行**)。

###### 段寄存器结构

段寄存器一共有CS SS DS ES FS GS LDTR TR 共8个。

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
   - **G**：LIMIT的单位，该位 0 表示单位是字节(0xfffff)，1表示单位是 4KB(0xffffffff)
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
  
- `狗多半零安，乐，破地皮两树，停`

```
总结：
如果 G = 0，把段描述符中的 20 bit LIMIT取出来，比如 0x003ff，然后在前面补 0 至32bit，即 limit = 0x000003ff
如果 G = 1，把段描述符中的 20 bit LIMIT取出来，比如 0x003ff，然后在后面补 f 至 32bit, 即 LIMIT = 0x003fffff
```

**S**: 该位为 1 表示这是一个**数据段**或者**代码段**。为 0 表示这是一个系统段（比如调用门，中断门等）

额我们先找**数据段**或者**代码段**，s位的不同会导致TYPE域发生变化。这张图是TYPE域满足什么条件下是数据段或代码段：

![image](https://c65mael.github.io/myassets/type.png)

1. 因为DPL的值只可能是全1或全0，所以16~12位如果是数据段或代码段的话只能为f(1111)或9(1001)。`那么在段描述符中找第五位，如果是f或9就是数据段或代码段`。
2. 因为TYPE域的第11位只可能是1或0，而且全为1是代码段；全为0是数据段。`那么第六位大于8就是代码段，小于8就是数据段`。

来看数据段的标志位：

- E：如果为1，表示向下扩展(右图)；E=0，表示向上扩展(左图)，windows只使用向上扩展，也就是E为0
- W：如果为1，代表该数据段描述符是可写的
- A：如果为1，代表该数据段描述符已经被访问过了

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

- 通俗的理解：当前段选择子的权限

- 比较`mov ax,0008`与`mov ax,000B`并且之后均执行`mov ds,ax`的区别

  (区别是8的二进制为`1000`，B的二进制为`1011`，无别就在于最后的两位所代表的RPL不同)

  将段描述指向的是同一个段描述符，但RPL是不一样的.

**数据段的权限检查参考如下代码:**

- 比如当前程序处于0环,也就是说CPL=0

  ```assembly
  mov ax,000B		//1011也就是RPL = 3 
  mov ds,ax		//ax指向的段描述符的DPL = 0
  ```

数据段的权限检查：

`CPL <= DPL` 并且 `RPL <= DPL` (数值E8比较)

注意：代码段和系统段描述符中的检查方式并不一样。

总结一下：

```
CPL -> CPU当前的权限级别
DPL -> 如果你想访问我,你应该具备什么样的权限
RPL -> 用什么权限去访问一个段(比如高权限可以用低权限访问)
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

所以如下：

```
0000 0000 0000 0000 -> Offset
1110 -> P、DPL、S
1100 -> Type
0000 0000 -> 0 - 7位
0x0000EC00

低32位段选择子可以设为0x0008（对应0环代码段）、0x001B（对应3环代码段）
0x00080000

加上偏移就可以使用了
```

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

1. **可屏蔽中断**就像是你房间里的门铃，你可以选择要不要打开门去接待访客。
2. **不可屏蔽中断**就像是火警响了，这是一个紧急情况，你不能选择不管它。

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

9~12位（缺页异常）

![image](https://c65mael.github.io/myassets/wuxiaoPTE.png)

- 内存紧张时，当CPU发现某一线性地址访问频率不是特别高时，操作系统就会把这个地址的内容存到文件里面，并且将P位置0。
- 当CPU访问一个地址，如果其PTE的P位为0，此时会产生缺页异常。（此时走`e`号中断）

G位

​	如果G位为1刷新`TLB`时将不会刷新`PDE/PTE`的G位为1的页，G=1切换进程该`PTE`扔然有效(这里学完`TLB`才能明白)

(PDE)PS位

  这个位只对`PDE`有意义。如果`PS == 1`，则`PDE`直接指向物理页（高20位就是物理页），不再指向`PTE`，`10-10-12`的低22位是页内偏移。它的大小为`4MB`，俗称“大页”。

(PTE)D 位

  脏位，指示是否被写过。若没有被写过为`0`，被写过为`1`。

A 位

  是否被访问，即是否被读或者写过，如果被访问过则置`1`。即使访问了一字节也是1。

R/W 位

  如果`R/W = 0`，表示是只读的，反之为可读可写。

U/S 位

  如果`U/S = 0`，则为特权用户（super user），即非3环权限。反之，则为普通用户，即为3环权限。

P 位

  表示`PDE`或者`PTE`是否有效，如果有效为`1`，反之为`0`。

###### 页目录表基址

如果系统要保证某个线性地址是有效的，必须为其填充正确的`PDE`与`PTE`，如果我们想填充`PDE`与`PTE`那么必须能够访问。有的人会想，直接拿`CR3`去填写就行了，还需要页目录表基址干嘛？操作系统只能用线性地址，不能用物理地址。`CR3`存储的是物理地址，这个是给`CPU`看的，不是给操作系统看的。操作系统访问它就必须知道它的线性地址才行。`CPU`可不帮我们挂物理页，它做不到这点，只能提供要求标准，而操作系统按照标准进行办事。于是乎页目录表基址与页表基址这两个东西就出现了。

通过页目录表基址，操作系统可以帮我们程序挂上正确的`PDE`，通过页表基址挂上正确的`PTE`，然后指向正确的物理页。

1. 通过`0xC0300000`找到的物理页就是页目录表，这个物理页即是页目录表本身也是页表
2. 页目录表是一张特殊的页表，每一项`PTE`指向的不是普通的物理页，而是指向其他的页表
3. 结论：`0xC0300000`存储的值就是`PDT`，如果我们要访问第N个`PDE`，那么有如下公式:`0xC0300000 +N*4`

![image](https://c65mael.github.io/myassets/ymlbjz.png)

```
0xC0300000
1100 0000 00|11 0000 0000 000
1：1100 0000 00 == 300*4
2：1100 0000 00 == 300*4
3：0
```

###### 页表基址

仅仅知道页目录表基址只能访问一个线性地址的`PDE`。但是`PTE`我们没办法知道（因为如果程序使用页目录表基址是没办法访`PTE`的）。与页目录表基址类似，通过页表基址就可以访问`PTT`，也就是地址`0xC0000000`。

1. 页表被映射到了从`0xC0000000`到`0xC03FFFFF`的`4M`地址空间
2. 在这1024个表中有一张特殊的表：页目录表
3. 页目录被映射到了`0xC0300000`开始处的`4K`地址空间

**PDI与PTI**

因为`PDE`是页目录表项，`PTE`是页表项。那么`PDI`就是页目录表索引，而`PTI`就是页表索引（`Index`）。在我们的`10-10-12`分页中，第一个10就是`PDI`，第二个10就是`PTI`，12就是物理页的页内偏移。

- 访问页目录表的公式：`0xC0300000 + PDI * 4`
- 访问页表的公式：`0xC0000000 + PDI * 4096 + PTI * 4`（就是挨个差一个页`0x1000`）

![image](https://c65mael.github.io/myassets/ybjz.png)

```
!vtop Cr3 线性地址
通过这个指令可以直接得到PDE和PTE😊
```

###### 2-9-9-12分页（PAE分页）

先回顾一下10-10-12分页：

- 为什么是12：因为最后要找的物理页大小为`4kb`，所以需要`2^12`来覆盖所有的地址，也就是所谓的页内偏移。
- `PTT`里面的`PTE`指向物理页，`PTE`一共有`1024`个所以需要`2^10`来找全`1024`个成员，也就是所谓的`PDI`。
- `PDT`里面的`PDE`指向`PTT`，与`PTE`类似，所以也需要`2^10`来找全`1024`个成员，也就是所谓的`PTI`。
- 通过以上，`CPU`通过`10-10-12`分页可以找到的内存一共有`4GB`，这个通过`CPU`识别的内存可不是通过上面的表乘起来的，是因为一个内存地址最多只有`32`位，所以可以找到的内存为`2^32 = 4GB`。

为什么要有`2-9-9-12`分页，其实还是物理页不够用了，需要扩展。主要就是将地址的长度变长了，物理地址由`32`位改为了`36`位。那么`PDE`与`PTE`也要将`base`增加`4`位，`4`字节对齐之后就是`8`字节。对`PTT`来说成员数量从`1024`个变为了`512`个，所以需要`2^9`来索引；与`PDT`一样，所以也需要`2^9`来索引。这就是两个`9`的来源。通过之前的改变应该可以算出来一个`PDT`就代表能够索引`1GB`的内存，所以在前面又有叫`PDPTE`的结构来指向`PDT`，这个`PDPTE`结构有`8`个字节，所以这个结构一共有`4`个。这就是`2`的来源。这样就可以索引一个`4GB`的内存啦！

![image](https://c65mael.github.io/myassets/29912.png)

**PDPTT结构：**

![image](https://c65mael.github.io/myassets/pdpte.png)

- `PDPTE`共有四项（第一个`2`）
- `35~12`存储的是页目录表的基址，低`12`位补`0`，共`36`位，即页目录基址。
- 其中，`Avali`位是给操作系统使用的。

**PDE结构：**

![image](https://c65mael.github.io/myassets/29912pdes.png)

↑是一般页

![image](https://c65mael.github.io/myassets/29912pdel.png)

↑是大页

注意：

- 当`PS=1`时是大页， `35-21`位是大页的物理地址，这样`36`位的物理地址的低`21`位为`0`，这就意味着页的大小为`2MB`，且都是`2MB`对齐。
- 当`PS=0`时，`35-12`位是页表基址，低`12`位补`0`，共`36`位。

**PTE结构：**

![image](https://c65mael.github.io/myassets/29912pte.png)

注意：

- `PTE`中`35-12`是物理页基址，`24`位，低`12`位补`0`

  `物理页基址+12位`的页内偏移指向具体数据

**XD位：**

它是一个位，处于`PDE`和`PTE`的最高位。其实就是`linux`保护机制里面的`NX`(禁止执行)，`NX`是栈上的内容不可执行；而`XD`是数据区不可执行，如果最高位是`1`，说明被保护。如果这个是数据区，且这个`X`位被置为`1`，则会被报出异常不能执行。

![image](https://c65mael.github.io/myassets/xd.png)

**公式总结：**

```c
2(PDPTI)-9(PDI)-9(PTI)-12(OFFSET)

pPDE = 0xc0600000 + (PDPTI*4KB) + (PDI*8)
pPTE = 0xc0000000 + (PDPTI*2MB) + (PDI*4KB) + (PTI*8)
```

针对MmIsAddressValid的公式如下：

```c
pPDE = (int*)(0xc0600000 + ((addr >> 18) & 0x3ff8))
pPTE = (int*)(0xc0000000 + ((addr >> 9) & 0x7ffff8))
```

###### TLB

- `TLB(Translation Lookaside Buffer)`其实就是实现了一个物理地址对线性地址的映射关系，提供缓存提高读写效率。

- 结构如下：

  | LA（线性地址） | PA（物理地址） | ATTR（属性） | LRU（统计） |
  | -------------- | -------------- | ------------ | ----------- |
  | 0x81010111     | ……             | ……           | 1           |

  其中：

  1.  ATTR（属性）：如果是`2-9-9-12`分页，属性是`PDPE`、`PDE`、`PTE`三个属性相**&&**。如果是`10-10-12`分页就是`PDE`和`PTE`两个属性相**&&**。
  2. 不同的`CPU`这个表的大小不一样。
  3. 只要`Cr3`变了，`TLB`立马刷新，一核一套`TLB`。

  操作系统的高2G映射基本不变，如果`Cr3`改了，`TLB`刷新重建高`2G`以上很浪费。所以`PDE`和`PTE`中有个`G`标志位，如果`G`位为1刷新`TLB`时将不会刷新`PDE/PTE`的`G`位为1的页，当`TLB`满了，根据统计信息将不常用的地址废弃，最近最常用的保留。

- `TLB`有不同的种类，用于不同的缓存目的，它在`X86`体系里的实际应用最早是从`Intel`的`486CPU`开始的，在`X86`体系的`CPU`里边，一般都设有如下`4`组`TLB`：

  - 第一组：缓存一般页表（`4K`字节页面）的指令页表缓存：`Instruction-TLB`
  - 第二组：缓存一般页表（`4K`字节页面）的数据页表缓存：`Data-TLB`
  - 第三组：缓存大尺寸页表（`2M/4M`字节页面）的指令页表缓存：`Instruction-TLB`
  - 第四组：缓存大尺寸页表（`2M/4M`字节页面）的数据页表缓存：`Data-TLB`

###### 中断与异常

**什么是中断？**

1. 中断通常是由`CPU`外部的输入输出设备（硬件）所触发的，供外部设备通知`CPU` "有事情需要处理" ，因此又叫中断请求（`Interrupt Request`）
2. 中断请求的目的是希望`CPU`暂时停止执行当前正在执行的程序，转去执行中断请求所对应的中断处理例程（中断处理程序在哪由`IDT`表决定）
3. `80×86`有两条中断请求线：
   - 非屏蔽中断线，称为`NMI` (`NonMaskable Interrupt`)
   - 可屏蔽中断线，称为`INTR`（`Interrupt Require`）

**非屏蔽中断如何处理？**

- `CPU`会查`IDT`表中的`2`号中断：

  | （IDT表）中断号 |     NMI      |         说明         |
  | :-------------: | :----------: | :------------------: |
  |      `0x2`      | 不可屏蔽中断 | `80x86`中固定为`0x2` |

- 解释：当非可屏蔽中断产生时，`CPU`在执行完当前指令后会里面进入中断处理程序。非可屏蔽中断不受`EFLAG`寄存器中`IF`位的影响，一旦发生，`CPU`**必须**处理非可屏蔽中断处理程序位于`IDT`表中的`2`号位置

**可屏蔽中断**

- 在硬件级，可屏蔽中断是由一块专门的芯片来管理的，通常称为中断控制器。它负责分配中断资源和管理各个中断源发出的中断请求为了便于标识各个中断请求，中断管理器通常用`IRQ`（`Interrupt Request`）后面加上数字来表示不同的中断。
- 比如：在`Windows`中时钟中断的`IRQ`编号为`0`也就是：`IRQ0`

**可屏蔽中断如何处理？**

- 中断号如下：

  | （IDT表）中断号 |     IRQ      |        说明        |
  | :-------------: | :----------: | :----------------: |
  |     `0x30`      |    `IRQ0`    |      时钟中断      |
  |   `0x31~0x3F`   | `IRQ1~IRQ15` | 其他硬件设备的中断 |

- 解释：

  1. 如果自己的程序执行时不希望`CPU`去处理这些中断，可以

     用`CLI`指令清空`EFLAG`寄存器中的`IF`位

     用`STI`指令设置`EFLAG`寄存器中的`IF`位

  2. 硬件中断与`IDT`表中的对应关系并非固定不变的，参见：`APIC`（高级可编程中断控制器）

**异常**

- 异常通常是`CPU`在执行指令时检测到的某些错误，比如除`0`、访问无效页面等。中断与异常的区别：

  1. 中断来自于外部设备，是中断源（比如键盘）发起的，`CPU`是被动的
  2. 异常来自于`CPU`本身，是`CPU`主动产生的
  3. `INT N`虽然被称为 "软件中断" ，但其本质是异常。`EFLAG`的`IF`位对`INT N`无效

- 无论是由硬件设备触发的中断请求还是由`CPU`产生的异常，处理程序都在`IDT`表。

  常见异常处理的对应调用号：

  | 错误类型 | （IDT表）中断号 |
  | :------: | :-------------: |
  |  页错误  |      `0xE`      |
  |  段错误  |      `0xD`      |
  | 除零错误 |      `0x0`      |
  | 双重错误 |      `0x8`      |


###### 控制寄存器

- 控制寄存器用于控制和确定`CPU`的操作模式

  一共有`5`个控制寄存器：`Cr0，Cr1，Cr2，Cr3，Cr4`

  其中`Cr1`保留，`Cr3`为页目录表基址

  - **Cr0寄存器**

    ![image](https://c65mael.github.io/myassets/cr0.png)

    - `PE`位是启用保护模式（`Protection Enable`）标志。

      若`PE = 1`是开启保护模式，反之为实地址模式。这个标志仅开启段级保护，而并没有启用分页机制。若要启用分页机制，那么`PE`和`PG`标志都要置位。

    - `PG`位是启用分页机制。在开启这个标志之前必须已经或者同时开启`PE`标志。

      `PG = 0`且`PE = 0`，处理器工作在实地址模式下。

      `PG = 0`且`PE = 1`，处理器工作在没有开启分页机制的保护模式下。

      `PG = 1`且`PE = 0`，在`PE`没有开启的情况下无法开启`PG`。

      `PG = 1`且`PE = 1`，处理器工作在开启了分页机制的保护模式下。

    - `WP`位对于`Intel 80486`或以上的`CPU`，是写保护（`Write Proctect`）标志。当设置该标志时，处理器会禁止超级用户程序（例如特权级0的程序）向用户级只读页面执行写操作；

      当`CPL < 3`的时候：

      如果`WP = 0`可以读写任意用户级物理页，只要线性地址有效。

      如果`WP = 1`可以读取任意用户级物理页，但对于只读的物理页，则不能写。

  - **Cr2寄存器**

    ![image](https://c65mael.github.io/myassets/cr2.png)

    当`CPU`访问某个无效页面时，会产生缺页异常，此时，`CPU`会将引起异常的线性地址存放在`Cr2`中。

  - **Cr4寄存器**

    ![image](https://c65mael.github.io/myassets/cr4.png)

    - `PAE = 1`是`2-9-9-12`分页`PAE = 0`是`10-10-12`分页。其实就是那个`boot.ini`文件里面我们修改的那个来判断的，操作系统希望我们用什么样的分页来启动操作系统。

    - `PSE`是大页是否开启的总开关，如果置`0`，就算`PDE`中设置了大页你也得是普通的页。

      | PSE  |  PS  | 分页类型 | 页大小 |
      | :--: | :--: | :------: | :----: |
      |  1   |  1   | 2-9-9-12 |   2M   |
      |  1   |  0   | 2-9-9-12 |   4K   |
      |  1   |  1   | 10-10-12 |   4M   |
      |  1   |  0   | 10-10-12 |   4K   |
      |      |      |          |        |
      |  0   |  1   | 2-9-9-12 |   4K   |
      |  0   |  0   | 2-9-9-12 |   4K   |
      |  0   |  1   | 10-10-12 |   4K   |
      |  0   |  0   | 10-10-12 |   4K   |

###### PWT 与 PCD

**CPU缓存**

- `CPU`缓存是位于`CPU`与物理内存之间的临时存储器，它的容量比内存小的多但是交换速度却比内存要快得多。它可以做的很大。

- `CPU`缓存与`TLB`类似但有所不同，`TLB`存的是线性地址与物理地址的对应关系，`CPU`缓存存的是物理地址与内容对应关系。

  | CPU缓存的对应关系 | TLB的对应关系 |
  | :---------------: | :-----------: |
  |     物理地址      |   线性地址    |
  |       内容        |   物理地址    |

- `PWT_PCD`:

  `PWT`全称为`Page Write Through`，`PWT = 1`时，写`Cache`的时候也要将数据写入内存中。

  `PCD`全称为`Page Cache Disable`，`PCD = 1`时，禁止某个页写入缓存，直接写内存。比如，做页表用的页，已经存储在`TLB`中了，可能不需要再缓存了。

### 驱动

###### 环境

- 先从32位的系统开始学习，安装一下`VS2010`+`WDK7600`，远古版本。

- 里面设置属性表的代码如下：

  ```html
  <?xml version="1.0" encoding="utf-8"?>
  <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
    <ImportGroup Label="PropertySheets" />
    <PropertyGroup Label="UserMacros" />
    <PropertyGroup>
      <ExecutablePath>C:\WinDDK\7600.16385.1\bin\x86;$(ExecutablePath)</ExecutablePath>
    </PropertyGroup>
    <PropertyGroup>
      <IncludePath>C:\WinDDK\7600.16385.1\inc\api;C:\WinDDK\7600.16385.1\inc\ddk;C:\WinDDK\7600.16385.1\inc\crt;$(IncludePath)</IncludePath>
    </PropertyGroup>
    <PropertyGroup>
      <LibraryPath>C:\WinDDK\7600.16385.1\lib\win7\i386;$(LibraryPath)</LibraryPath>
      <TargetExt>.sys</TargetExt>
      <LinkIncremental>false</LinkIncremental>
      <GenerateManifest>false</GenerateManifest>
    </PropertyGroup>
    <ItemDefinitionGroup>
      <ClCompile>
        <PreprocessorDefinitions>_X86_;DBG</PreprocessorDefinitions>
        <CallingConvention>StdCall</CallingConvention>
        <ExceptionHandling>false</ExceptionHandling>
        <BasicRuntimeChecks>Default</BasicRuntimeChecks>
        <BufferSecurityCheck>false</BufferSecurityCheck>
        <CompileAs>Default</CompileAs>
        <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
      </ClCompile>
      <Link>
        <AdditionalDependencies>ntoskrnl.lib;wdm.lib;wdmsec.lib;wmilib.lib;ndis.lib;Hal.lib;MSVCRT.LIB;LIBCMT.LIB;%(AdditionalDependencies)</AdditionalDependencies>
      </Link>
      <Link>
        <IgnoreAllDefaultLibraries>true</IgnoreAllDefaultLibraries>
        <EnableUAC>false</EnableUAC>
        <SubSystem>Native</SubSystem>
        <EntryPointSymbol>DriverEntry</EntryPointSymbol>
        <BaseAddress>0x10000</BaseAddress>
        <RandomizedBaseAddress>
        </RandomizedBaseAddress>
        <DataExecutionPrevention>
        </DataExecutionPrevention>
        <GenerateDebugInformation>true</GenerateDebugInformation>
        <Driver>Driver</Driver>
      </Link>
    </ItemDefinitionGroup>
    <ItemGroup />
  </Project>
  ```

  记住要修改`C:\WinDDK\7600.16385.1`这个为`WDK`的路径。

###### 内核编程基础

- 在应用层编程我们可以使用`WINDOWS`提供的各种`API`函数，只要导入头文件`windows.h`就可以了。但是在内核编程的时候，微软为内核程序提供了专用的`API`，只要在程序中包含相应的头文件就可以使用了，如：`#include <ntddk.h>`，假设你安装了`WDK`。

  为什么要用两个头文件：为了安全，因为内核很脆弱，用`3`环的头文件就压力大了；而且一个没进`0`环一个进`0`环了，不一样。

- 在应用层编程的时候，我们通过`MSDN`来了解函数的详细信息，在内核编程的时候，要使用`WDK`自己的帮助文档。

- `WDK`说明文档中只包含了内核模块导出的函数，对于未导出的函数，则不能直接使用。如果要德用未导出的函数，只要自己定义一个函数指针，并且为函数指针提供正确的函数地址就可以使用了。有两种办法都可以获取为导出的函数地址：

  1. 特征码搜索
  2. 解析内核`PDB`文件（就是`windbg`中可以使用`u 函数名`来获取函数的反汇编的原因）

  > |     补充     |                     解释                     |
  > | :----------: | :------------------------------------------: |
  > |  未导出函数  | 导出表里面没有该函数，文档里面自然没有该函数 |
  > | 未文档化函数 | 文档里面没有写该函数，但在导出表里面有该函数 |

- **基本数据类型**

  1. 在内核编程的时候，强烈建议大家遵守`WDK`的编码习惯，建议不要这样写：`unsigned long length;`，建议这样写：`ULONG length`。

  2. 习惯使用WDK自己的类型：

     | WDK 习惯 |    SDK 习惯    |
     | :------: | :------------: |
     |  ULONG   | unsigned long  |
     |  PULONG  | unsigned long* |
     |  UCHAR   | unsigned char  |
     |  PUCHAR  | unsigned char* |
     |   UINT   |  unsigned int  |
     |  PUNIT   | unsigned int*  |
     |   VOID   |      void      |
     |  PVOID   |     void*      |

- **返回值**

  大部分内核函数的返回值都是`NTSTATUS`类型，如：

  ```c
  NTSTATUS PsCreateSystemThread();
  NTSTATUS ZwOpenProcess();
  NTSTATUS ZwOpenEvent();
  ```

  这个值能说明函数执行的结果，比如：

  ```c
  #define STATUS_SUCCESS 0x00000000    //成功
  #define STATUS_INVALID_PARAMETER 0xC000000D    //参数无效
  #define STATUS_BUFFER_OVERFLOW 0x80000005    //缓冲区长度不够
  ……
  //这里每一个值都有一个对应的宏，那么在执行一个内核函数后可以判断返回值为STATUS_XXXXXX，就可以判断函数的执行状态了，可读性好一些
  ```

  当你调用的内核函数，如果返回的结果不是`STATUS_SUCCESS`，就说明函数执行中遇到了问题，具体是什么问题，可以在`ntstatus.h`文件中查看。

- **异常处理**

  在内核中，一个小小的错误就可能导致蓝屏，比如：读写一个无效的内存地址。为了让自己的内核程序更加健壮，强烈建议大家在编写内核程序时，使用异常处理。

  `Windows`提供了结构化异常处理机制，一般的编译器都是支持的，如下：

  ```c
  __try{
      //可能出错的代码
  }
  __except(filter_value) {
      //出错时要执行的代码
  }
  ```

  出现异常时，可根据`filter_value`的值来决定程序该如果执行，当`filter_value`的值为：

  1. `EXCEPTION_EXECUTE_HANDLER(1)`：代码进入`except`块
  2. `EXCEPTION_CONTINUE_SEARCH(0)`：不处理异常，由上一层调用函数处理
  3. `EXCEPTION_CONTINUE_EXECUTION(-1)`：回去继续执行错误处的代码

- **常用的内核内存函数**

  对内存的使用，主要就是：申请、设置、拷贝以及释放。

  | c语言  |        内核中         |
  | :----: | :-------------------: |
  | malloc | ExAllocatePoolWithTag |
  | memset |     RtlFillMemory     |
  | memcpy |     RtlMoveMemory     |
  |  free  |      ExFreePool       |

  > 请注意`ExAllocatePoolWithTag`函数的`POOL_TYPE PoolType`参数：
  >
  > ```c
  > typedef enum _POOL_TYPE {
  >   NonPagedPool,
  >   PagedPool,
  >   NonPagedPoolMustSucceed,
  >   DontUseThisType,
  >   NonPagedPoolCacheAligned,
  >   PagedPoolCacheAligned,
  >   NonPagedPoolCacheAlignedMustS
  > } POOL_TYPE;
  > ```
  >
  > `NonPagedPool`代表非分页内存，`PagedPool`代表分页内存
  >
  > 非分页内存：物理页很重要，系统不会放到硬盘上的内存（常驻，存代码）
  >
  > 分页内存：物理页没那么重要，允许把物理页写到硬盘上的内存（存数据）

- **IRQL**

  - 什么是中断请求级别：就是`CPU`在执行时会遇到中断时会执行中断程序，但是如果在执行时又遇到了中断，这时该执行哪个中断程序呢？此时就需要看两个中断的中断级别了（中断是分等级的！），如果现在`CPU`执行中断的等级高于又遇到的中断，那么就忽略这个新来的中断；否则就会终止当前的中断程序，转去执行新来的中断程序（被打断了）。
  - `IRQL`是`Windows`自己定义的一套优先级方案，与`CPU`无关，**数值越大权限越高，相同权限无法互相打断，只有更高的权限才能打断**。
  - `CPU`任何时刻必须必须在`IRQL`中处于某一等级。

  ![image](https://c65mael.github.io/myassets/IRQL.png)
  
- **内核字符串种类**

  在编写3环程序我们经常用：`CHAR(char)`/`WCHAR(wchar_t)`来分别表示宅字符串和宽字符串，用0表示结尾。但是在内核中，我们常用：`ANSI_STRING`/`UNICODE_STRING`来分别表示宅字符串和宽字符串。它们的结构如下：

  `ANSI_STRING`字符串：

  ```c
  typedef struct _STRING
  {
      USHORT Length;
      USHORT MaximumLength;
      PCHAR Buffer;
  }STRING;
  ```

  `UNICODE_STRING`字符串：

  ```c
  typedef struct _UNICODE_STRING
  {
      USHORT Length;
      USHORT MaxmumLength;
      PWSTR Buffer;
  } UNICODE_STRING;
  ```

- **内核字符串常用函数**

  符串常用的功能无非就是：创建、复制、比较以及转换等等。

  |  操作  |      ANSI_STRING字符串       |     UNICODE_STRING字符串     |
  | :----: | :--------------------------: | :--------------------------: |
  | 初始化 |      RtlInitAnsiString       |     RtlInitUnicodeString     |
  |  拷贝  |        RtlCopyString         |     RtlCopyUnicodeString     |
  |  比较  |       RtlCompareString       |   RtlCompareUnicodeString    |
  |  转换  | RtlAnsiStringToUnicodeString | RtlUnicodeStringToAnsiString |

###### 内核空间与内核模块

- 之前了解到，每个进程都有`4GB`虚拟空间，而且低`2GB`所对应的物理页基本不同；高`2GB`内存所对应的物理页基本相同（共用）

  ![image](https://c65mael.github.io/myassets/kerkj.png)

- 硬件种类繁多，不可能做一个兼容所有硬件的内核，所以，微软提供规定的接口格式，让硬件驱动人员安装规定的格式编写**驱动程序** 。

  在内核中，这些驱动程序每一个都是一个模块，称为**内核模块**，都可以加载到内核中，都遵守`PE`结构。但本质上讲，任意一个`sys`文件与内核文件没有区别。每个驱动都是一个模块。就和在`3`环的程序加载`dll`一样，加载一个贴上一个。

  ![image](https://c65mael.github.io/myassets/kermk.png)

- 做练习可以了解到入口函数为`NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path)`，需要注意它的第一个参数：

  - `DRIVER_OBJECT`（驱动对象）描述了当前该模块的一些重要信息

    ```c
    kd> dt _DRIVER_OBJECT
    nt!_DRIVER_OBJECT
       +0x000 Type             : Int2B
       +0x002 Size             : Int2B
       +0x004 DeviceObject     : Ptr32 _DEVICE_OBJECT
       +0x008 Flags            : Uint4B
       +0x00c DriverStart      : Ptr32 Void    //驱动从哪里开始的
       +0x010 DriverSize       : Uint4B    //部署的驱动有多大
       +0x014 DriverSection    : Ptr32 Void
       +0x018 DriverExtension  : Ptr32 _DRIVER_EXTENSION
       +0x01c DriverName       : _UNICODE_STRING    //驱动叫什么名字
       +0x024 HardwareDatabase : Ptr32 _UNICODE_STRING
       +0x028 FastIoDispatch   : Ptr32 _FAST_IO_DISPATCH
       +0x02c DriverInit       : Ptr32     long 
       +0x030 DriverStartIo    : Ptr32     void 
       +0x034 DriverUnload     : Ptr32     void 
       +0x038 MajorFunction    : [28] Ptr32     long 
    ```

    请注意里面的成员`DriverSection`，一个指针对应结构体的双向循环链表`LDR_DATA_TABLE_ENTRY`，它圈着内核里面的所有模块（就是查看成员`InLoadOrderLinks`就行了）
    
    ```c
    kd> dt _LDR_DATA_TABLE_ENTRY
    nt!_LDR_DATA_TABLE_ENTRY
       +0x000 InLoadOrderLinks : _LIST_ENTRY
       +0x008 InMemoryOrderLinks : _LIST_ENTRY
       +0x010 InInitializationOrderLinks : _LIST_ENTRY
       +0x018 DllBase          : Ptr32 Void
       +0x01c EntryPoint       : Ptr32 Void
       +0x020 SizeOfImage      : Uint4B
       +0x024 FullDllName      : _UNICODE_STRING
       +0x02c BaseDllName      : _UNICODE_STRING
       +0x034 Flags            : Uint4B
       +0x038 LoadCount        : Uint2B
       +0x03a TlsIndex         : Uint2B
       +0x03c HashLinks        : _LIST_ENTRY
       +0x03c SectionPointer   : Ptr32 Void
       +0x040 CheckSum         : Uint4B
       +0x044 TimeDateStamp    : Uint4B
       +0x044 LoadedImports    : Ptr32 Void
       +0x048 EntryPointActivationContext : Ptr32 Void
       +0x04c PatchInformation : Ptr32 Void
    ```
    
  - 我们使用工具将驱动加载的第一步就是先注册驱动，就是在注册表里面写上驱动，第二个参数`reg_path`就是将驱动写在注册表里面的什么地方
  
  - > 在`3`环里面，有一块内存描述线程的信息，就是`TEB`。`FS:[0]`就指向这个结构体：
    >
    > ```c
    > kd> dt _TEB
    > nt!_TEB
    >    +0x000 NtTib            : _NT_TIB
    >    +0x01c EnvironmentPointer : Ptr32 Void
    >    +0x020 ClientId         : _CLIENT_ID
    >    +0x028 ActiveRpcHandle  : Ptr32 Void
    >    +0x02c ThreadLocalStoragePointer : Ptr32 Void
    >    +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
    >    +0x034 LastErrorValue   : Uint4B
    >    +0x038 CountOfOwnedCriticalSections : Uint4B
    >    +0x03c CsrClientThread  : Ptr32 Void
    >    +0x040 Win32ThreadInfo  : Ptr32 Void
    >    +0x044 User32Reserved   : [26] Uint4B
    >    +0x0ac UserReserved     : [5] Uint4B
    >    +0x0c0 WOW32Reserved    : Ptr32 Void
    >    +0x0c4 CurrentLocale    : Uint4B
    >    +0x0c8 FpSoftwareStatusRegister : Uint4B
    >    +0x0cc SystemReserved1  : [54] Ptr32 Void
    >    +0x1a4 ExceptionCode    : Int4B
    >    +0x1a8 ActivationContextStack : _ACTIVATION_CONTEXT_STACK
    >    +0x1bc SpareBytes1      : [24] UChar
    >    +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
    >    +0x6b4 RealClientId     : _CLIENT_ID
    >    +0x6bc GdiCachedProcessHandle : Ptr32 Void
    >    +0x6c0 GdiClientPID     : Uint4B
    >    +0x6c4 GdiClientTID     : Uint4B
    >    +0x6c8 GdiThreadLocalInfo : Ptr32 Void
    >    +0x6cc Win32ClientInfo  : [62] Uint4B
    >    +0x7c4 glDispatchTable  : [233] Ptr32 Void
    >    +0xb68 glReserved1      : [29] Uint4B
    >    +0xbdc glReserved2      : Ptr32 Void
    >    +0xbe0 glSectionInfo    : Ptr32 Void
    >    +0xbe4 glSection        : Ptr32 Void
    >    +0xbe8 glTable          : Ptr32 Void
    >    +0xbec glCurrentRC      : Ptr32 Void
    >    +0xbf0 glContext        : Ptr32 Void
    >    +0xbf4 LastStatusValue  : Uint4B
    >    +0xbf8 StaticUnicodeString : _UNICODE_STRING
    >    +0xc00 StaticUnicodeBuffer : [261] Uint2B
    >    +0xe0c DeallocationStack : Ptr32 Void
    >    +0xe10 TlsSlots         : [64] Ptr32 Void
    >    +0xf10 TlsLinks         : _LIST_ENTRY
    >    +0xf18 Vdm              : Ptr32 Void
    >    +0xf1c ReservedForNtRpc : Ptr32 Void
    >    +0xf20 DbgSsReserved    : [2] Ptr32 Void
    >    +0xf28 HardErrorsAreDisabled : Uint4B
    >    +0xf2c Instrumentation  : [16] Ptr32 Void
    >    +0xf6c WinSockData      : Ptr32 Void
    >    +0xf70 GdiBatchCount    : Uint4B
    >    +0xf74 InDbgPrint       : UChar
    >    +0xf75 FreeStackOnTermination : UChar
    >    +0xf76 HasFiberData     : UChar
    >    +0xf77 IdealProcessor   : UChar
    >    +0xf78 Spare3           : Uint4B
    >    +0xf7c ReservedForPerf  : Ptr32 Void
    >    +0xf80 ReservedForOle   : Ptr32 Void
    >    +0xf84 WaitingOnLoaderLock : Uint4B
    >    +0xf88 Wx86Thread       : _Wx86ThreadState
    >    +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
    >    +0xf98 ImpersonationLocale : Uint4B
    >    +0xf9c IsImpersonating  : Uint4B
    >    +0xfa0 NlsCache         : Ptr32 Void
    >    +0xfa4 pShimData        : Ptr32 Void
    >    +0xfa8 HeapVirtualAffinity : Uint4B
    >    +0xfac CurrentTransactionHandle : Ptr32 Void
    >    +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
    >    +0xfb4 SafeThunkCall    : UChar
    >    +0xfb5 BooleanSpare     : [3] UChar
    > ```
    >
    > 可以看到，在`TEB`的成员中的`0x30`，存储着进程环境块（`PEB`）。它描述着进程里面的信息：
    >
    > ```c
    > kd> dt _PEB
    > nt!_PEB
    >    +0x000 InheritedAddressSpace : UChar
    >    +0x001 ReadImageFileExecOptions : UChar
    >    +0x002 BeingDebugged    : UChar
    >    +0x003 SpareBool        : UChar
    >    +0x004 Mutant           : Ptr32 Void
    >    +0x008 ImageBaseAddress : Ptr32 Void
    >    +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
    >    +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
    >    +0x014 SubSystemData    : Ptr32 Void
    >    +0x018 ProcessHeap      : Ptr32 Void
    >    +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
    >    +0x020 FastPebLockRoutine : Ptr32 Void
    >    +0x024 FastPebUnlockRoutine : Ptr32 Void
    >    +0x028 EnvironmentUpdateCount : Uint4B
    >    +0x02c KernelCallbackTable : Ptr32 Void
    >    +0x030 SystemReserved   : [1] Uint4B
    >    +0x034 AtlThunkSListPtr32 : Uint4B
    >    +0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
    >    +0x03c TlsExpansionCounter : Uint4B
    >    +0x040 TlsBitmap        : Ptr32 Void
    >    +0x044 TlsBitmapBits    : [2] Uint4B
    >    +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
    >    +0x050 ReadOnlySharedMemoryHeap : Ptr32 Void
    >    +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
    >    +0x058 AnsiCodePageData : Ptr32 Void
    >    +0x05c OemCodePageData  : Ptr32 Void
    >    +0x060 UnicodeCaseTableData : Ptr32 Void
    >    +0x064 NumberOfProcessors : Uint4B
    >    +0x068 NtGlobalFlag     : Uint4B
    >    +0x070 CriticalSectionTimeout : _LARGE_INTEGER
    >    +0x078 HeapSegmentReserve : Uint4B
    >    +0x07c HeapSegmentCommit : Uint4B
    >    +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
    >    +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
    >    +0x088 NumberOfHeaps    : Uint4B
    >    +0x08c MaximumNumberOfHeaps : Uint4B
    >    +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
    >    +0x094 GdiSharedHandleTable : Ptr32 Void
    >    +0x098 ProcessStarterHelper : Ptr32 Void
    >    +0x09c GdiDCAttributeList : Uint4B
    >    +0x0a0 LoaderLock       : Ptr32 Void
    >    +0x0a4 OSMajorVersion   : Uint4B
    >    +0x0a8 OSMinorVersion   : Uint4B
    >    +0x0ac OSBuildNumber    : Uint2B
    >    +0x0ae OSCSDVersion     : Uint2B
    >    +0x0b0 OSPlatformId     : Uint4B
    >    +0x0b4 ImageSubsystem   : Uint4B
    >    +0x0b8 ImageSubsystemMajorVersion : Uint4B
    >    +0x0bc ImageSubsystemMinorVersion : Uint4B
    >    +0x0c0 ImageProcessAffinityMask : Uint4B
    >    +0x0c4 GdiHandleBuffer  : [34] Uint4B
    >    +0x14c PostProcessInitRoutine : Ptr32     void 
    >    +0x150 TlsExpansionBitmap : Ptr32 Void
    >    +0x154 TlsExpansionBitmapBits : [32] Uint4B
    >    +0x1d4 SessionId        : Uint4B
    >    +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
    >    +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
    >    +0x1e8 pShimData        : Ptr32 Void
    >    +0x1ec AppCompatInfo    : Ptr32 Void
    >    +0x1f0 CSDVersion       : _UNICODE_STRING
    >    +0x1f8 ActivationContextData : Ptr32 Void
    >    +0x1fc ProcessAssemblyStorageMap : Ptr32 Void
    >    +0x200 SystemDefaultActivationContextData : Ptr32 Void
    >    +0x204 SystemAssemblyStorageMap : Ptr32 Void
    >    +0x208 MinimumStackCommit : Uint4B
    > ```
    >
    > 看`PEB`，里面`0x00c`处的`Ldr`，里面存放着`3`个链表：
    >
    > ```c
    > kd> dt _PEB_LDR_DATA
    > nt!_PEB_LDR_DATA
    >    +0x000 Length           : Uint4B
    >    +0x004 Initialized      : UChar
    >    +0x008 SsHandle         : Ptr32 Void
    >    +0x00c InLoadOrderModuleList : _LIST_ENTRY    //<=第一个（加载顺序）
    >    +0x014 InMemoryOrderModuleList : _LIST_ENTRY    //<=第二个（内存顺序）
    >    +0x01c InInitializationOrderModuleList : _LIST_ENTRY    //<=第三个（初始化顺序）
    >    +0x024 EntryInProgress  : Ptr32 Void
    > ```
    >
    > 这三个链表记录了当前进程有哪些模块，与`0`环的`LDR_DATA_TABLE_ENTRY`类似

###### 0环与3环通信(常规方式)

- **设备对象**

  我们在开发窗口程序的时候，消息被封装成一个结构体：`MSG`。在内核开发时，消息被封装成另外一个结构体：`IRP`（`I/O Request Package`）。

  在窗口程序中，能够接收消息的只能是窗口对象。在内核中，能够接收`IRP`消息的只能是设备对象。

  ![image](https://c65mael.github.io/myassets/shebeiduixiang.png)

- 通信流程

  1. **创建设备对象**

     如何理解：正常来说一个设备对象对应一个硬件，但是也可以什么都不对应，就是一个抽象的概念：只有结构体没有硬件

     ```c
     //创建设备名称
     UNICODE_STRING Devicename;
     RtlInitUnicodeString(&Devicename,L"\\Device\\MyDevice");
     
     //创建设备
     IoCreateDevice(
         pDriver,    //当前设备所属的驱动对象，一个设备对象必须属于某一个驱动对象
         0,
         &Devicename,    //设备对象的名称
         FILE_DEVICE_UNKNOWN,    //没有对应的设备就是这个UNKNOWN
         FILE_DEVICE_SECURE_OPEN,
         FALSE,
         &pDeviceObj    //设备对象指针
     );
     ```

  2. **设置交互数据的方式**

     ```c
     pDeviceObj->Flags |= DO_BUFFERED_IO;
     ```

     - 缓冲区方式读写(`DO_BUFFERED_IO`) ：操作系统将应用程序提供缓冲区的数据复制到内核模式下的地址中。

     - 直接方式读写`(DO_DIRECT_IO`) ：操作系统会将用户模式下的缓冲区锁住。然后操作系统将这段缓冲区在内核模式地址再次映射一遍。这样，用户模式的缓冲区和内核模式的缓冲区指向的是同一区域的物理内存。缺点就是要单独占用物理页面。

     - 其他方式读写（在调用`IoCreateDevice`创建设备后对`pDevObj->Flags`即不设置`DO_BUFFERED_IO`也不设置`DO_DIRECT_IO`此时就是其他方式。）

       在使用其他方式读写设备时，派遣函数直接读写应用程序提供的缓冲区地址。在驱动程序中，直接操作应用程序的缓冲区地址是很危险的。只有驱动程序与应用程序运行在相同线程上下文的情况下，才能使用这种方式。如果`CPU`中的任务切换了，即`CR3`切换掉了，在高`2GB`的驱动仍在使用该方式读取低`2GB`内存，导致读到的数据和实际不符，导致错误，故强烈不推荐此方式。

  3. **创建符号链接**

     - 就是让3环的程序找到你的驱动对象。设备名称的作用是给内核对象用的，如果要在3环访问，必须要有符号链接。其实就是一个别名，没有这个别名，在3环不可见。

       ```c
       //创建符号链接名称
       RtlInitUnicodeString(&SymbolicLinkName,L"\\??\\MyTestDriver");
       
       //创建符号链接
       IoCreateSymbolicLink(&SymbolicLinkName,&Devicename);
       ```

     - 内核模式下，符号链接是以`\??\`开头的，如C盘就是`\??\C:`。而在用户模式下，则是以`\\.\`开头的，如C盘就是`\\.\C:`

  4. **IRP**

     类比一下，在图形界面上是通过鼠标单击或双机来调用回调函数，而在内核里面则是通过调用对应的函数来执行派遣函数的

     ![image](https://c65mael.github.io/myassets/cksbduixiang.png)

     在3环调用`CreateFile`函数，操作系统就会封装一个`IRP`派发给设备对象，设备对象通过`IRP`的类型调用对应的派发函数。

     当应用层通过`CreateFile`、`ReadFile`、`WriteFile`、`CloseHandle`等函数打开、从设备读取数据、向设备写入数据、关闭设备的时候，会使操作系统分别产生出`IRP_MJ_CREATE`、`IRP_MJ_READ`、`IRP_MJ_WRITE`、`IRP_MJ_CLOSE`等不同的`IRP`。

     其他类型的`IRP`：

     |        IRP类型        |                    来源                     |
     | :-------------------: | :-----------------------------------------: |
     | IRP_MJ_DEVICE_CONTROL | 使用 DeviceControl 函数时产生（最多的方式） |
     |     IRP_MJ_POWER      |        在操作系统处理电源消息时产生         |
     |    IRP_MJ_SHUTDOWN    |              关闭系统前时产生               |

  5. **派遣函数**

     如何注册派遣函数：其实每一个`IRP`都对应一个值，那么你提供的派遣函数就应该写在成员`MajorFunction`下标对应的位置。

     ```c
     kd> dt _DRIVER_OBJECT
     ntdll!_DRIVER_OBJECT
        +0x000 Type             : Int2B
        +0x002 Size             : Int2B
        +0x004 DeviceObject     : Ptr32 _DEVICE_OBJECT
        +0x008 Flags            : Uint4B
        +0x00c DriverStart      : Ptr32 Void
        +0x010 DriverSize       : Uint4B
        +0x014 DriverSection    : Ptr32 Void
        +0x018 DriverExtension  : Ptr32 _DRIVER_EXTENSION
        +0x01c DriverName       : _UNICODE_STRING
        +0x024 HardwareDatabase : Ptr32 _UNICODE_STRING
        +0x028 FastIoDispatch   : Ptr32 _FAST_IO_DISPATCH
        +0x02c DriverInit       : Ptr32     long 
        +0x030 DriverStartIo    : Ptr32     void 
        +0x034 DriverUnload     : Ptr32     void 
        +0x038 MajorFunction    : [28] Ptr32     long 
     ```
  
     代码形式：
  
     ```c
     //设置卸载函数
     pDriverObject->DriverUnload = 卸载函数;
     
     //设置派遣函数
     pDriverObject->MajorFunction[IRP_MJ_CREATE] = 派遣函数1;
     pDriverObject->MajorFunction[IRP_MJ_CLOSE] = 派遣函数2;
     pDriverObject->MajorFunction[IRP_MJ_WRITE] = 派遣函数3;
     pDriverObject->MajorFunction[IRP_MJ_READ] = 派遣函数4;
     pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = 派遣函数5;
     pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = 派遣函数6;
     pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = 派遣函数7;
     pDriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = 派遣函数8;
     pDriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = 派遣函数9;
     ```
  
     **派遣函数的格式**
  
     ```c
     NTSTATUS MyDispatchFunction(PDEVICE_OBJECT pDevObj, PIRP pIrp)
     {
         //处理自己的业务……
     
         //设置返回状态
         pIrp->IoStatus.Status = STATUS_SUCCESS;    //GetLastError() 函数得到的就是该值
         pIrp->IoStatus.Information = 0;    //返回给3环多少数据 没有填0
         IoCompleteRequest(pIrp, IO_NO_INCREMENT);
         return STATUS_SUCCESS;
     }
     ```
  
- 

  
