---
title: Crack
cascade:
  type: docs
---

###### 流程

- 程序执行的逻辑可以理解为如下：

  ```mermaid
  graph TB
      A[点击注册按钮] --> B[读取注册码];
      B --> C[判断注册码是否合法];
      C --T--> D[提示用户是否注册成功];
      C --F--> F[提示用户是否注册失败];
      F --> C[判断注册码是否合法];
      D --> C[判断注册码是否合法];
  ```

  关键就是`判断注册码是否合法`这一步。

  主要其实就是让程序断在注册失败的位置，然后单步跟程序返回到判断的位置。如果提示是弹窗的话就可以下断在`MessageBoxA`的最后面。

- `IDA`里面进行中文搜索：在目标中添加后缀`-dCULTURE=all`

###### 调试

- 进程与线程是宿主与寄宿者的关系，一个提供资源，一个使用资源。

- 调试寄存器

  ![image](/myassets-crack/tsjcq.png)

  需要注意的如下：

  - `DR0-DR3`

      这四个寄存器用于存储最多四个硬件断点的线性地址

  - `DR6`

    `DR6`寄存器是调试状态寄存器，用于指示调试异常 (`#DB`) 发生的原因和状态

  - `L0, L1, L2, L3`

    这四个位分别对应`4`个硬件断点（`DR0 ~ DR3`），用于控制断点在仅对当前任务（或当前线程）层面是否生效。当任务切换时，这些断点会被自动清除或失效。

  - `G0, G1, G2, G3`

    这四个位也分别对应`4`个硬件断点（`DR0 ~ DR3`），用于控制断点在“全局”层面（在所有任务中都生效，不随任务切换而失效）是否启用。

  - 关于`Dr7=1`可以断，`Dr7=2`断不下来？的思考：

    由于`Gx`是设置全局断点的，设置的硬件断点将在所有任务和进程中都有效，大多数操作系统不会让你真正地对全局断点生效，要么直接忽略，要么在下一次切换或写寄存器时清掉那个`Gx`位，导致实际执行时并没有开启硬件断点，于是“断不下来”。一般设置`Lx`就可以了。


###### 带壳调试

- 壳的加载过程：

  ```mermaid
  graph TB
      A[运行程序] --> B[在内存中吐出真正的的代码];
      B --> C[转到真实的OEP];
      C --> D[执行真实的代码];
  	D --> E[执行到我们需要下断点的位置];
  ```

  在壳解码后的断点可以下`CreatWindowExA`，`LoadLibraryA`。在对应位置下硬件访问断点可以看到壳是在什么位置给我们吐代码的。

  注意下断点时`CreatWindowExA`与`CreatWindowExW`都下，不是所有的`A`都调用`W`

###### 花指令

- 花指令的思路：构造恒成立的跳转，中间插无效数据。花指令防`IDA`，防不了动态调试。
- 去花指令的话可以在`IDA`中调试，遇到小跳的跳过去，然后把当前指令的上面直到比较的指令全部`nop`掉就行

###### TLS（线程局部存储）

- 特征：先于`OEP`执行

- 函数解释：

  `NtSetInformationThread`：调用这个函数时，如果在第二个参数里指定`0x11`这个值（意思是`ThreadHideFromDebugger`），等于告诉操作系统，将所有附加的调试器统统取消掉。

  `NtQueryInformationProcess`：它的第二个参数可以用来查询进程的调试端口。如果进程被调试，那么返回的端口值会是`-1`，否则就是其他的值。

- 反调试案例：

  ```c++
  #include <windows.h>
  #include <stdio.h>
  #include "ntdll/ntdll.h"
  
  #pragma comment(linker,"/INCLUDE:_tls_used")
  
  DWORD isDebug = 0;
  
  void NTAPI TLS_CALLBACK(PVOID DLLHandle,DWORD Reason,PVOID Reserved)
  {
  	if(Reason == DLL_PROCESS_ATTACH){
  		NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
  		NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, (PVOID)&isDebug, sizeof(DWORD), NULL);
  	}
  }
  
  int main() {
      MessageBoxA(NULL,"hello","hello",MB_OK);
      return 0;
  }
  
  #pragma data_seg(".CRT$XLX")
  PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = {TLS_CALLBACK,NULL};
  #pragma data_seg()
  ```


###### 易语言特征码

- 字符串比较函数特征码：`test edx,0x3`

  ```asm
  mov edx,dword ptr ss:[esp+0x4]
  mov ecx,dword ptr ss:[esp+0x8]
  test edx,edx
  
  test edx,0x3
  ```

  断下后注意观察`ECX`与`EDX`

- 按钮事件特征码：`FF55FC5F5E`

- 易语言体特征码：`FF25`

###### 提取特征码基本原则

- 一定不能包含绝对地址，如果有，一定要换成通配符
- 有`CALL`也不行，如果有，也要换成通配符
- 有常量也不行，如果有，也要换成通配符

