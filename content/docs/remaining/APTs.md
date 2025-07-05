---
title: APTs
cascade:
  type: docs
---

### 2011.02.10 - Night Dragon

（`zwshell`）这个其实是一个类似`cobalt strike`的一个工具生成的样本，不过好像比`cs`的功能少一些。看一下这个样本的`loader`的核心部分：

- 查找和加载资源：
  
  ```c
  ResourceA = FindResourceA(0, Name, 0xA);      // 在资源节查找DATA类型的资源
  foundResource = ResourceA;
  if ( !ResourceA )
      return 0;
  Resourcesize = SizeofResource(0, ResourceA);  // 获取资源大小
  Resource = LoadResource(0, foundResource);    // 将资源加载近内存
  ```
  
- 锁定和加密资源：
  
  ```c
  if (LockResource(Resource)) // 锁定资源
  {
      handle_Gchunk = GlobalAlloc(0x40u, Resourcesize);  // 分配内存
      Gchunkaddr = GlobalLock(handle_Gchunk);           // 锁定内存
      qmemcpy(Gchunkaddr, isLocked, Resourcesize);      // 拷贝数据到新内存
      xorencryption(Gchunkaddr, Resourcesize);          // 加密数据
  }
  ```
  
- 互斥体管理：

  ```c
  MutexA = OpenMutexA(0x100000u, 0, byte_403113);  // 尝试打开互斥体
  if ( !MutexA )
  {
      MutexA = CreateMutexA(0, 0, byte_403113);    // 如果不存在则创建互斥体
  }
  ```

- 获取文件路径并重命名文件：

  ```c
  GetModuleFileNameA(0, Filename, 0x105u);  // 获取当前程序路径
  lstrcpyA(String1, Filename);              // 复制到 String1
  ```

- 文件移动/重命名：

  ```c
  for ( i = lstrlenA(String1) - 1; i >= 0; String1[i--] = v10 + 2 )
  {
      v10 = String1[i]; //当前程序的绝对路径
      if ( v10 == '\\' )
          break;
  }
  if ( MoveFileA(Filename, String1) )  // 如果移动成功
  {
      lstrcpyA(byte_4032AC, String1);  // 更新文件路径
      MoveFileExA(String1, 0, 4u);      // 延迟删除文件，重启前才会删除该文件
  }
  else
  {
      lstrcpyA(byte_4032AC, Filename);
      MoveFileExA(Filename, 0, 4u);
  }
  ```

- 注册表操作：

  ```c
  if ( regcreat(2u, String1, lpValueName, Filename, v16 + 1) )// 向注册表写入数据，进行持久化
  {
  	ReleaseMutex(MutexA);
  	CloseHandle(MutexA);
  下面是这个函数:
  char __cdecl regcreat(DWORD dwType, CHAR *lpSubKey, LPCSTR lpValueName, BYTE *lpData, DWORD cbData)
  {
    DWORD dwDisposition; // [esp+0h] [ebp-4h] BYREF
  
    dwDisposition = 2;
    if ( RegCreateKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, 0, 0, 0xF003Fu, 0, &lpSubKey, &dwDisposition) )
      return 0;
    RegSetValueExA(lpSubKey, lpValueName, 0, dwType, lpData, cbData);
    RegCloseKey(lpSubKey);
    return 1;
  }
  ```

- 服务管理：

  ```c
  if (OpenServiceA(hSCManager, String2, 0xF01FFu))
  {
      StartServiceA(v17, 0, 0);  // 启动服务
      CloseServiceHandle(v17);
  }
  ```


调试：

- 在填写样本信息的时候可以发现，这个样本可以释放一个`DLL`到指定的目录下，默认是`%windir%\System32\`就是`Windows`目录下的`System32`文件夹里面（不过我尝试了一下，它会自动跑到`C:\Windows\SysWOW64\`下，可能那个时候只支持`32`位系统吧）
- 在上面的`regcreat`的参数中的`String1`参数（就是要生成注册表的目录）为`SYSTEM\CurrentControlSet\Services\FastUserSwitchingCompatibility\Parameters`就是注册一个快速用户切换功能，注册表键值就是上面的那个指定的目录路径，后面会打开`FastUserSwitchingCompatibility`服务完成上线。
- 在文件重命名的第一个`for`循环将程序的名称改为`Ugtxgt0gzg`，配合`MoveFileExA`函数达到文件重启自删除。但是如果不附加调试的情况下文件会直接删除🧐
- 使用`svchost.exe netsvcs –k`将这个`DLL`注册成服务；同样的使用`%systemroot%\system32\svchost.exe -k netsvcs` 注册网络通信服务

看一下上面那个`DLL`文件的导出表，发现只有一个函数（`ServiceMain`），分析一下这个函数：

- 这是一个`DLL`所以要写一个`Loader`去加载这个函数（相同路径下），如下：

  ```c
  #include <windows.h>
  #include <stdio.h>
  
  typedef void (*ServiceMain)(int argc, char *argv[]);
  
  int main() {
      HINSTANCE hDLL = LoadLibrary("123.dll");
      if (hDLL == NULL) {
          printf("加载DLL失败.\n");
          return 1;
      }
  
      ServiceMain pServiceMain = (ServiceMain)GetProcAddress(hDLL, "ServiceMain");
      if (pServiceMain == NULL) {
          printf("获取ServiceMain函数地址失败.\n");
          FreeLibrary(hDLL);
          return 1;
      }
  
      char *args[] = {"arg1", "arg2"};
      pServiceMain(2, args);
  
      FreeLibrary(hDLL);
  
      return 0;
  }
  ```

  将这个代码编译后，放到`IDA`中下断点就可以了。

- ```c
    v8 = 0;
    FileA = CreateFileA(Filename, 0x80000000, 1u, 0, 3u, 0, 0);    //打开这个DLL，Filename为DLL路径
    hFile = FileA;
    if ( FileA != -1 )
    {
      SetFilePointer(FileA, -737, 0, 2u);    //移动文件指针为文件末尾737字节
      ReadFile(hFile, &data, 737u, &NumberOfBytesRead, 0);    // 从文件读取737字节到data。
      CloseHandle(hFile); 
  ```

- ```c
  de_code(&data, 737);    //解密
      v8 = data == 321148776;
      if ( data == 321148776 )    //是否解密成功hW$
      {
        if ( byte_100264B8 )    //sign
        {
          NumberOfBytesRead = 4;
          lstrcpyA(String1, lpString2);
          lstrcatA(String1, aPolicyagent);
          RegSet_func(4u, String1, Start_s, &NumberOfBytesRead, 4u);
          ServiceStatus.dwServiceType = 0;
          ServiceStatus.dwCurrentState = 1;
          memset(&ServiceStatus.dwControlsAccepted, 0, 20);
          OpenService_func(aPolicyagent, &ServiceStatus);
        }
        DeleteFileA(byte_100264B9);    //删除Ugtxgt0gzg文件
        lstrcpyA(String1, lpString2);    //SYSTEM\\CurrentControlSet\\Services\\
        lstrcatA(String1, ServiceName);    //FastUserSwitchingComp|atibility这后面的字符串下面代码会加上
        NumberOfBytesRead = 2;
        RegSet_func(4u, String1, Start_s, &NumberOfBytesRead, 4u);
        NumberOfBytesRead = 272;
        RegSet_func(4u, String1, ValueName, &NumberOfBytesRead, 4u);
        v1 = lstrlenA(&byte_1002634A);
        RegSet_func(1u, String1, aDisplayname, &byte_1002634A, v1 + 1);
        v2 = lstrlenA(&byte_100263A5);
        RegSet_func(1u, String1, aDescription, &byte_100263A5, v2 + 1);
        sub_10002061();
      }
  ```

- ```c
    if ( v0 )
    {
      v0 = OpenMutexA(0x100000u, 0, Name);    //就是DLL的名字作为互斥体名字
      if ( !v0 )
      {
        MutexA = CreateMutexA(0, 0, Name);
        v0 = RegisterServiceCtrlHandlerA(ServiceName, HandlerProc);    //注册服务控制句柄FastUserSwitchingCompatibility
        hServiceStatus = v0;
        if ( v0 )
        {
          SetServiceStatus_func(2u);    //服务正在启动
          SetServiceStatus_func(4u);    //服务正在运行
          sub_10003F70(0);    //网络连接
          SetServiceStatus_func(3u);    //服务正在停止
          SetServiceStatus_func(1u);    //服务已停止
          ReleaseMutex(MutexA);
          LOBYTE(v0) = CloseHandle(MutexA);
        }
      }
    }
    return v0;
  }
  ```

- ```c
  int __stdcall sub_10003F70(int a1)
  {
    HANDLE Thread; // eax
    struct WSAData WSAData; // [esp+10h] [ebp-190h] BYREF
  
    WSAStartup(0x202u, &WSAData);    //初始化 Winsock 库，Winsock 2.2
    sub_10001BD8(&unk_100262D0);
    time1 = GetTickCount() - 30000;    //时间减去30s
    while ( ServiceStatus.dwCurrentState != 1 )    //服务停止就跳出
    {
      if ( ServiceStatus.dwCurrentState == 3 )    //服务正在停止就break
        break;
      if ( GetTickCount() - time1 > 0x7530 )    //隔30s
      {
        if ( ThreadId )
        {
          sub_10001D39(&unk_100262D0, 20483, 0, 0, dword_1002661D, 0, 0);    //是释放内存吗？
        }
        else
        {
          Thread = CreateThread(0, 0, sub_10003BD7, 0, 0, &ThreadId);    //sub_10003BD7远程控制函数
          CloseHandle(Thread);
        }
        dword_10026621 = GetTickCount();
      }
      Sleep(1u);
    }
    sub_10001BE4(&unk_100262D0);    //结束
    WSACleanup();
    return 0;
  }
  ```

  核心功能就差不多了。

### 2024.12.9 - APT-C-08（蔓灵花）

- 创建互斥体（`rabadaisunique`）防止多开：

  ```c++
   MutexA = CreateMutexA(0i64, 1, "rabadaisunique");
    if ( GetLastError() == 183 || GetLastError() == 5 )
    {
      CloseHandle(MutexA);
      return 1;
    }
  ```

- 断到函数`isalpha(*v9)`可以看到`*v9`里面是字符串`emj.rqgjlgu\\yrybkypempn\\:A`的倒转，而且后面的循环判断`while ( v9 != v10 )`中`v10 = 0`，可以化简后面的代码逻辑，解密如下：

  ```c++
  #include <stdio.h>
  #include <stdlib.h>
  #include <windows.h>
  
  void process_buffer(char *v9, char *v10) {
      while (v9 != v10) {
          if (isalpha(*v9)) {
              if ((*v9 >= 'a') && (*v9 <= 'z')) {
                  *v9 = (*v9 - '_') % 26 + 'a';
              } else if ((*v9 >= 'A') && (*v9 <= 'Z')) {
                  *v9 = (*v9 - '?') % 26 + 'A';
              }
          } else if (isdigit(*v9)) {
              *v9 = (*v9 - '.') % 10 + '0';
          }
          v9++;
      }
  }
  
  int main() {
  	char test1[50] = "A:\\npmepykbyry\\ugljgqr.jme";
  	char test2[50] = "0";
  
  	process_buffer(test1, test1 + strlen(test1));
  	process_buffer(test2, test2 + strlen(test2));
  
  	printf("%s %s", test1, test2);
  	return 0;
  }
  ```

  执行结果为：`C:\programdata\winlist.log 2`（正常解密结果为`C:\programdata\winlist.log`）

  同样发方法，后面的解密字符串为`emj.cqgpns\\yrybkypempn\\:A`（`C:\programdata\uprise.log`），`rvr.cryb\\yrybkypempn\\:A`（`C:\programdata\date.txt`），`rvr.ppc\\yrybkypempn\\:A`（`C:\programdata\err.txt`）
  
- 获取系统时间，将系统时间转为时间戳，获取计算机名称，获取用户名称：

  ```c++
  GetSystemTime(&SystemTime);
  SystemTimeToFileTime(&SystemTime, &FileTime);
  nSize = 512;
  GetComputerNameW(Buffer, &nSize);
  nSize = 512;
  GetUserNameW(aErr_1, &nSize);
  ```

- 之后在特定的目录下找特定的文件，不过它的字符串的变换操作我没有看明白。而且与之前倒转字符串的函数很相似，都有与`0x7FFFFFFFFFFFFFFE`进行比较之类的操作。

- 后面的行为与之前的一个函数也比较相似，似乎是对高精度时间进行的操作：

  ```c++
    perf_frequency = Query_perf_frequency();
    perf_counter = Query_perf_counter();
  ```

