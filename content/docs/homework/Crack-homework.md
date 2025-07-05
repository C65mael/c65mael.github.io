---
title: Crack-homework
cascade:
  type: docs
---

###### 2

- 用四种方法定位到本程序关键破解位置并爆破
  - 下函数断点在`MessageBoxA`后面，之后向后跟到再次比较的位置是`0x42FB03`，将它`NOP`就不会跳到错误的位置了。
  - 在`ida`中搜字符串可以找到是`Tserial_button1Click@<eax>`函数。

###### 3

- 爆破这个程序，并且做出内存补丁

  还是下函数断点在`MessageBoxA`后面，可以看到关键跳是`0x004010FD`。我使用的是`Baymax Patch Tools`，设置异常中断补丁，由于不太会设置虚拟地址什么的，我直接用特征码进行硬件断点的设置为`0F 84 39 00 00 00`（就是那个关键跳的机器码），补丁类型为修改`eip`。保存出来之后先执行补丁，之后就成了。

###### 4

- 易语言：

  ```
  线程_启动 (&子程序1, , )
  返回 (0)
  
  .子程序 子程序1
  
  .循环判断首 ()
  .循环判断尾 (内存读写.读字节 (到整数 (进程_取自进程ID ()), 进制_十六到十 (“4010f0”)) ≠ 83)
  内存读写.写字节集 (到整数 (进程_取自进程ID ()), 进制_十六到十 (“4010fd”), { 144, 144, 144, 144, 144, 144 })
  
  ```

  `c`语言实现的原理一样。

###### 5

- 不修改代码破解本程序，需说明分析思路以及解决问题的代码

  这个的程序比较输出的位置是程序的窗口名称（`SetWindowTextA`），`F8`之后可以看到是地址`0x0401053`在比较，而且特征码为`0F 85 51 00 00 00`，之后就和之前一样写一个异常补丁就好了，记住运行补丁前一定要关调试器。

###### 6

- 这个题首先是易语言写的。而且这个程序的注册逻辑是将用户输入的`Key`写到本地文件中，之后每次启动之后进行比较。

  易语言的特性应该是首先会执行`API` `GetVersion`。由于这个程序加了壳，所以需要将真实的代码吐出来，就在`GetVersion`上下断点。通过字符串搜索发现有`\\License.Key`，应该是上面说保存的本地文件，那么就断在这里看一下（`0x004016D6`，其实就是先断在`GetVersion`将代码吐出来，然后断在`0x004016D6`，但是一定要启用断点，调试器比较汇编指令变化后会自动将这个断点禁用）。往下找大跳转，在`0x00401895`位置，直接`nop`掉，出了。

###### 7

- 计算出正确的注册码。并且注册成功

  直接到注册控件的处理函数中，可以看到核心的代码如下：

  ```c++
          *v6 = GetDlgItemInt(hWnd, 1000, 0, 1);
          sprintf(Buffer, "%d", v6[0]);
          sub_401000(*v6);
  ```

  这个`*v6`应该就是读取用户输入的数值，那么在`sub_401000`就是验证用户输入的函数：

  ```c++
    result = a1 * (a1 - 23) == -102;
    if ( a1 * (a1 - 23) == -102 )
    {
      result = a1 * a1 * a1;
      if ( result == 0x1331 )
        return MessageBoxW(0, "m`淯`O", &Caption, 0);
    }
    return result;
  }
  ```

  算一下应该是`17`

###### 8

- 去花指令的话可以在`IDA`中调试，遇到小跳的跳过去，然后把当前指令的上面直到比较的指令全部`nop`掉就行：

  ```c++
  int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
  {
    char v3; // [esp+0h] [ebp-11Ch]
    char v4; // [esp+0h] [ebp-11Ch]
    char Str1[136]; // [esp+10h] [ebp-10Ch] BYREF
    char Str[132]; // [esp+98h] [ebp-84h] BYREF
  
    meun();
    memset(Str, 0, 0x80u);
    memset(Str1, 0, 0x80u);
    while ( 1 )
    {
      memset(Str, 0, 0x80u);
      memset(Str1, 0, 0x80u);
      output("\n", v3);
      scanf(&aS_0, Str);
      encode(Str, Str1, 128);
      strcmp(Str1, "((++**--,,//..QQPP");
      printf("\n\n注册失败\n\n", v4);
    }
  }
  ```

  其中`encode`：

  ```c++
  const char* bcc[] = "bcdaren";
  
  int __cdecl encode(const char *Str, char *Str1, unsigned int 128)
  {
    signed int v4;
    size_t j;
    signed int i;
  
    if ( !Str )
      return -1;
    if ( !Str1 || !128 )
      return -1;
    if ( strlen(Str) <= 128 )
      v4 = strlen(Str);
    else
      v4 = 128;
    for ( i = 0; i < v4; ++i )
    {
      for ( j = 0; j < strlen("bcdaren"); ++j )
        Str1[i] = bcc[j] ^ (Str[i] + 13);
    }
    return 0;
  }
  ```
  
  这个`for`循环里面的`j`只是不停的加以，但是最后不变的就是最后的字母`n`，逆运算应该为：
  
  ```c++
  //  for ( i = 0; i < v4; ++i )
  //  {
  //      Str1[i] = 'n' ^ (Str[i] + 13);
  //  }
    for ( i = 0; i < v4; ++i )
    {
        Str1[i] = (Str[i] ^ 'n') - 13;
    }
  //应该可以理解为等式的移项a=b+13,那么b=a-13，然后交换一下变量位置那么a=b-13就是逆运算了
  ```
  
  那么输入`((++**--,,//..QQPP`进行解密就可以了。
  
  ```c++
  #include <windows.h>
  #include <stdio.h>
  
  int __cdecl encode(const char *Str, char *Str1)
  {
    signed int v4;
    size_t j;
    signed int i;
  
    if ( !Str )
      return -1;
    if ( !Str1 || !128 )
      return -1;
    if ( strlen(Str) <= 128 )
      v4 = strlen(Str);
    else
      v4 = 128;
    for ( i = 0; i < v4; ++i )
    {
      for ( j = 0; j < strlen("bcdaren"); ++j )
        Str1[i] = (Str[i] ^ 'n') - 13;
    }
    return 0;
  }
  
  int main() {
      char decoded_str[256] = {0};
      encode("((++**--,,//..QQPP",decoded_str);
      printf("%s",decoded_str);
      return 0;
  }
  ```

###### 9

- 算出正确的注册码（`flag{……}`）

  这里的反调试就是`TLS`里面有阻止调试器接收消息与检测是否被调试的功能。

  直接找回调函数，但是算法我是真的不会呀。

###### 10

- `patch`脚本我用`ida`自带的`python`写的：

  在`File -> Script command`找到，记得要将下面的`IDC`改为`Python`：

  ```python
  startaddr = 0x00402000
  endaddr = 0x00402200
  
  for i in range(startaddr,endaddr):
      if get_wide_byte(i) == 0xE8 and get_wide_byte(i+1) == 0x00 and get_wide_byte(i+6) == 0x04 and get_wide_byte(i+12) == 0xC3:
          for j in range(0,0x1C):
              patch_byte(i+j,0x90)
              
      if get_wide_byte(i) == 0xE8 and get_wide_byte(i+1) == 0x01 and get_wide_byte(i+6) == 0x83 and get_wide_byte(i+7) == 0x04:
          for k in range(0,0xA):
              patch_byte(i+k,0x90)
  ```

  
