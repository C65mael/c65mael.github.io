---
title: ItemLearn
cascade:
  type: docs
---

###### obfusheader.h

[真的不菜](https://github.com/ac3ss0r/obfusheader.h)

**OBFUSCATION**

- 伪造假的段名称，也就是伪签名

  不过这个伪造似乎对我的`die`影响不大（话说`die`不是更具特征码识别保护的吗？）

  ```c++
  #if FAKE_SIGNATURES && defined(_WINDOWS) && !KERNEL_MODE
      #ifdef _MSC_VER
          #pragma section(".arch")
          #pragma section(".srdata")
          #pragma section(".xpdata")
          #pragma section(".xdata")
          #pragma section(".xtls")
          #pragma section(".themida")
          #pragma section(".vmp0")
          #pragma section(".vmp1")
          #pragma section(".vmp2")
          #pragma section(".enigma1")
          #pragma section(".enigma2")
          #pragma section(".dsstext")
      #endif
      // https://enigmaprotector.com
      FAKE_SIG(_enigma1, ".enigma1", 0); FAKE_SIG(_enigma2, ".enigma2", 0);
      // https://vmpsoft.com (opensource)
      FAKE_SIG(_vmp1, ".vmp0", 0); FAKE_SIG(_vmp2, ".vmp1", 0); FAKE_SIG(_vmp3, ".vmp2", 0);
      // DENUVO
      FAKE_SIG(_denuvo1, ".arch", 0); FAKE_SIG(_denuvo2, ".srdata", 0); FAKE_SIG(_denuvo3, ".xdata", 0);
      FAKE_SIG(_denuvo4, ".xpdata", 0); FAKE_SIG(_denuvo5, ".xtls", "\x64\x65\x6E\x75\x76\x6F\x5F\x61\x74\x64\x00\x00\x00\x00\x00\x00");
      // THEMIDA
      FAKE_SIG(_themida1, ".themida", 0);
      // SECUROM
      FAKE_SIG(_securom1, ".dsstext", 0);
  #endif
  ```

- 生成随机数种子

  关键字`constexpr`：变量或函数的值可以在编译时确定。

  `__TIME__`：在编译时被替换为一个字符串，表示源代码被编译的时间。

  `__LINE__`：编译时被替换为当前源代码的行号。

  `__COUNTER__`：在这个代码中是每次调用`CTimeSeed`后都会增加`1`。

  ```c++
  #ifdef __cplusplus 
  // using constexpr allows us to avoid embeding XX:XX:XX into the binary
      static constexpr int CTime = __TIME__[0] + __TIME__[1] + __TIME__[3] + __TIME__[4] + __TIME__[6] + __TIME__[7];    //将编译的时间求和
      #define CTimeSeed ((__COUNTER__ + CTime) * 2654435761u)    //斐波那契散列常数吗？
  
  #else 
  // for C we cannot base it on __TIME__, since there's no constexpr, or XX:XX:XX will be added to the binary
      #define CTimeSeed ((__COUNTER__ + __LINE__) * 2654435761u)
  #endif
  #define RND(Min, Max) (Min + (CTimeSeed % (Max - Min + 1)))
  ```

- 混淆的真假异或门

  不管这个`RND(1, 10)`（从`1`到`10`之间随机取一个数）取多少，下面的真还是真，假也是假，和自己实现了一个异或门。

  ```c++
  #define _RND RND(1, 10)
  #define _TRUE ((((_9 + __7() + ((_RND * __2()) * __0()))) / _8) - _1)
  #define _FALSE ((_3 + __6() + ((_RND * __3()) * _0)) - __9())
  #define XOR(x, y) (x + y - (2 * (x & y)))
  ```

- 定义静态字符串

  应该是不让直接搜索出来字符串吧，不过后面的定义类似函数的数字确实很有用，`ida`直接升天。

  ```c++
  // Use stored in static memory essential bytes for hardcoded cflow blocks & expressions
  #if CFLOW_CONST_DECRYPTION || CFLOW_BRANCHING
      static volatile char _a = 'a', _b = 'b', _c = 'c', _d = 'd', _e = 'e', _f = 'f', _g = 'g', _h = 'h', _i = 'i', _j = 'j', _k = 'k', _l = 'l', _m = 'm', _n = 'n', _o = 'o', _p = 'p',
                           _q = 'q', _r = 'r', _s = 's', _t = 't', _u = 'u', _v = 'v', _w = 'w', _x = 'x', _y = 'y', _z = 'z', _S = 'S', _L = 'L', _A = 'A', _I = 'I', _D = 'D', _P = 'P';
      static volatile char _0 = 0, _1 = 1, _2 = 2, _3 = 3, _4 = 4, _5 = 5, _6 = 6, _7 = 7, _8 = 8, _9 = 9;
      // Same trick with NOINLINED functions (proxies)
      static NOINLINE char __0() { return 0; } static NOINLINE char __1() { return 1; } static NOINLINE char __2() { return 2; } static NOINLINE char __3() { return 3; } static NOINLINE char __4() { return 4; }
      static NOINLINE char __5() { return 5; } static NOINLINE char __6() { return 6; } static NOINLINE char __7() { return 7; } static NOINLINE char __8() { return 8; } static NOINLINE char __9() { return 9; }
  #endif
  ```

- 构造真假判断

  ```c++
  // Easily build hardcoded control-flow protection blocks
  #define BLOCK_COND(cond, block) if (cond) { block; }
  #define BLOCK_TRUE(block) BLOCK_COND(_TRUE, block)
  //if (true) { block; }也就是恒执行
  #define BLOCK_FALSE(block) BLOCK_COND(_FALSE, block)
  //自然是恒不执行
  ```

- 反静态分析

  其实就是添加恒跳转的花指令，如下：

  ```asm
  xor eax, eax
  jz loc_real
  _emit 0x00
  loc_real:
  ```

- 混淆

  读取`0`到`0x7FFFFF`中的随机一个值的地址，有可能会发生段错误。

  下面定义的`int_proxy`函数其实就是参数是多少就返回多少，一个混淆。

  ```c++
  #define SEGFAULT int_proxy(*(int*)RND(0, 0x7FFFFF))
  
  #if CFLOW_CONST_DECRYPTION || CFLOW_BRANCHING
      volatile static INLINE int int_proxy(double val) {
          INDIRECT_BRANCH;
          volatile double a = val * ((double)_7 - ((double)_3 * 2));
          BLOCK_TRUE(
              BLOCK_FALSE(
                  return _RND;
              )
          )
          BLOCK_TRUE(
              loc_end:
              if (_RND)
                  return a * _TRUE;
              loc_fake:
                  return _RND;
          )
      }
  #endif
  ```

- 嘲讽

  其实就是构造了一个假函数，然后……并不会执行到这。

  ```c++
  static void obfusheader_watermark_hook(const char* param) {} // to avoid crashing we assign a real func
  typedef volatile void(*draw_ptr) (const char*); // define a draw function
  static volatile draw_ptr obfusheader_watermark_orig = (draw_ptr)obfusheader_watermark_hook; // assign draw_orig to avoid segfault
  
  // Binary watermarking for IDA/GHIDRA that bypasses compiler optimizations
  #define WATERMARK(...)\
      const char * data[] = {__VA_ARGS__};\
      for (volatile int i = 0; i <sizeof(data)/sizeof(data[0]); i++)\
          obfusheader_watermark_orig(data[i]);
  
  static volatile void obfusheader_decoy_main() {
      WATERMARK("Stop reversing the binary", // Message for crackers ;)
                  "Reconsider your life choices",
                      "And go touch some grass", 0);
  }
  
  // Fake decoy functions to hide the original one (for call hiding)
  static void obfusheader_decoy_1() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_2() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_3() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_4() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_5() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_6() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_7() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_8() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_9() { obfusheader_decoy_main(); }
  static void obfusheader_decoy_10() { obfusheader_decoy_main(); }
  ```

- 加密与解密

  `obfuscator`加密应该就是简单的数据与`key`异或的运算

  ```c++
  // Normal & threadlocal encryption modes
  #define OBF_KEY_NORMAL(x, type, size, key) []() {\
      constexpr static auto result = obf::obfuscator<type, size, key>(x);\
      return result; }() 
  //调用lambda表达式，只有宏没有名称，进行加密
  
  #define OBF_KEY_THREADLOCAL(x, type, size, key) []() {\
      constexpr static auto data = obf::obfuscator<type, size, key>(x);\
      thread_local auto decryptor = obf::decryptor<type, size, key>(data);\
      return decryptor; }()
  //线程中都有一个解密实例，在线程中解密
  
  #define MAKEOBF_NORMAL(x) OBF_KEY_NORMAL(x, obf::clean_type<decltype(obf::gettype(x))>, obf::getsize(x), (char)RND(1, 255))
  
  #define MAKEOBF_THREADLOCAL(x) OBF_KEY_THREADLOCAL(x, obf::clean_type<decltype(obf::gettype(x))>, obf::getsize(x), (char)RND(1, 255))
  //生成密钥
  
  #if CONST_ENCRYPTION
      #if CONST_ENCRYPT_MODE == NORMAL
          #define MAKEOBF(x) MAKEOBF_NORMAL(x)
      #elif CONST_ENCRYPT_MODE == THREADLOCAL
          #define MAKEOBF(x) MAKEOBF_THREADLOCAL(x)
      #endif
      #define OBF(x) ((meta::decay_t<decltype(x)>) MAKEOBF(x))
  #else
      #define MAKEOBF(x) x
      #define OBF(x) x
  #endif
  ```

- 后面的命名空间似乎是对编译文件的一些操作，就先跳过

- 又一个混淆

  之前的那个永真`if`与永假`if`以及自己实现的异或，进行挨个与`key+i`进行异或操作

  ```c++
      template <class T, char key, size_t size>
      INLINE void xord(T* data) {
          #if CFLOW_CONST_DECRYPTION
          for (volatile int i = 0; i < size; i++) {
              BLOCK_FALSE(
                  data[i] = XOR(data[i], int_proxy(key + 1));    //不执行
              )
              BLOCK_TRUE(                  //int_proxy之前分析的就是输入几输出就是几
                  BLOCK_FALSE(
                      data[i] = XOR(data[i], int_proxy(key + 2));    //不执行
                  );
                  BLOCK_FALSE(
                      data[i] = XOR(data[i], int_proxy(key + 3));    //不执行
                  );
                  BLOCK_TRUE(
                      data[i] = XOR(data[i], CAST(T, int_proxy(key + i))); // real
                  )
              )
              BLOCK_FALSE(
                  data[i] = XOR(data[i], int_proxy(key + 4));    //不执行
              )
          }
          #else
          for (volatile int i = 0; i < size; i++)
              data[i] = data[i] ^ CAST(T, key + i); // no cflow (optimized+unsafe)
          #endif
      }
  ```

- 还是一个异或与解密

  实现了单值与多值两个版本，异或加密与异或解密

  ```c++
      template <class T, size_t size, char key>
      class obfuscator {
      public:
          constexpr obfuscator(const T* data) {
              for (int i = 0; i < size; i++)
                  m_data[i] = data[i] ^ CAST(T, key + i);
          }
  
          constexpr obfuscator(const T data) {
              m_data[0] = data ^ key;
          }
  
          INLINE T* decrypt() {    //解密
              if (!decrypted) {
                  xord<T, key, size>(m_data);
              }
              decrypted = true;
              return m_data;
          }
  
          INLINE operator T* () {
              return decrypt();
          }
  
          INLINE operator T () {
              return decrypt()[0];
          }
  
          bool decrypted = false;
          T m_data[size]{};
      };
  
      template <class T, size_t size, char key>
      class decryptor {
      public:
          INLINE decryptor(const obfuscator<T, size, key> data) {
              for (int i = 0; i < size; i++)
                  m_data[i] = data.m_data[i];    //将加密数据从obfuscator转移过来
          }
  
          INLINE T* decrypt() {    //解密
              if (!decrypted) {
                  xord<T, key, size>(m_data);
              }
              decrypted = true;
              return m_data;
          }
  
          INLINE operator T* () {
              return decrypt();
          }
  
          INLINE operator T () {
              return decrypt()[0];
          }
  
          bool decrypted = false;
          T m_data[size]{};
      };
  ```

- 隐藏函数指针

  创建了一个函数地址的数组，里面有随机数，假函数地址，数组最后一个是真函数地址。然后有两种寻找函数地址的方式，如果`index == real_index`则返回数组中第`N`个（是真的地址，因为数组长度为`N+1`），否则返回第`index`个。

  ```c++
      template <typename T, int N, int real_index, T real_value, int index>
      constexpr T select_func() {
          T funcs[N + 1] = {
              RCAST(T, (char*)_RND), RCAST(T, obfusheader_decoy_1), RCAST(T, obfusheader_decoy_2), RCAST(T, obfusheader_decoy_3),
              RCAST(T, (char*)_RND), RCAST(T, 0), RCAST(T, (char*)_RND),
              RCAST(T, obfusheader_decoy_5), RCAST(T, (char*)_RND), RCAST(T, (char*)_RND), RCAST(T, real_value)
          };
          if (index == real_index)  // Index of the real func
              return funcs[N];
          return reinterpret_cast<T>(funcs[index]);
      }
  
      template <typename T, int N, int real_index, T real_value, int... indices>
      struct FunctionPtrHider {
          static T shuffled_arr[N];
      };
  
      template <typename T, int N, int real_index, T real_value, int... indices>
      T FunctionPtrHider<T, N, real_index, real_value, indices...>::shuffled_arr[N] = {
          select_func<T, N, real_index, real_value, indices>()...
      };
  ```

  在`c`里面直接禁用混淆：

  ```c++
  #else // C doesn't support compile-time encryption cause no constexpr sadly :( So we just implement it like this & disable everything
      #define OBF(x) x
          #define CALL(ptr, ...) ((ptr)(__VA_ARGS__))
          #define HIDE_PTR(ptr) (ptr)
  ```

- 符号调用隐藏

  `linux`与安卓平台使用动态链接库函数`dlsym`从默认符号表中查找符号，`windows`平台就`load`要用的`dll`之后`GetProcAddress`就可以找到了。（避免在代码中硬编码函数地址`IAT`）

  ```c++
      // Symbol - based call hiding(different for Linux& windows)
      #if defined(__linux__) || defined(__ANDROID__)
          #define CALL_EXPORT(mtd, def) ((def)(dlsym(RTLD_DEFAULT, OBF(mtd))))
      #elif defined(_WINDOWS)
          #define CALL_EXPORT(lib, mtd, def) ((def)(GetProcAddress(LoadLibraryA(lib), mtd)))
      #endif
  #endif
  ```

- 影响性能的混淆

  其实就是将这些常用的条件跳转与返回自己实现了一个混淆的版本

  ```c++
  #if CFLOW_BRANCHING
      #define if(x) if (_TRUE) if (int_proxy((long long)(x)) * _TRUE && _RND)
      #define for(x) for (int _i=0; _i<int_proxy(_TRUE);_i++) for (x)
      #define while(x) while(int_proxy((long long)(x)) * _TRUE && _RND)
      #define switch(x) switch(int_proxy((long long)(x)) * _TRUE)
      #define return for (int _i=0; _i<RND(1, 100);_i++) return
      // This will hurt (Some compilers don't allow this, disable if fails)
      #define else else\
                          BLOCK_FALSE(\
                              int_proxy(_RND);\
                              BLOCK_TRUE(\
                                  int_proxy(_RND);\
                              )\
                          ) else
  #endif
  ```

**MODULES**

其实就是自己实现了一些常用的字符串操作的函数

###### XAntiDebug

[真的不菜](https://github.com/strivexjun/XAntiDebug)

这个反调试代码函数`XAD_Initialize`为反调试初始化，`XAD_ExecuteDetect`函数为检测调试。先看初始化吧

- 1

  ```c++
  
  ```

  

