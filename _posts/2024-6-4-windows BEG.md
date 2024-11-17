---
title: Windows BEG
description: PE，win
date: 2024-06-04 00:00:00
categories:
- Windows
---

### PE文件结构

###### 总体结构

![image](https://c65mael.github.io/myassets-beg/image-20240124021409-650cwqy.png)​​

- 程序在内存中是分节的，每一个节存储不同的数据，硬盘对齐(200h)，内存对齐(1000h)。因为程序在硬盘上和内存中的状态可能略有不同(以前的程序在内存中与在硬盘上，在内存中节与节之间会有一个"拉伸"过程，节与节之间的空隙变大(填充0)。而现在的程序则并不会。)，这样做可以:

  - 节省硬盘空间。
  - 实现多开(将只读的节保留，将可读可写的节多开，可以节省内存空间)。

  ![image](https://c65mael.github.io/myassets-beg/image-20240124024811-j31e5w4.png)

- 头的大致结构如下：

  |   结构   |
  | :------: |
  |  DOS头   |
  | 标准PE头 |
  | 可选PE头 |
  |   节表   |
  
  

**结构解释：**

1. DOS头（`IMAGE_DOS_HEADER`）最早是为16位的DOS程序设计的，因此包含了一些与DOS相关的信息。现代的Windows可执行文件（PE格式）仍然保留了DOS头，以便在DOS环境下运行时能显示“此程序不能在DOS模式下运行”的消息。DOS头的第一个字段是`WORD e_magic`，通常为`0x5A4D`，即字符“MZ”，用于标识这是一个有效的DOS可执行文件头。另一个重要字段是`DWORD e_lfanew`，它保存了PE头（`IMAGE_NT_HEADERS`）在文件中的偏移量。程序在解析PE文件时，会从`e_lfanew`字段找到PE头的位置。值得注意的是，在`e_lfanew`和PE标识符（“PE”，即`0x5045`）之间的部分数据通常被认为是“垃圾数据”，这些数据在现代Windows系统中没有实际用途，只是为了保持文件结构的兼容性。

   ```asm
   	1、DOS头：										
   											
   	WORD   e_magic                *				"MZ标记" 用于判断是否为可执行文件.						
   	DWORD  e_lfanew;              *				PE头相对于文件的偏移，用于定位标准PE头
   ```

   

2. 在找到PE标识符“PE\0\0”（`0x50450000`）后，接下来就是（`IMAGE_NT_HEADERS`）**NT头**的内容。

   ```c
   typedef struct _IMAGE_NT_HEADERS {
       DWORD Signature;                 // 文件签名，通常为'PE\0\0'（0x00004550），用于标识这是一个有效的PE文件
       IMAGE_FILE_HEADER FileHeader;    // 标准PE头，包含文件的基本信息
       IMAGE_OPTIONAL_HEADER OptionalHeader; // 可选PE头，包含加载和运行时的详细信息
   } IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
   ```

   文件签名紧随其后的是`FileHeader`（`IMAGE_FILE_HEADER`），通常被称为**标准PE头**或`COFF`头，包含文件的基本信息。

   ```asm
   2、标准PE头：										
   											
   	WORD    Machine;              *				程序运行的CPU型号：0x0 任何处理器/0x14C 386及后续处理器						
   	WORD    NumberOfSections;     *				文件中存在的节的总数,如果要新增节或者合并节 就要修改这个值.						
   	DWORD   TimeDateStamp;        *				时间戳：文件的创建时间(和操作系统的创建时间无关)，编译器填写的.						
   	DWORD   PointerToSymbolTable;
   
   	DWORD   NumberOfSymbols;
   
   	WORD    SizeOfOptionalHeader; *				可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h  大小可以自定义.						
   	WORD    Characteristics;      *				每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1 				
   ```

   `Characteristics` 标志位如下：

   | 标号 | Characteristics 标志位             |                        属性                        |
   | :--- | :--------------------------------- | :------------------------------------------------: |
   | 0    | IMAGE_FILE_RELOCS_STRIPPED         |  重定位信息已被剥离，意味着文件中不包含重定位信息  |
   | 1    | IMAGE_FILE_EXECUTABLE_IMAGE        |      文件是可执行的，可以作为应用程序直接运行      |
   | 2    | IMAGE_FILE_LINE_NUMS_STRIPPED      |    行号信息已被剥离，意味着文件中不包含行号信息    |
   | 3    | IMAGE_FILE_LOCAL_SYMS_STRIPPED     |  符号信息已被剥离，意味着文件中不包含局部符号信息  |
   | 4    | IMAGE_FILE_AGGRESIVE_WS_TRIM       |              调整工作集，优化内存使用              |
   | 5    | IMAGE_FILE_LARGE_ADDRESS_AWARE     |        应用程序可以处理大于 2GB 的地址空间         |
   | 6    |                                    |            此标志位保留，没有特定的属性            |
   | 7    | IMAGE_FILE_BYTES_REVERSED_LO       | 字节顺序反转（低字节序），文件采用小尾方式存储数据 |
   | 8    | IMAGE_FILE_32BIT_MACHINE           |                只在 32 位平台上运行                |
   | 9    | IMAGE_FILE_DEBUG_STRIPPED          |                   不包含调试信息                   |
   | 10   | IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP |                 不能从可移动盘运行                 |
   | 11   | IMAGE_FILE_NET_RUN FROM_SWAP       |                   不能从网络运行                   |
   | 12   | IMAGE_FILE_SYSTEM                  |         系统文件（如驱动程序),不能直接运行         |
   | 13   | IMAGE_FILE_DLL                     |                 这是一个 DLL 文件                  |
   | 14   | IMAGE_FILE_UP_SYSTEM_ONLY          |           文件不能在多处理器计算机上运行           |
   | 15   | IMAGE_FILE_BYTES_REVERSED_HI       |                      大尾方式                      |

   

3. 紧接着，就是可选(扩展)PE头(`IMAGE_OPTIONAL_HEADER`):

   ```asm
   3、可选PE头：										
   											
   	WORD    Magic;      		  *		        说明文件类型：10B 32位下的PE文件     20B 64位下的PE文件						
   	BYTE    MajorLinkerVersion;
   
   	BYTE    MinorLinkerVersion;
   
   	DWORD   SizeOfCode;*						所有代码节的和，必须是FileAlignment的整数倍 编译器填的  没用						
   	DWORD   SizeOfInitializedData;*				 已初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用						
   	DWORD   SizeOfUninitializedData;*			 未初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用						
   	DWORD   AddressOfEntryPoint;*				 程序入口						
   	DWORD   BaseOfCode;*						代码开始的基址，编译器填的   没用						
   	DWORD   BaseOfData;*						数据开始的基址，编译器填的   没用						
   	DWORD   ImageBase;*							内存镜像基址						
   	DWORD   SectionAlignment;*					 内存对齐						
   	DWORD   FileAlignment;*						 文件对齐						
   	WORD    MajorOperatingSystemVersion;										
   	WORD    MinorOperatingSystemVersion;										
   	WORD    MajorImageVersion;										
   	WORD    MinorImageVersion;										
   	WORD    MajorSubsystemVersion;										
   	WORD    MinorSubsystemVersion;										
   	DWORD   Win32VersionValue;										
   	DWORD   SizeOfImage;*			 内存中整个PE文件的映射的尺寸，可以比实际的值大，但必须是SectionAlignment的整数倍						
   	DWORD   SizeOfHeaders;*						所有头+节表按照文件对齐后的大小，否则加载会出错						
   	DWORD   CheckSum;*							校验和，一些系统文件有要求.用来判断文件是否被修改.						
   	WORD    Subsystem;										
   	WORD    DllCharacteristics;										
   	DWORD   SizeOfStackReserve;*				初始化时保留的堆栈大小 						
   	DWORD   SizeOfStackCommit;*					初始化时实际提交的大小 					
   	DWORD   SizeOfHeapReserve;*					初始化时保留的堆大小 				
   	DWORD   SizeOfHeapCommit;*					初始化时实践提交的大小 				
   	DWORD   LoaderFlags;								
   	DWORD   NumberOfRvaAndSizes;*				目录项数目
   ```

   `DllCharacteristics`属性如下：

   | 标志位 |             DllCharacteristics属性             |            说明            |
   | ------ | :--------------------------------------------: | :------------------------: |
   | 0      |                    Reserved                    |          必须为0           |
   | 1      |                    Reserved                    |          必须为0           |
   | 2      |                    Reserved                    |          必须为0           |
   | 3      |                    Reserved                    |          必须为0           |
   | 4      |                      null                      |            null            |
   | 5      |                      null                      |            null            |
   | 6      |     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE      |  DLL可以在加载时被重定位   |
   | 7      |    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    |   强制代码实施完整性验证   |
   | 8      |       IMAGE_DLLCHARACTERISTICS_NX_COMPAT       |       该映像兼容 DEP       |
   | 9      |     IMAGE_DLLCHARACTERISTICS_NO_ISOLATION      | 可以隔离，但并不隔离此映像 |
   | 10     |        IMAGE_DLLCHARACTERISTICS_NO_SEH         | 没有结构化异常处理（SEH）  |
   | 11     |        IMAGE_DLLCHARACTERISTICS_NO_BIND        |         不绑定映像         |
   | 12     |                    Reserved                    |          必须为0           |
   | 13     |      IMAGE_DLLCHARACTERISTICS_WDM_DRIVER       |  该映像为一个 WDM driver   |
   | 14     |                    Reserved                    |          必须为0           |
   | 15     | IMAGE_DLLCHARACTERISTICS_TERMINAL SERVER_AWARE |      可用于终端服务器      |

   

4. 最后就是节表

   - 如果节相当于书里面的内容，那么节表就相当于书的目录。之前的什么DOS头之类的结构就相当于书的出版社什么的信息。

   ```c
   typedef struct _IMAGE_SECTION_HEADER {
       BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];     // 节的名称，长度为8个字节。通常是以"\0"结尾的ASCII字符串，但系统会截取8个字节的内容。名称可以自定义。
       
       union {
           DWORD   PhysicalAddress;               // 在COFF格式中用于指示物理地址。对于PE文件通常不使用。
           DWORD   VirtualSize;                   // 节的虚拟大小。在内存中的实际大小可以与SizeOfRawData不同。
       } Misc;									// 双字是该节在没有对齐前的真实尺寸,该值可以不准确。
       
       DWORD   VirtualAddress;                    // 节在内存中的虚拟地址，加上ImageBase才是内存中的实际地址。
       
       DWORD   SizeOfRawData;                     // 节在文件中的对齐后的大小。在文件中的实际大小。
       
       DWORD   PointerToRawData;                  // 节在文件中的偏移地址，指向节的实际数据。
       
       DWORD   PointerToRelocations;              // 对于obj文件中的重定位信息使用。对于exe文件，通常为0。
       DWORD   PointerToLinenumbers;              // 行号表的偏移，用于调试。对于exe文件，通常为0。
       WORD    NumberOfRelocations;               // 在obj文件中使用，指示节中重定位的数量。对于exe文件，通常为0。
       WORD    NumberOfLinenumbers;               // 行号表中行号的数量，用于调试。对于exe文件，通常为0。
       
       DWORD   Characteristics;                  // 节的属性标志，如是否为可执行代码、是否可读、是否可写等。
   } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;			
   ```
   
   所以，节表的结构如下：
   
   ![image](https://c65mael.github.io/myassets-beg/jb.png)
   
   

完整如下：

```asm
	1、DOS头：										
											
	WORD   e_magic                *				"MZ标记" 用于判断是否为可执行文件.						
	DWORD  e_lfanew;              *				PE头相对于文件的偏移，用于定位PE文件						
											
											
	2、标准PE头：										
											
	WORD    Machine;              *				程序运行的CPU型号：0x0 任何处理器/0x14C 386及后续处理器						
	WORD    NumberOfSections;     *				文件中存在的节的总数,如果要新增节或者合并节 就要修改这个值.						
	DWORD   TimeDateStamp;        *				时间戳：文件的创建时间(和操作系统的创建时间无关)，编译器填写的.						
	DWORD   PointerToSymbolTable;

	DWORD   NumberOfSymbols;

	WORD    SizeOfOptionalHeader; *				可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h  大小可以自定义.						
	WORD    Characteristics;      *				每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1 						
											
	3、可选PE头：										
											
	WORD    Magic;      		  *		        说明文件类型：10B 32位下的PE文件     20B 64位下的PE文件						
	BYTE    MajorLinkerVersion;

	BYTE    MinorLinkerVersion;

	DWORD   SizeOfCode;*						所有代码节的和，必须是FileAlignment的整数倍 编译器填的  没用						
	DWORD   SizeOfInitializedData;*				 已初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用						
	DWORD   SizeOfUninitializedData;*			 未初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用						
	DWORD   AddressOfEntryPoint;*				 程序入口						
	DWORD   BaseOfCode;*						代码开始的基址，编译器填的   没用						
	DWORD   BaseOfData;*						数据开始的基址，编译器填的   没用						
	DWORD   ImageBase;*							内存镜像基址						
	DWORD   SectionAlignment;*					 内存对齐						
	DWORD   FileAlignment;*						 文件对齐						
	WORD    MajorOperatingSystemVersion;										
	WORD    MinorOperatingSystemVersion;										
	WORD    MajorImageVersion;										
	WORD    MinorImageVersion;										
	WORD    MajorSubsystemVersion;										
	WORD    MinorSubsystemVersion;										
	DWORD   Win32VersionValue;										
	DWORD   SizeOfImage;*			 内存中整个PE文件的映射的尺寸，可以比实际的值大，但必须是SectionAlignment的整数倍						
	DWORD   SizeOfHeaders;*						所有头+节表按照文件对齐后的大小，否则加载会出错						
	DWORD   CheckSum;*							校验和，一些系统文件有要求.用来判断文件是否被修改.						
	WORD    Subsystem;										
	WORD    DllCharacteristics;										
	DWORD   SizeOfStackReserve;*				初始化时保留的堆栈大小 						
	DWORD   SizeOfStackCommit;*					初始化时实际提交的大小 					
	DWORD   SizeOfHeapReserve;*					初始化时保留的堆大小 				
	DWORD   SizeOfHeapCommit;*					初始化时实践提交的大小 				
	DWORD   LoaderFlags;								
	DWORD   NumberOfRvaAndSizes;*				目录项数目
```

- PE加载的过程：

  1. 根据SizeOfImage的大小，开辟一块缓冲区(ImageBuffer)
  2. 根据SizeOfHeader的大小，将头信息从FileBuffer拷贝到ImageBuffer
  3. 根据节表中的信息循环将FileBuffer中的节拷贝到ImageBuffer中

  ![image](https://c65mael.github.io/myassets-beg/pejz.png)

###### ‍RVA与FOA的转换

因为运行的程序全局变量的初始值在未运行的程序中也存在，所以我们如何通过运行程序的地址的值，来推出程序在未运行时这个值对应的地址。

1. ‍RVA相对虚拟地址

   `‍RVA=address(程序运行时要找值的地址)-ImageBase`

2. FOA文件偏移地址(程序未运行要找的地址)

3. 对应关系(不过现在的程序运行和未运行是对齐都相等，所以直接FOA=RVA)：

   - 如果在头部(前面没有节的对齐) FOA=RVA

   - 不在头部(节内的差值是相同的)

```
RVA >=节.VirtualAddress

RVA <= 节.VirtualAddress + 当前节内存对齐后的大小

差值 = RVA - 节.VirtualAddress

FOA =节.PointerToRawData +差值
```

###### 实验：在编译好的程序执行前弹个窗口

1. 汇编对应硬编码6A 00 ：push 0	E8跳转值 ：call 要跳转的地址
2. 计算要跳转地址的硬编码：

```
跳转值=要跳转的地址-E8(call)指令当前的地址-5(对齐到下一个指令)
```



###### 扩大节

当我们想添加的代码或者shellcode比较多，程序没地方写的话可以选择扩大节，由于对齐的原因，扩大最后一个节对其他节的影响最小，是最优选择

扩大节的步骤：

1. 分配一块新的空间,大小为S

2. 将最后一个节的SizeOfRawData和VirtualSize改成N

   `N = (SizeOfRawData或者VirtualSize内存对齐后的值) + S`

3. 修改SizeOflmage大小

###### 新增节

新增节的步骤：

1. 判断是否有足够的空间,可以添加一个节表.
2. 在节表中新增一个成员.
3. 修改PE头中节的数量.
4. 修改sizeOflmage的大小.
5. 再原有数据的最后,新增一个节的数据(内存对齐的整数倍).
6. 修正新增节表的属性.

###### 导出表

一个程序是由多个配文件所组成，那么这个程序使用了哪些dll文件，会在一个表中记录，这就是导入表；同样的，有哪些程序使用了我这个程序的函数，也会记录在一个表内，这个表是导出表。

如何找到导出表：pe文件结构中最后一个结构中的第一个结构体，那里存放着导出表的地址(rva)和大小(size)

请注意，这个大小(size)指的是导出表中的指针指向的内容的和大小(比如name指针指向的字段以\x00截至，等等的所有字段和加上固定的40个字节，只是编译器填的值，无实际意义)

```c
IMAGE_DIRECTORY_ENTRY_EXPORT
    
struct_IMAGE_DATA_DIRECTORY { 
0x00 DWORD VirtualAddress; 
0x04 DWORD Size;
}
```

通过这个地址就可以找到导出表，结构如下：

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;        //未使用
    DWORD   TimeDateStamp;          //时间戳
    WORD    MajorVersion;           //未使用
    WORD    MinorVersion;           //未使用
    DWORD   Name;                   //指向改导出表文件名字符串
    DWORD   Base;                   //导出表的起始序号
    DWORD   NumberOfFunctions;      //导出函数的个数(更准确来说是AddressOfFunctions的元素数，而不是函数个数)
    DWORD   NumberOfNames;          //以函数名字导出的函数个数
    DWORD   AddressOfFunctions;     //导出函数地址表RVA:存储所有导出函数地址(表元素宽度为4，总大小NumberOfFunctions * 4)
    DWORD   AddressOfNames;         //导出函数名称表RVA:存储函数名字符串所在的地址(表元素宽度为4，总大小为NumberOfNames * 4)
    DWORD   AddressOfNameOrdinals;  //导出函数序号表RVA:存储函数序号(表元素宽度为2，总大小为NumberOfNames * 2)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

1.导出的函数要么用名字导出，要么用序号导出(隐藏),总数为NumberOfNames的值

一共有三个表，地址表，序号表，名称表

其中：序号表的数量与名称表的数量相同。

比如：

|    地址表     | 序号表(2字节) |   名称表    |
| :-----------: | :-----------: | :---------: |
| addr1(knameA) |       4       | ADDR1(AAAA) |
| addr2(knameB) |       1       | ADDR2(BBBB) |
| addr3(knameC) |       0       | ADDR3(CCCC) |
|   00000000    |               |             |
| addr4(knameD) |               |             |

**通过名字找函数时**：

1. 首先遍历名称表，比如找到名称AAAA函数，发现是表中的第0号成员。
2. 通过①中的0直接查询序号表中的0号成员，发现是数字4
3. 通过②中的4直接查找地址表中的第4号成员，为addr4(knameD)，所以knameD就是AAAA

**通过序号找函数时**：

1. 将导出序号减去导出表的起始序号(Base的值)。
2. 将这个值直接对应地址表，就没了。

###### 导入表

1. 依赖一个模块就会有一个导入表，所以导入表有很多。
2. 遇到连续20个\x00说明导入表结束了

结构如下：

```c
typedef struct_IMAGE_IMPORT_DESCRIPTOR 
union {
DWORD Characteristics;
DWORD OriginalFirstThunk;			  //RVA指向IMAGE_THUNK_DATA结构数组
};
DWORD TimeDateStamp;				 //时间戳
DWORD ForwarderChain;
DWORD Name;							 //RVA,指向dl名字，该名字已0结尾
DWORD FirstThunk;					 //RVA,指向IMAGE_THUNK_DATA结构数组
}IMAGE_IMPORT_DESCRIPTOR;
```

其中:

1. OriginalFirstThunk成员和FirstThunk成员又分别指向了INT(导入名称表)和IAT(导入地址表)，这两张表位置和名称都不同，但内容却相同，都能找到函数名称。
2. 当遇到全为\x00时，说明已经结束了。
3. 成员有多少个，该程序就使用了这个dll中的多少个函数。

![image](https://c65mael.github.io/myassets-beg/daorubiao1.png)

```c
typedef struct_IMAGE_THUNK_DATA32
union{
	PBYTE ForwarderString;
	PDWORD Function;
	DWORD Ordinal;						//序号
	PIMAGE_IMPORT_BY_NAME AddressOfData;  //指向IMAGE_IMPORT_BY_NAME
}u1;
}IMAGE_THUNK_DATA32;

```

在OriginalFirstThunk中的IMAGE_THUNK_DATA32成员。判断最高是否为1，如果是，那么除去最高位的值就是函数的导出序号(按序号导入)；如果不是，那么这个值是一个RVA指向IMAGE_IMPORT_BY_NAME

```c
typedef struct_IMAGE_IMPORT_BY_NAME {
	WORD Hint;							//可能为空,编译器决定如果不为空是函数在导出表中的索引
	BYTE Name[1];						//函数名称，以0结尾
}IMAGE IMPORT BY NAME, *PIMAGE IMPORT BY NAME;
```

Hint成员如果不为空，则直接找导出表中地址表的索引，直接可以找到函数。

Hint成员如果为空，则通过Name[1]来确定函数叫说明名字，之所以是1字节，是因为函数不知道函数名称的长度，所以确定第一个字节之后一直找，遇到\x00结束，就是函数的名称。

确定函数地址：

![image](https://c65mael.github.io/myassets-beg/daorubiao2.png)

1. 在使用其他dll中的函数，使用的call都是间接call。间接call会提供一个地址编号来存放函数的地址，那么这个地址所在的表就是导入地址表(IAT)。
2. pe文件加载前后IAT表会发生变化，会存放函数的地址(也就是通过函数的名称进而得到函数的地址)。
3. 为什么有两条线？如果IAT表的这条线被破坏，则可以通过INT表进行修正。

###### 重定位表

如果两个dll文件在导入内存时，导入在相同的ImageBase的偏移处，该怎么办？只需要修正其中一个dll文件的偏移在没有文件导入的内存偏移，即可。但这两个dll中的全局变量的硬编码可能会有相同的偏移。这时就需要使用重定位表了

数据目录项的第6个结构，就是重定位表(相对于映像基址的偏移量)。

结构如下：

```C
typedef struct _IMAGE_BASE_RELOCATION {
	DWORD VirtualAddress;
	DWORD SizeOfBlock; //字节为单位
} IMAGE_BASE_RELOCATION;
```

1. 这个结构体中的第二个成员SizeOfBlock是当前重定位块的总大小，就是加上VirtualAddress成员的大小。
2. 当遇到全为\x00时(8个)，说明已经结束了。

比如其中一个重定位块如下：

| Virtual  |          |          |          |
| :------: | :------: | :------: | :------: |
|   Size   |          |          |          |
| 0011#### | ######## | 0011#### | ######## |
| 0011#### | ######## | 0011#### | ######## |

说明：Virtual代表VirtualAddress成员，Size(0x10)代表SizeOfBlock成员，#代表一位的数据，一个框代表一个字节。

2^12=4096，即为一页对齐的数据，所以使用两个字节(16位其中的低12位)来存放地址，其中的高4位的作用是：当高4位的值为3(0011=3，不是3时就是垃圾！)时，说明该地址有意义重定位，应当重定位的值=VirtualAddress成员+低12位

###### 移动导出表，重定向表

1. 在DLL中新增一个节，并返回新增后的FOA
2. 复制AddressOfFunctions	长度：4*NumberOfFunctions
3. 复制AddressOfNameOrdinals	长度：NumberOfNames*2
4. 复制AddressOfNames	长度：NumberOfNames*4
5. 复制所有的函数名	长度不确定，复制时直接修复AddressOfNames
6. 复制IMAGE_EXPORT_DIRECTORY结构
7. 修复IMAGE_EXPORT_DIRECTORY结构中的	AddressOfFunctions	AddressOfNameOrdinals	AddressOfNames
8. 修复目录项中的值，指向新的IMAGE_EXPORT_DIRECTORY











###### 注入shellcode

不依赖环境，放到任何地方都可以执行的机器码。

ShellCode的编写原则：①不能有全局变量②不能使用常量字符串③不能使用系统调用④不能嵌套调用其他函数

```c
char shellcode[] = {'S','h','e','l','l','C','o','d','e',0}; //不能使用常量字符串
```

后面那个不会



###### VirtualTable_Hook

①HOOK是用来获取、更改程序执行时的某些数据,或者是用于更改程序执行流程的一种技术。

② HOOK的两种主要形式：

1. 改函数代码	INLINE HOOK
2. 改函数地址IAT HOOK	SSDT HOOK	IDT HOOK	EAT HOOK	IRP HOOK



### win32

###### 字符编码

ASCII编码无法满足我们输入的中文文字。便引入了扩展ASCII表，原来的ASCII表进行扩展，将0x80~0xff的两个符号拼起来组成新的文字(GB2312)，就是中文。但是不同国家有不同的规则，那么中文文字发送过去会产生乱码。为了解决这个问题，就产生了unicode编码，unicode编码是将世界上所有的字符建立与0~0x10ffff的对应。但是unicode编码长度可能的1或2或3字节，这样不好存储。

**UTF-16:**

UTF-16编码以16位无符号整数为单位，注意是16位为一个单位,不表示一个字符就只有16位。这个要看字符的unicode编码处于什么范围而定,有可能是2个字节，也可能是4个字节现在机器上的unicode编码一般指的就是UTF-16。

**UTF-8:**

不同的16进制码用不同的UTF-8规则编码

| Unicode编码(6进制) |        UTF-8 字节流(二进制)         |
| :----------------: | :---------------------------------: |
|  000000 - 00007F   |              0xxxxxxx               |
|  000080 - 0007FF   |         110xxxxx  10xxxxxx          |
|  000800 - 00FFFF   |     1110xxxx 10xxxxxx  10xxxxxx     |
|   010000 -10FFFF   | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx |

**BOM(Byte Order Mark):**

放在UTF-8或UTF-16编码的前面，让计算机知道这是什么方式编码的

|      BOM       |          |
| :------------: | :------: |
|     UTF-8      | EF BB BF |
| UTF-16LE(小端) |  FF FE   |
| UTF-16BE(大端) |  FE FF   |

###### c语言中的宽字节

对比：

```c
char szStr[]= "中国";										2D 4E FD 56 00			(GB2312编码)
wchar_t swzStr]=L"中国";									D6 D0 B9 FA 00 00		(Unicode编码)宽字节
```

###### win32 api中的宽字节

- 在win32编程中都是见过的类型，只不过是换了一个名字而已。
- 在win32编程中函数一般都会有两个(比如：massageboxA messageboxW)，为了使ASCII编码和unicode编码有区分。

###### 进程

就是运行中的一个程序，进程提供程序所需要的资源，它提供数据和代码，是一种空间的概念

①进程内存空间的地址划分：

|     分区     |    x86 32位的windows    |
| :----------: | :---------------------: |
| 空指针赋值区 | 0x00000000 - 0x0000FFFF |
|  用户模式区  | 0x00010000 - 0x7FFEFFFF |
|  64KB禁入区  | 0x7FFF0000 - 0x7FFFFFFF |
|     内核     | 0x80000000 - 0xFFFFFFFF |

②进程的创建

<1>任何进程都是别的进程创建的：CreateProcess()

<2> 进程的创建过程

1. 映射EXE文件(将exe放到内存中)
2. 创建内核对象EPROCESS
3. 映射系统DLL(ntdll.dll)
4. 创建线程内核对象ETHREAD
5. 系统启动线程

​		映射DLL(ntdll.LdrlnitializeThunk)

​		线程开始执行

###### 创建进程

```c
BOOL CreateProcess(
	LPCSTR lpApplicationName,	//对象名称
	LPSTR lpCommandLine,		//命令行
	LPSECURITY_ATTRIBUTES lpProcessAttributes,	//不继承进程句柄
	LPSECURITY_ATTRIBUTES lpThreadAttributes,	//不继承线程句柄
	BOOL bInheritHandles,		//不继承句柄
	DWORD dwCreationFlags,		//没有创建标志
	LPVOID lpEnvironment,		//使用父进程环境变量
	LPCSTR lpCurrentDirectory,	//使用父进程自录作为当前目录，可以自己设置目录
	LPSTARTUPINFOA lpStartupInfo,	//STARTUPINFOW结构体详细信息
	LPPROCESS_INFORMATION lpProcessInformation	//PROCESS_INFORMATION结构体进程信息
    )
```

###### 句柄表

什么是内核对象：

像进程、线程、文件、互斥体、事件等在**内核**都有一个对应的**结构体**，这些结构体由内核负责管理。我们管这样的对象叫做内核对象。

![image](https://c65mael.github.io/myassets-beg/nhdx.png)

一个进程有一个自己的内核对象(EPROCESS)，在这一个进程里面还有可能创建其他的内核对象(紫色的)，那么如何使用他们呢？可以将对应的内核对象的地址传回去就可以了，但是在用户层访问内核层的问题在于，如果这个内核对象的地址被修改，那么访问对应内核层的地址时就会内存无法访问。所以就产生了句柄表，句柄表是0环EPROCESS下的一个成员(蓝色的)，句柄表存在的目的就是解决上面的问题。在句柄表里面会存储进程里面所有内核对象的地址(0环)，所以将编号传回去，使用对应的内核对象时用编号来代替对应0环的地址。(相当于防火墙的存在，用户层没办法直接操作内核层)：

![image](https://c65mael.github.io/myassets-beg/gbb1.png)

- 多个进程可以共享一个内核对象，但是索引值可能不太一样。
- 有几个进程打开或使用了这个内核对象，内核对象中的计数器就会变为几(紫色里面的红色小下标)。
- closehandle的api是让内核对象中的计数器的值减一。
- 如果想要关闭线程的内核对象，要使计数器的值为0且需要关闭这个线程，两个条件缺一不可。除了线程以外的内核对象只需要使计数器的值为0就可以关闭这个内核对象。

![image](https://c65mael.github.io/myassets-beg/gbb2.png)























### MFC

本质是对win32api的封装

###### CWinApp类

派生Windows应用程序对象的基类。应用程序对象提供了用于初始化应用程序和运行应用程序的成员函数。

使用MFC的每个应用程序只能包含一个从CWinApp派生的对象。当您从CWinApp派生应用程序类时,覆盖InitInstance成员函数以创建应用程序的主窗口对象。它还有一个成员变量:m pMainWnd用来记录创建的主窗口的对象。

除了CWinApp成员函数之外, Microsoft基础类库还提供了以下全局函数来访问CWinApp对象和其他全局信息:

* AfxGetApp获取一个指向CWinApp对象的指针。
* AfxGetinstanceHandle获取当前应用程序实例的句柄。
* AfxGetResourceHandle获取应用程序资源的句柄。
* AfxGetAppName获取指向包含应用程序名称的字符串的指针。如果您有一个指向CWinApp对象的指针,请使用m pszExeName获取应用程序的名称。

###### CFrameWnd类

提供了Windows单文档界面(SDI)重叠或弹出框架窗口的功能,以及用于管理窗口的成员。

要为应用程序创建有用的框架窗口,请从CFrameWnd派生类。向派生类添加成员变量以存储特定于您的应用程序的数据。在派生类中实现消息处理程序成员函数和消息映射,以指定在将消息定向到窗口时会发生什么。

有三种方法来构造框架窗口：

* 使用Create直接构造它。（本节需要掌握的内容）
* 使用LoadFrame直接构造它。(后续课程讲解)
* 使用文档模板间接构建它。（后续课程讲解）

###### CFrameWnd :: Create 成员函数

如果类名为NULL,则以MFC内建的窗口类产生一个标准的外框窗口

```bash
BOOL Create(LPCTSTR IpszClassName

	LPCTSTR IpszWindowName,

	DWORD dwStyle = WS_OVERLAPPEDWINDOW,

	const RECT& rect = rectDefault,

	CWnd* pParentWnd = NULL, // != NULL for popups

	LPCTSTR IpszMenuName=NULL,

	DWORD dwExStylel=0,

	CCreateContext* pContext=NULL);
```

返回值:非零表示初始化成功,否则为0

备注：通过两个步骤构造一个CFrameWnd对象。首先调用构造函数,它构造CFrameWnd一对象,然后调用Create,创建Windows框架窗口并将其附加到CFrameWnd对象。创建初始化窗口的类名和窗口名称,并注册其样式,父级和关联菜单的默认值。

**总结：(就是根据如下操作就可以创建一个窗口😊)**

1. 基于MFC的窗口程序必须也只能有一个由从CWinApp派生的对象
2. 我们必须覆盖CWinApp的虚函数InitInstance在里面创建窗口.并把窗口对象保存在它的成员变量m pMainWnd.
3. 创建窗口是通过派生CFrameWnd对象.在它的构造函数里面调用成员函数create
