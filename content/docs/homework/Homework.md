---
title: Homework
cascade:
  type: docs
---

### PE结构

#### 内存分配—文件读写

- 将记事本的`.exe`文件读取到内存，并返回读取后在内存中的地址

  ```c
  #include <stdio.h>
  #include <stdlib.h>
  
  void* load(const char* file_path, size_t* size) {
      FILE* file = fopen(file_path, "rb");
      if (!file) {
          return NULL;
      }
  
      fseek(file, 0, SEEK_END);
      *size = ftell(file);
      fseek(file, 0, SEEK_SET);
  
      void* memory = malloc(*size);
      if (!memory) {
          fclose(file);
          return NULL;
      }
  
      size_t read_size = fread(memory, 1, *size, file);
      if (read_size != *size) {
          free(memory);
          fclose(file);
          return NULL;
      }
  
      fclose(file);
  
      return memory;
  }
  
  int main() {
      const char* path = "C:\\Windows\\notepad.exe";
      size_t size = 0;
  
      void* file_memory = load(path, &size);
  
      if (file_memory) {
          printf("address: %p\n", file_memory);
          printf("size: %zu bytes\n", size);
          }
          free(file_memory);
      }
  
      return 0;
  }
  ```

- 将内存中的数据存储到一个文件中，（`.exe`格式），然后双击打开，看是否能够使用

  ```c
  int main()
  {
      const char* lpszFile = "output.exe";
      FILE *pFile = NULL;
      FILE* fpw = fopen_s(&pFile, lpszFile, "rb");
      if(!fpw)
      {
          return 0;
      }
      if (fwrite(pMemBuffer, 1, size, fpw) == 0)
  	{
  		return 0;
  	}
  	fclose(fpw);			
  	fpw = NULL;
  	return size;
  }
  ```

#### PE头解析

```asm
    4D  5A  90  00  03  00  00  00  04  00  00  00  FF  FF  00  00 
    B8  00  00  00  00  00  00  00  40  00  00  00  00  00  00  00 
    00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00 
    00  00  00  00  00  00  00  00  00  00  00  00  D8  00  00  00| 
    0E  1F  BA  0E  00  B4  09  CD  21  B8  01  4C  CD  21  54  68 
    69  73  20  70  72  6F  67  72  61  6D  20  63  61  6E  6E  6F 
    74  20  62  65  20  72  75  6E  20  69  6E  20  44  4F  53  20 
    6D  6F  64  65  2E  0D  0D  0A  24  00  00  00  00  00  00  00 
    31  42  8C  CE  75  23  E2  9D  75  23  E2  9D  75  23  E2  9D 
    F6  3F  EC  9D  7B  23  E2  9D  43  05  E8  9D  43  23  E2  9D 
    75  23  E3  9D  46  23  E2  9D  17  3C  F1  9D  76  23  E2  9D 
    43  05  E9  9D  76  23  E2  9D  52  69  63  68  75  23  E2  9D 
    00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00 
    00  00  00  00  00  00  00  00  50  45  00  00  |4C  01  05  00 
    4A  11  BE  54  00  00  00  00  00  00  00  00  E0  00  0E  01| 
    0B  01  06  00  00  10  02  00  00  A0  00  00  00  00  00  00 
    20  12  00  00  00  10  00  00  00  10  00  00  00  00  40  00
    00  10  00  00  00  10  00  00  04  00  00  00  00  00  00  00 
    04  00  00  00  00  00  00  00  00  C0  02  00  00  10  00  00 
    00  00  00  00  03  00  00  00  00  00  10  00  00  10  00  00 
    00  00  10  00  00  10  00  00  00  00  00  00  10  00  00  00 
```

以这个为例吧

- 找出所有`DOC`头数据，并统计`DOC`头大小

  ```asm
  e_magic = 4D  5A
  e_cblp = 90  00
  e_cp = 03  00
  e_crlc = 00  00
  e_cparhdr = 04  00
  e_minalloc = 00  00
  e_maxalloc = FF  FF
  e_ss = 00  00
  e_sp = B8  00
  e_csum = 00  00
  e_ip = 00  00
  e_cs = 00  00
  e_lfarlc = 40  00
  e_ovno = 00  00
  e_res[4] = 00  00,00  00,00  00,00  00
  e_oemid = 00  00
  e_oeminfo = 00  00
  e_res2[10] = 00  00,00  00,00  00,00  00,00  00,00  00,00  00,00  00,00  00,00  00
  e_lfanew = D8  00  00  00
  ```

- 找出所有标准PE头数据，并统计标准PE头大小

  ```asm
  Signature = 00  00
  Machine = 4C  01
  NumberOfSection = 05  00 
  TimeDateStamp = 4A  11  BE  54
  PointerToSymbolTable = 00  00  00  00
  NumberOfSymbols = 00  00  00  00
  SizeOfOptionalHeader = E0  00
  Characteristics = 0E  01
  ```

- 找出所有可选PE头数据，并统计可选PE头大小

  ```asm
  Magic = 0B  01
  MajorLinkerVersion = 06
  MinorLinkerVersion = 00
  SizeOfCode = 00  10  02  00
  SizeOfInitializedData = 00  A0  00  00
  SizeOfUninitializedData = 00  00  00  00
  AddressOfEntryPoint = 20  12  00  00
  BaseOfCode = 00  10  00  00
  BaseOfData = 00  10  00  00
  ImageBase = 00  00  40  00
  SectionAlignment = 00  10  00  00
  FileAlignment = 00  10  00  00
  MajorOperatingSystemVersion = 04  00
  MinorOperatingSystemVersion = 00  00
  MajorImgdeVersion = 00  00
  MinorImgdeVersion = 00  00
  MajorSubsystemVersin = 04  00
  MinorSubsystemVersin = 00  00
  Win32VersionValue = 00  00  00  00
  SizeOfImage = 00  C0  02  00
  SizeOfHeaders = 00  10  00  00
  CheckSum = 00  00  00  00
  Subsystem = 03  00
  DllCharacteristics = 00  00
  SizeOfStackReserve = 00  00  10  00
  SizeOfStackCommit = 00  10  00  00 
  SizeOfHeapReserve = 00  00  10  00
  SizeOfHeapCommit = 00  10  00  00 
  LoadFlags = 00  00  00  00
  NumberOfRvaAndSizes = 10  00  00  00
  ```

- 编写程序读取一个`.exe`文件，输出所有的PE头信息

  ```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <windows.h>
  
  #define FILEPATH "C:\\Users\\Administrator\\Desktop\\HelloWorld.exe"
  
  LPVOID ReadPEFile(LPSTR lpszFile)
  {
      FILE *pFile = NULL;
      DWORD fileSize = 0;
      LPVOID pFileBuffer = NULL;
  	size_t n = 0 ; 
      
      // 使用 fopen_s 来打开文件
      if (fopen_s(&pFile, lpszFile, "rb") != 0 || pFile == NULL)
      {
          return NULL;
      }
      
      fseek(pFile, 0, SEEK_END);
      fileSize = ftell(pFile);
      fseek(pFile, 0, SEEK_SET);
      
      pFileBuffer = malloc(fileSize);
      if (!pFileBuffer)
      {
          fclose(pFile);
          return NULL;
      }
      
      // 使用 size_t 类型的变量来存储 fread 的返回值
      n = fread(pFileBuffer, 1, fileSize, pFile);
      if (n != fileSize)
      {
          free(pFileBuffer);
          fclose(pFile);
          return NULL;
      }
      fclose(pFile);
      
      return pFileBuffer;
  }
  
  VOID PrintNTHeaders()
  {
      LPVOID pFileBuffer = NULL;
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      
      pFileBuffer = ReadPEFile(FILEPATH);
      if (!pFileBuffer)
      {
          printf("Error reading the file.\n");
          return;
      }
      
      // 检查 DOS 头签名
      if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
      {
          free(pFileBuffer);
          printf("Not a valid PE file (DOS header signature mismatch).\n");
          return;
      }
      
      pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
      printf("DOS Header\n");
      printf("MZ: %X\n", pDosHeader->e_magic);
      printf("PE Offset: %X\n", pDosHeader->e_lfanew);
      
      // 检查 NT 头签名
      if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
      {
          free(pFileBuffer);
          printf("Not a valid PE file (NT header signature mismatch).\n");
          return;
      }
      
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
      printf("\n\nNT Header\n");
      printf("NT Signature: %X\n", pNTHeader->Signature);
      
      pPEHeader = &pNTHeader->FileHeader;  // 获取 PE 文件头
      printf("\n\nPE File Header\n");
      printf("Machine: %X\n", pPEHeader->Machine);
      printf("Number of Sections: %d\n", pPEHeader->NumberOfSections);
      printf("Size of Optional Header: %X\n", pPEHeader->SizeOfOptionalHeader);
      
      pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + sizeof(IMAGE_FILE_HEADER));
      printf("\n\nOptional Header\n");
      printf("Magic: %X\n", pOptionHeader->Magic);
      
      free(pFileBuffer);  // 释放文件缓冲区
  }
  
  int main()
  {
  	ReadPEFile(FILEPATH);
  	PrintNTHeaders();
  	return 0;
  }
  ```

- 编写程序打印节表中的信息

  ```
  偏移如下：
  +-------------------------+  <-- 文件开始
  |     IMAGE_DOS_HEADER    |
  +-------------------------+
  |   Padding (对齐数据)    |
  +-------------------------+  <-- e_lfanew 指向这里
  |    IMAGE_NT_HEADERS     |  <-- pNTHeader
  |  - Signature (4B)       |
  |  - IMAGE_FILE_HEADER    |
  |  - IMAGE_OPTIONAL_HEADER|
  +-------------------------+
  |   IMAGE_SECTION_HEADER  |  <-- 节表开始
  |       Section[0]        |
  |       Section[1]        |
  |          ...            |
  +-------------------------+
  
  还有就是从pNTHeader开始找IMAGE_SECTION_HEADER的过程，其中注意sizeof(IMAGE_OPTIONAL_HEADER)是编译时定义的常量，就是理论大小;而pNTHeader->FileHeader.SizeOfOptionalHeader表示实际的 IMAGE_OPTIONAL_HEADER 大小
  ```
  
  ```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <windows.h>
  
  #define FILEPATH "C:\\Users\\Administrator\\Desktop\\notepad.exe"
  
  LPVOID ReadPEFile(LPSTR lpszFile)
  {
      FILE *pFile = NULL;
      DWORD fileSize = 0;
      LPVOID pFileBuffer = NULL;
      size_t n = 0;
  
      if (fopen_s(&pFile, lpszFile, "rb") != 0 || pFile == NULL)
      {
          return NULL;
      }
  
      fseek(pFile, 0, SEEK_END);
      fileSize = ftell(pFile);
      fseek(pFile, 0, SEEK_SET);
  
      pFileBuffer = malloc(fileSize);
      if (!pFileBuffer)
      {
          fclose(pFile);
          return NULL;
      }
  
      n = fread(pFileBuffer, 1, fileSize, pFile);
      if (n != fileSize)
      {
          free(pFileBuffer);
          fclose(pFile);
          return NULL;
      }
      fclose(pFile);
  
      return pFileBuffer;
  }
  
  VOID PrintNTSections()
  {
      LPVOID pFileBuffer = NULL;
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
  	int i = 0;
  	char name[9] = {0};
  
      pFileBuffer = ReadPEFile(FILEPATH);
      if (!pFileBuffer)
      {
          printf("Error reading the file.\n");
          return;
      }
  
      if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
      {
          free(pFileBuffer);
          printf("Not a valid PE file (DOS header signature mismatch).\n");
          return;
      }
  
      pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
  
      if (*((PDWORD)((DWORD_PTR)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
      {
          free(pFileBuffer);
          printf("Not a valid PE file (NT header signature mismatch).\n");
          return;
      }
  
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pFileBuffer + pDosHeader->e_lfanew);
  
      pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNTHeader + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_OPTIONAL_HEADER) + pNTHeader->FileHeader.SizeOfOptionalHeader);
  
      printf("Section Headers:\n");
      printf("Name\tVirtual Address\tSize\tRaw Data Pointer\n");
      for (; i < pNTHeader->FileHeader.NumberOfSections; i++)
      {
          
          strncpy(name, (char *)pSectionHeader[i].Name, 8);
          printf("%s\t0x%08X\t0x%08X\t0x%08X\n",
                 name,
                 pSectionHeader[i].VirtualAddress,
                 pSectionHeader[i].Misc.VirtualSize,
                 pSectionHeader[i].PointerToRawData);
      }
  
      free(pFileBuffer);
  }
  
  int main()
  {
      PrintNTSections();
      return 0;
  }
  ```

#### FileBuffer-ImageBuffer

- 实现如下功能:

  ![image](/homework/pe-h1.png)

  编写一个函数，能够将`RVA`的值转换成`FOA`

  ```c
  //函数声明								
  //**************************************************************************								
  //ReadPEFile:将文件读取到缓冲区								
  //参数说明：								
  //lpszFile 文件路径								
  //pFileBuffer 缓冲区指针								
  //返回值说明：								
  //读取失败返回0  否则返回实际读取的大小								
  //**************************************************************************								
  DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);								
  {
  	FILE *pFile = NULL;
      DWORD fileSize = 0;
      size_t n = 0;
  
      if (fopen_s(&pFile, lpszFile, "rb") != 0 || pFile == NULL)
      {
          return NULL;
      }
  
      fseek(pFile, 0, SEEK_END);
      fileSize = ftell(pFile);
      fseek(pFile, 0, SEEK_SET);
  
      pFileBuffer = malloc(fileSize);
      if (!pFileBuffer)
      {
          fclose(pFile);
          return NULL;
      }
  
      n = fread(pFileBuffer, 1, fileSize, pFile);
      if (n != fileSize)
      {
          free(pFileBuffer);
          fclose(pFile);
          return NULL;
      }
      fclose(pFile);
      return fileSize;
  }
  //**************************************************************************								
  //CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer								
  //参数说明：								
  //pFileBuffer  FileBuffer指针								
  //pImageBuffer ImageBuffer指针								
  //返回值说明：								
  //读取失败返回0  否则返回复制的大小								
  //**************************************************************************								
  DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);	
  {
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
      int i = 1;
      
      if (pFileBuffer == NULL || pImageBuffer == NULL) {
          return 0;
      }
      
      pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
      pPEHeader = &pNTHeader->FileHeader;
      pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
      pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNTHeader + sizeof(IMAGE_NT_HEADERS));
      
      *pImageBuffer = malloc(pOptionHeader -> SizeOfImage);
      if (*pImageBuffer == NULL) {
          return 0;
      }
  
  
      memcpy(*pImageBuffer, pFileBuffer, pOptionHeader -> SizeOfImage);
      for(;i<pFileHeader->NumberOfSections;i++,pSectionHeader++)
      {
          memcpy((LPVOID)((DWORD)*ppImageBuffer+pSectionHeader->VirtualAddress),(LPVOID)((DWORD)pFileBuffer+pSectionHeader->PointerToRawData),pSectionHeader->SizeOfRawData);
      }
  
  
      return pOptionHeader -> SizeOfImage;
  }
  //**************************************************************************								
  //CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区								
  //参数说明：								
  //pImageBuffer ImageBuffer指针								
  //pNewBuffer NewBuffer指针								
  //返回值说明：								
  //读取失败返回0  否则返回复制的大小								
  //**************************************************************************								
  DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);
  {
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
      int i = 0;
      
  	if(!pImageBuffer)
  	{
  		return 0;
  	}
      
      pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
      pPEHeader = &pNTHeader->FileHeader;
      pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
      pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNTHeader + sizeof(IMAGE_NT_HEADERS));
      
      memcpy(*pImageBuffer, pNewBuffer, pOptionHeader -> SizeOfImage);
      for(;i<pFileHeader->NumberOfSections;i++,pSectionHeader++)
      {
          memcpy((LPVOID)((DWORD)*ppImageBuffer+pSectionHeader->VirtualAddress),(LPVOID)((DWORD)pNewBuffer+pSectionHeader->PointerToRawData),pSectionHeader->SizeOfRawData);
      }
      
      return pOptionHeader -> SizeOfImage;
  }
  //**************************************************************************								
  //MemeryTOFile:将内存中的数据复制到文件								
  //参数说明：								
  //pMemBuffer 内存中数据的指针								
  //size 要复制的大小								
  //lpszFile 要存储的文件路径								
  //返回值说明：								
  //读取失败返回0  否则返回复制的大小								
  //**************************************************************************								
  BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
  {
      FILE *pFile = NULL;
      FILE* fpw = fopen_s(&pFile, lpszFile, "rb");
      if(!fpw)
      {
          return 0;
      }
      if (fwrite(pMemBuffer, 1, size, fpw) == 0)
  	{
  		return 0;
  	}
  	fclose(fpw);			
  	fpw = NULL;
  	return size;
  }
  //**************************************************************************								
  //RvaToFileOffset:将内存偏移转换为文件偏移								
  //参数说明：								
  //pFileBuffer FileBuffer指针								
  //dwRva RVA的值								
  //返回值说明：								
  //返回转换后的FOA的值  如果失败返回0								
  //**************************************************************************								
  DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);
  {
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
      DWORD sectionCount = NULL;
      DWORD dwFoa = 0;
      int i = 0;
      
      if (pFileBuffer == NULL) {
          return 0;
      }
      
      pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
      pPEHeader = &pNTHeader->FileHeader;
      pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
      pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNTHeader + sizeof(IMAGE_NT_HEADERS));
      sectionCount = pNtHeaders->FileHeader.NumberOfSections;
      
      for(;i < sectionCount;i++)
      {
          if(dwRva >= pSectionHeader[i].VirtualAddress && dwRva < pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)
          {
              dwFoa = dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
              return dwFoa;
          }
      }
      
      return 0;
  }
  ```
  
  自己不会写，把大佬的全部抄了一遍（自己真的写不出来😭）
  
  ```c
  // globlepdd.h: interface for the globlepdd class.
  //
  //////////////////////////////////////////////////////////////////////
  
  #if !defined(AFX_GLOBLEPDD_H__DDA6AB97_A94D_41F9_B3B9_8426B6CB7934__INCLUDED_)
  #define AFX_GLOBLEPDD_H__DDA6AB97_A94D_41F9_B3B9_8426B6CB7934__INCLUDED_
  
  #if _MSC_VER > 1000
  #pragma once
  #endif // _MSC_VER > 1000
  
  #include <windows.h>
  #include <stdio.h>
  
  //#define FILEPATH_IN         "C:\\WINDOWS\\system32\\kernel32.dll"
  //#define FilePath_In         "C:\\Windows\\notepad.exe"
  #define FilePath_In         "C:\\Windows\\Input.exe"
  //#define FilePath_Out        "C:\\Windows\\notepadnewpes.exe"
  #define FilePath_Out        "C:\\Windows\\Out.exe"
  #define MESSAGEBOXADDR      0x77D5050B
  #define SHELLCODELENGTH     0x12 //16进制的，转换为十进制就是18
  
  extern BYTE ShellCode[];
  
  DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);
  
  DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);
  
  DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer,OUT LPVOID* pNewBuffer);
  
  BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile);
  
  //DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva);
  
  VOID AddCodeInCodeSec();
  
  #endif // !defined(AFX_GLOBLEPDD_H__DDA6AB97_A94D_41F9_B3B9_8426B6CB7934__INCLUDED_)
  ```
  
  ```c
  // globlepdd.cpp: implementation of the globlepdd class.
  //
  //////////////////////////////////////////////////////////////////////
  
  #include "stdafx.h"
  #include "globlepdd.h"
  #include <string.h>
  #include <windows.h>
  #include <stdlib.h>
  
  //////////////////////////////////////////////////////////////////////
  // Construction/Destruction
  //////////////////////////////////////////////////////////////////////
  
  BYTE ShellCode[] = 
  {
      0x6A,00,0x6A,00,0x6A,00,0x6A,00, //push 0
      0xE8,00,00,00,00,  // call
      0xE9,00,00,00,00   // jmp
  };
  
  DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
  {
      FILE* pFile = NULL;
      DWORD fileSize = 0;
      LPVOID pTempFileBuffer = NULL;
      
      //open
      pFile = fopen(lpszFile,"rb");
      if(!pFile)
      {
          return 0;
      }
      
      //size
      fseek(pFile,0,SEEK_END);
      fileSize = ftell(pFile);
      fseek(pFile,0,SEEK_SET);
      
      //malloc
      pTempFileBuffer = malloc(fileSize);
      if(!pTempFileBuffer)
      {
          fclose(pFile);
          return 0;
      }
      
      //read memory
      size_t n = fread(pTempFileBuffer,fileSize,1,pFile);
      if(!n)
      {
          free(pTempFileBuffer);
          fclose(pFile);
          return 0;
      }
      
      //succeed close file
      *pFileBuffer = pTempFileBuffer;
      pTempFileBuffer = NULL;
      fclose(pFile);
      return fileSize;
  }
  
  DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer)
  {
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTIOM_HEADER pSectionHeader = NULL;
      LPVOID pTempImageBuffer = NULL;
      
      if(pFileBuffer == NULL)
      {
          return 0;
      }
      
      if(*((PWORD)pFileBuffer)!= IMAGE_DOS_SIGNATURE)
      {
          return 0;
      }
      pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
      if(*((PDWORD)((DOWRD)pFileBuffer+pDosHeader -> e_lfanew)) != IMAGE_NT_SIGNATURE)
      {
          return 0;
      }
      //NT
      pNTHeader = (PIMAGE_NT_HEADER)((DWORD)pFileBuffer+pDosHeader -> e_lfanew);
      //PE
      pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
      //OPT PE
      pOptionHeader = (PIMAGE_OPTION_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
      //SEC HEADER
      pSectionHeader = (PIMAGE_SECTIOM_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
      
      pTempImageBuffer = malloc(pOptionHeader->SizeOfImage);
      if (!pTempImageBuffer)
      {
          return 0;
      }
      memset(pTempImageBuffer,0,pOptionHeader->SizeOfImage);
      memcpy(pTempImageBuffer,pDosHeader,pOptionHeader->SizeOfheHeaders);
      PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
      for(int i=0;i<pPEHeader->NumberOfSections;i++,pTempSectionHeader++)
      {
          memcpy((void*)((DWORD)pTempImageBuffer+pTempSectionHeader->VirtualAddress),(void*)((DWORD)pFileBuffer+pTempSectionHeader->PointerToRawData),pTempSectionHeader->SizeOfRawData);
      }
      *pImageBuffer=pTempImageBuffer;
      pTempImageBuffer=NULL;
      return pOptionHeader->SizeOfImage;
  }
  
  BOOL MemeryTOFile(IN LPVOID pMemBuffer,IN size_t size,OUT LPSTR lpszFile)
  {
      FILE* fp = NULL;
      fp = fopen(lpFile,"wb+");
      if(!fp)
      {
          return FALSE;
      }
      fwrite(pMemBuffer,size,1,fp);
      fclose(fp);
      fp = NULL;
      return TRUE;
  }
  
  DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva)
  {
      DWORD dwFOAValue = 0;
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
      
      if(!pFileBuffer)
      {
          return dwFOValue;
      }
      
      if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE)
      {
          return dwFOValue;
      }
      pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
      pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
      pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
      return 0;
  }
  ```
  
  解释：
  
  > `fseek`通过使用二进制的方式打开文件，移动文件读写指针的位置，在`stdio.h`头文件里
  >
  > `int fseek(FILE * stream, long offset, int fromwhere);`
  >
  > 上面是`fseek`的函数原型
  > 第一个参数`stream`为文件指针
  > 第二个参数`offset`为偏移量，整数表示正向偏移，负数表示负向偏移
  > 第三个参数`fromwhere`为指针的起始位置,设定从文件的哪里开始偏移,可能取值为：`SEEK_CUR，SEEK_END，SEEK_SET`
  > `SEEK_SET` 0 文件开头
  > `SEEK_CUR` 1 当前读写的位置
  > `SEEK_END` 2 文件尾部
  >
  > 
  >
  > `ftell()`用于返回文件当前指针指向的位置，与`fseek`配合可以算出文件元素数据总数。
  >
  > `ftell()`函数用来获取文件读写指针的当前位置，其原型为：`long ftell(FILE * stream)`; 同样在`stdio.h`头文件里
  >
  > 
  >
  > `void* malloc (size_t size);`
  > `size_t` ---> `typedef unsigned int size_t`；无符号整型别名是`size_t`
  > `void*`  ---> 函数的返回值类型是`void*`；`void`并不是说没有返回值或者返回空指针，而是返回的指针类型未知;
  > 所以在使用`malloc()`时通常需要进行强制类型转换，将 void 指针转换成我们希望的类型;
  > 例如：`char *ptr = (char *)malloc(10);`  //分配10个字节的内存空间，用来存放字符
  > 参数说明 ---> `size` 为需要分配的内存空间的大小，以字节（`Byte`）计。
  > 函数说明 ---> `malloc()`在堆区分配一块指定大小的内存空间，用来存放数据。这块内存空间在函数执行完成后不会被初始化;
  > 它们的值是未知的，所以分配完成内存之后需要初始化；
  > 返回值:分配成功返回指向该内存的地址，失败则返回`NULL`。
  >
  > 
  >
  > `LPVOID` ---->  `typedef void far *LPVOID`；在`WINDEF.H`头文件里面；别名的`void`指针类型
  >
  > 
  >
  > `PIMAGE_DOS_HEADER` ---> 指向结构体，别名为这两个`IMAGE_DOS_HEADER`, `*PIMAGE_DOS_HEADER`
  > `PIMAGE_NT_HEADERS` ---> 指向结构体，`typedef PIMAGE_NT_HEADERS32`    `PIMAGE_NT_HEADERS`;
  > `PIMAGE_FILE_HEADER` ---> 指向结构体，别名为这两个`IMAGE_FILE_HEADER`, `*PIMAGE_FILE_HEADER`;
  > `PIMAGE_OPTIONAL_HEADER32` ---> 指向结构体，别名为这两个 `IMAGE_OPTIONAL_HEADER32`，`*PIMAGE_OPTIONAL_HEADER32`;
  > `PIMAGE_SECTION_HEADER` ---> 指向结构体，别名为这两个`IMAGE_SECTION_HEADER`，`*PIMAGE_SECTION_HEADER`;
  >
  > 
  >
  > `IMAGE_DOS_SIGNATURE`这个在头文件`WINNT.H`里面，对应是个无参数宏；
  > `#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ`
  > 在宏扩展的时候就会替换为`0x5A4D`，然后根据架构的不同进行排序存储，分大端和小端模式；
  > 使用上面方式进行比对是否是有效的`MZ`头是非常有效；
  > 而且`IMAGE_DOS_SIGNATURE`存储的值是两个字节，刚好就是`PWORD` ---> `typedef WORD near *PWORD`；
  > 所以在进行比较的时候需要强制类型转换为相同的类型进行比较
  >
  > 
  >
  > `IMAGE_NT_SIGNATURE`  ---> `#define IMAGE_NT_SIGNATURE   0x00004550  // PE00`
  > 上述同样是个宏扩展，在头文件`WINNT.H`里面；
  > 在进行比对的时候因为在`Dos`头里面有个值是`e_lfanew`对应的时候`DWORD`类型，所以在进行指针相加的时候
  > 需要先进行强制类型转换，然后相加，即移动指针位置；然后最终需要比对的结果是`0x4550`站两个字节
  > 所以又要强制转换类型为`PWORD`；
  >
  > 
  >
  > `IMAGE_SIZEOF_FILE_HEADER`也是个宏扩展，里面字节描述了`PE`文件头的大小是20个字节；
  > `#define IMAGE_SIZEOF_FILE_HEADER  20`，所以只要在PE文件头的首地址偏移20个字节即可移动到可选`PE`头；
  > 指针相加的时候，此处的类型依然是`DWORD`
  >
  > 
  >
  > 到了节表的首地址位置之后，因为需要将`FileBuffer`复制到`ImageBuffer`，这个过程中，节表之前的`Dos`头，`NT`头
  > `PE`文件头，可选`PE`头，它们的大小都是不变的，所以定位出来之后，到后面的操作中直接复制即可，而节表不一样
  > 它在`FileBuffer`状态和`ImageBuffer`状态是不相同的，它们节表之间复制转换到`ImageBuffer`是需要拉长节表，所以
  > 在操作的时候是需要确定`FileBuffer`到`ImageBuffer`之后`ImageBuffer`的大小是多少，而这个大小，已经在可选`PE`头
  > 里面的某一个值中已经给出来了 ---> `SizeOfImage` ;
  >
  > 
  >
  > `void* memset( void* ptr,int value,size_t num );`
  > `memset()`函数用来将指定内存的前n个字节设置为特定的值;
  >
  > 参数说明：
  > `ptr`：为要操作的内存的指针;
  > `value`：为要设置的值;既可以向value传递int类型的值,也可以传递`char`类型的值，`int`和`char`可以根据`ASCII`码相互转换;
  > `num`：为`ptr`的前`num`个字节，`size_t`就是`unsigned int`。
  > 函数说明：`memset()`会将`ptr`所指的内存区域的前`num`个字节的值都设置为`value`，然后返回指向`ptr`的指针；
  >
  > 
  >
  > `void* memcpy (void* dest,const void* src,size_t num);`
  > `memcpy()`函数功能用来复制内存的；她会复制`src`所指向内容的首地址，作为起始位置，然后偏移`num`个字节到`dest`所指的内存地址
  > 的位置；此函数有个特征就是，她并不关心被复制的数据类型，只是逐字节地进行复制，这给函数的使用带来了很大的灵活性，
  > 可以面向任何数据类型进行复制；
  >
  > 需要注意的是：
  > `dest`指针要分配足够的空间，也就是要大于等于`num`字节的空间，如果没有分配足够的空间会出现错误；
  > `dest`和`src`所指的内存空间不能重叠（如果发生了重叠，使用`memmove()`会更加安全）。

#### 代码节空白区添加代码

- 在代码空白区添加代码（手动）

  我找的这个程序是之前的那个`crackme`，由于文件对齐和内存对齐不一样，所以要算一下。`CODE`节开头在文件中是`600h`，在内存中是`1000h`，换算关系为：`内存地址 = 文件地址 - 600 + 1000`。防止头晕所以全部转为内存地址计算就可以了，视频中说的那个`MessageboxA`地址就直接用`CODE`节那里面的函数地址是`CODE:0040143A`。加到第一个节的文件中的`B90`位置，仔细算一下要跳的地址就行，一定要按小端序来写：

  ```
  6A 00 6A 00 6A 00 6A 00 E8 9D FE FF FF E9 5E FA FF FF
  ```

  再将`oep`改为`1590h`就好了。

#### 任意代码空白区添加代码

- 向代码节添加代码编程实现

  ```c
  VOID ADDCodeInCodeSec()
  {
      LPVOID pFileBuffer = NULL;
      LPVOID pImageBuffer = NULL;
      LPVOID pNewBuffer = NULL;
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
      PBYTE codeBegin = NULL;
      BOOL isOK = FALSE;
      DWORD size = 0;
      
      ReadPEFile(FilePath_In,&pFileBuffer);
      if(!pFileBuffer)
      {
          return ;
      }
      CopyFileBufferToImageBuffer(pFileBuffer,&pImageBuffer);
      if(!pFileBuffer)
      {
          free(pFileBuffer);
          return ;
      }
      pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
      pOprionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
      pSectionHeader = (PIMAGE_SECTION_HEADER)(((DWORD)pImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER + IMAGE_SIZEOF_NT_OPTIONAL32_HEADER);
      if (((pSectionHeader->SizeOfRawData) - (pSectionHeader->Misc.VirtualSize)) < SHELLCODELENGTH)
      {
          free(pFileBuffer);
          free(pImageBuffer);
      }
      codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
      printf("pSectionHeader->VirtualAddress: %#010X\r\n", pSectionHeader->VirtualAddress);
      printf("pSectionHeader->Misc.VirtualSize: %#010X\r\n", pSectionHeader->Misc.VirtualSize);
      printf("codeBegin: %#010X\r\n", codeBegin);
      memcpy(codeBegin,ShellCode,SHELLCODELENGTH);
      DWORD callAddr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)));
      printf("callAddr ---> %#010X \r\n",callAddr);
      *(PDWORD)(codeBegin + 0x09) = callAddr;
      printf("*(PWORD)(codeBegin + 0x09) ---> %#010X \r\n",*(PDWORD)(codeBegin + 0x09));
      DWORD jmpAddr = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + SHELLCODELENGTH) - (DWORD)pImageBuffer)));
      printf("jmpAddr ---> %#010X \r\n",jmpAddr);
      *(PDWORD)(codeBegin + 0x0E) = jmpAddr;
      printf("*(PWORD)(codeBegin + 0x0E) ---> %#010X \r\n",*(PDWORD)(codeBegin + 0x0E));
      printf("pOptionHeader->AddressOfEntryPoint ---> %#010X \r\n",pOptionHeader->AddressOfEntryPoint);
      printf("(DWORD)codeBegin ---> %#010X \r\n",((DWORD)codeBegin - (DWORD)pImageBuffer));
      pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;
      printf("pOptionHeader->AddressOfEntryPoint ---> %#010X \r\n",pOptionHeader->AddressOfEntryPoint);
      
      size = CopyImageBufferToNewBuffer(pImageBuffer,&pNewBuffer);
      if (size == 0 || !pNewBuffer)
      {
          free(pFileBuffer);
          free(pImageBuffer);
          return ;
      }
      
      isOK = MemeryTOFile(pNewBuffer,size,FilePath_Out);
      if (isOK)
      {
          return ;
      }
  
      free(pFileBuffer);
      free(pImageBuffer);
      free(pNewBuffer);
  }
  }
  ```

- 向其他节空白区添加代码编程实现

#### 新增节-添加代码

- 手动新增一个节表和节，保证修改后的程序能正确执行

  1. 改`SizeOfImage`
  2. 改节的个数
  3. 加一个节表，并修正
  4. 到文件最后加对应大小的位置
  
- 编程实现：新增一个节，并添加代码

  ```c
  BOOL AddFileBufferToSectionTable(IN LPVOID pFileBuffer,OUT LPVOID* pNewBuffer,IN const char* sectionTable,IN size_t SsectionTableSize)
  {
      PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
  	//NT头
  	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
  	//标准PE头
  	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 0x4);
  	//可选PE头
  	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
  	//节表解析
  	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
  
  	//计算空间是否足够
      DWORD whiteSpaceSize = 0;
      whiteSpaceSize = pNTHeader->OptionalHeader.SizeOfHeaders - (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pNTHeader->FileHeader.NumberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER)));
  	if (whiteSpaceSize < sizeof(IMAGE_SECTION_HEADER))
  	{
  		printf("数据缓冲区太小无法添加节表！");
  		return false;
  	}
  	//Copy一个新的节表 
  	char* pTmpFile = (char*)pFileBuffer;
  	char* pTmpFileCopy = (char*)pFileBuffer;
  	pTmpFile = pTmpFile + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader);
  	pTmpFileCopy = pTmpFileCopy + (pDosHeader->e_lfanew + sizeof(pNTHeader->Signature) + sizeof(pNTHeader->FileHeader) + pPEHeader->SizeOfOptionalHeader + ((pNTHeader->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)));
  	memcpy(pTmpFileCopy, pTmpFile, sizeof(IMAGE_SECTION_HEADER));
  	//在新增节后面 填充一个节大小的000 (忽略)
  	//修改PE头中节的数量
  	pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
  	//修改sizeOfImage的大小
  	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + SsectionTableSize;
  	//再原有数据的最后，新增一个节的数据(内存对齐的整数倍)
  	//使用PE结构计算文件大小
  	PIMAGE_SECTION_HEADER pTempSectionHeaderTo = pSectionHeader;
  	for (DWORD i = 2; i < pPEHeader->NumberOfSections; i++)
  		pTempSectionHeaderTo++;
  	DWORD fileSize = pTempSectionHeaderTo->SizeOfRawData + pTempSectionHeaderTo->PointerToRawData;
  	//申请File大小空间
  	*pNewBuffer = (PDWORD)malloc(fileSize + SsectionTableSize);
  	if (!*pNewBuffer)
  	{
  		printf("%s", "申请ImageBuffer失败！");
  		free(*pNewBuffer);
  		return false;
  	}
  	memset(*pNewBuffer, 0, fileSize + SsectionTableSize);
  	//修正节表属性
  	PIMAGE_SECTION_HEADER pTempSectionHeaderTo2 = (PIMAGE_SECTION_HEADER)pTmpFileCopy;
  	memcpy(pTempSectionHeaderTo2->Name, sectionTable, 4);
  	pTempSectionHeaderTo2->Misc.VirtualSize = SsectionTableSize;
  	pTempSectionHeaderTo2->VirtualAddress = pTempSectionHeaderTo->VirtualAddress + Align(pTempSectionHeaderTo->Misc.VirtualSize, pNTHeader->OptionalHeader.SectionAlignment);
  	pTempSectionHeaderTo2->SizeOfRawData = Align(SsectionTableSize, pNTHeader->OptionalHeader.FileAlignment);
  	pTempSectionHeaderTo2->PointerToRawData = pTempSectionHeaderTo->PointerToRawData + Align(pTempSectionHeaderTo->SizeOfRawData, pNTHeader->OptionalHeader.FileAlignment);
  	memcpy(*pNewBuffer, pFileBuffer, fileSize);
  	return true;
  }
  ```

- 编程实现：扩大最后一个节，并添加代码

  

#### 扩大节-合并节-数据目录

- 扩大最后一个节，保证程序正常运行

  1. 改`SizeOfImage`
  2. 改大`SizeOfRawData`和`VirtualSize`
  3. 到文件最后加对应大小的位置

- 将所有节合并，保证程序正常运行

  1. 改节的个数为1

  2. 删去多余节表，并调整剩下这个节的`VirtualSize`和`SizeOfRawData`为：

     `Max = SizeOfRawData>VirtualSize?SizeOfRawData:VirtualSize`

     `SizeOfRawData = VirtualSize = 最后一个节的VirtualAddress + Max - SizeOfHeaders内存对齐后的大小`

     其实就是所有节对齐后的大小，就是`SizeOfImage - SizeOfHeaders`，值应该是一样的

  3. 改这一个节的属性为全部属性`E0000060`

- 定义一个函数，能够返回对齐后的大小`Align(int x,int y)`，`y`是对齐大小

  ```c
  int Align(int x, int y)
  {
      int i;
      if (x <= y) 
      {
          return y;
      }
      
      for (i = 1; i <= x / y; i++) 
      {
          if (x - y * (i - 1) > 0 && x - y * i <= 0) 
          {
              return y * i;
          }
      }
  
      return y * i;
  }
  ```

- 编程输出全部目录项（16个）

  ```c
  DWORD PrintDriectory(LPVOID pImageBuffer){
  	
  	//定义PE头的信息
  	PIMAGE_DOS_HEADER pDosHeader = NULL;
  	PIMAGE_NT_HEADERS pNTHeader = NULL;
  	PIMAGE_FILE_HEADER pPEHeader = NULL;
  	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
  	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
  	
  	if(!pImageBuffer)
  	{
  		printf("error");
  		return 0;
  	}
  	//判断是不是exe文件
  	if(*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
  	{
  		printf("error");
  		return 0;
  	}
  	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
  	if(*((PDWORD)((BYTE *)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
  		printf("error");
  		return 0;
  	}
  	
  	//读取pFileBuffer 获取DOS头，PE头，节表等信息
  	pDosHeader =(PIMAGE_DOS_HEADER)pImageBuffer;
  	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
  	//打印NT头	
  	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  //加4个字节到了标准PE头
  	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER); //标准PE头+标准PE头的大小 20
  	
  	printf("===导出表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[0].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[0].Size);
  
  	printf("===导入表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[1].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[1].Size);
  	
  	printf("===资源表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[2].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[2].Size);
  	
  	printf("===异常信息表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[3].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[3].Size);
  	
  	printf("===安全证书表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[4].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[4].Size);
  	
  	printf("===重定位表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[5].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[5].Size);	
  
  	printf("===调试信息表证书表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[6].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[6].Size);
  	
  	printf("===版权所有表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[7].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[7].Size);
  
  	printf("===全局指针表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[8].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[8].Size);
  
  	printf("===TLS表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[9].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[9].Size);
  
  	printf("===加载配置表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[10].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[10].Size);
  
  	printf("===绑定导入表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[11].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[11].Size);
  
  	printf("====IAT表===\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[12].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[12].Size);
  
  	printf("====延迟导入===\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[13].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[13].Size);
  
  	printf("====COM===\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[14].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[14].Size);
  	
  	printf("====保留===\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[15].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[15].Size);
  
  	return 1;
  }
  ```
  

#### 静态链接库-动态链接库

- 创建一个静态链接库，并在代码中使用

  完成，注意名称相同

- 创建一个动态链接库，使用两种方式进行导出(`_declspec(dllexport)`与`.def`文件)

  完成

- 分别使用隐式链接和显示链接使用一个`DLL`文件

  完成，注意显示链接要包含`windows.h`头文件

#### 导出表

- 编写程序打印所有的导出表信息

  ```c
  DWORD PrintExport(LPVOID pFileBuffer){
  	
  	//定义PE头的信息
  	PIMAGE_DOS_HEADER pDosHeader = NULL;
  	PIMAGE_NT_HEADERS pNTHeader = NULL;
  	PIMAGE_FILE_HEADER pPEHeader = NULL;
  	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
  	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
  	
  	if(!pFileBuffer)
  	{
  		printf("error");
  		return 0;
  	}
  	//判断是不是exe文件
  	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
  	{
  		printf("error");
  		return 0;
  	}
  	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
  	if(*((PDWORD)((BYTE *)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
  		printf("error");
  		return 0;
  	}
  	
  	//读取pFileBuffer 获取DOS头，PE头，节表等信息
  	pDosHeader =(PIMAGE_DOS_HEADER)pFileBuffer;
  	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
  	//打印NT头	
  	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  //加4个字节到了标准PE头
  	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER); //标准PE头+标准PE头的大小 20
  	
  	printf("===导出表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[0].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[0].Size);
  
  	printf("===结构===\n");
      PIMAGE_EXPORT_DIRECTORY Export_Directory = (PIMAGE_EXPORT_DIRECTORY)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress));
  	
  	printf("Name:%s\n",(char*)pFileBuffer + RvaToFileOffset(pFileBuffer,Export_Directory->Name));
  	printf("Base:%x\n",Export_Directory->Base);
  	printf("NumberOfFunctions:%x\n",Export_Directory->NumberOfFunctions);
  	printf("NumberOfNames:%x\n",Export_Directory->NumberOfNames);
  	printf("AddressOfFunctions: %x\n", Export_Directory-> AddressOfFunctions);
  	printf("AddressOfNames;: %x\n", Export_Directory-> AddressOfNames);
  	printf("AddressOfNameOrdinals;: %x\n\n", Export_Directory-> AddressOfNameOrdinals);
  	return 1;
  }
  ```
  
- `GetFunctionAddrByName`(`FileBuffer`指针，函数名指针)

  ```c
  DWORD GetFunctionAddrByName(PVOID pFileBuffer,char* FuncName){
      PIMAGE_DOS_HEADER pDosHeader = NULL;
      PIMAGE_NT_HEADERS pNTHeader = NULL;
      PIMAGE_FILE_HEADER pPEHeader = NULL;
      PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
      PIMAGE_SECTION_HEADER pSectionHeader = NULL;
      if(!pFileBuffer)
      {
          printf("error");
          return 0;
      }
      
      if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE)
      {
          printf("error");
          return 0;
      }
      
      pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
      if(*((PWORD)((BYTE *)pFileBUffer+pDosHesder->e_lfanew)) !=IMAGE_NT_SIGNATURE){
          printf("error");
          return 0;
      }
      pDosHeader = (PIMAGE_DOS_HEADER)pFileBUffer;
      pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBUffer + pDosHeader->e_lfanew);
      pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
      PIMAGE_EXPORT_DIRECTORY Export_Directory = (PIMAGE_EXPORT_DIRECTORY)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress));
      DWORD* AddressOfNamesFunctionsAddress = (DWORD*)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,Export_Directory->AddressOfNames));
  	
  	WORD* AddressOfNameOrdinalsAddress =(WORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer,Export_Directory->AddressOfNameOrdinals));
  	
  	DWORD* AddressOfFunctionsAddress = (DWORD*)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,Export_Directory->AddressOfFunctions));
  	
  	for(int x =0;x<Export_Directory->NumberOfNames;x++,AddressOfNamesFunctionsAddress++)
  	{
  		if (*FuncName == *((char*)pFileBuffer+RvaToFileOffset(pFileBuffer,*AddressOfNamesFunctionsAddress)))
  		{
  			printf("函数地址:%x\n",AddressOfFunctionsAddress[AddressOfNameOrdinalsAddress[x]]);
  		}
  }
  ```

- `GetFunctionAddrByOrdinals`(`FileBuffer`指针，函数名导出序号)

  ```c
  DWORD GetFunctionAddrByOrdinals(LPVOID pFileBuffer,DWORD FunctionOrdinals){
  
  	PIMAGE_DOS_HEADER pDosHeader = NULL;
  	PIMAGE_NT_HEADERS pNTHeader = NULL;
  	PIMAGE_FILE_HEADER pPEHeader = NULL;
  	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
  	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
  	
  	if(!pFileBuffer)
  	{
  		printf("error");
  		return 0;
  	}
  	//判断是不是exe文件
  	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
  	{
  		printf("error");
  		return 0;
  	}
  	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
  	if(*((PDWORD)((BYTE *)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
  		printf("error");
  		return 0;
  	}
  	
  	//读取pFileBuffer 获取DOS头，PE头，节表等信息
  	pDosHeader =(PIMAGE_DOS_HEADER)pFileBuffer;
  	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
  	//打印NT头	
  	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);  //加4个字节到了标准PE头
  	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER); //标准PE头+标准PE头的大小 20
  	//
  	PIMAGE_EXPORT_DIRECTORY Export_Directory = (PIMAGE_EXPORT_DIRECTORY)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,pOptionHeader->DataDirectory[0].VirtualAddress));
  	
  	DWORD* AddressOfNamesFunctionsAddress = (DWORD*)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,Export_Directory->AddressOfNames));
  	
  	printf("函数地址为：%x\n",AddressOfNamesFunctionsAddress[FunctionOrdinals-Export_Directory->Base]);
  
  }
  ```

#### 重定位表

- 打印所有重定位信息

  ```c
  DWORD PrintRelocation(LPVOID pFileBuffer){
  	
  	PIMAGE_DOS_HEADER pDosHeader = NULL;
  	PIMAGE_NT_HEADERS pNTHeader = NULL;
  	PIMAGE_FILE_HEADER pPEHeader = NULL;
  	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
  	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
  	
  	if(!pFileBuffer)
  	{
  		printf("读取到内存的pfilebuffer无效！\n");
  		return 0;
  	}
  	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
  	{
  		printf("不含MZ标志，不是exe文件！\n");
  		return 0;
  	}
  	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
  	if(*((PDWORD)((BYTE *)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE){
  		printf("无有效的PE标志\n");
  		return 0;
  	}
  	pDosHeader =(PIMAGE_DOS_HEADER)pFileBuffer;
  	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
  	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
  	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER); 
      
  	if(pOptionHeader->DataDirectory[5].VirtualAddress == 0){
  		printf("%s","不存在重定位表...");
  		return 0;
  	}
  	
      printf("========1=========\n");
      PIMAGE_BASE_RELOCATION ReloCation = (_IAMGE_BASE_RELOCATION*)((char*)pFileBuffer + RvaToFileOffset(pFileBuffer,pOptionHeader->DataDirectory[5].VirtualAddress));
  	printf("===重定位表====\n");
  	printf("内存地址%x\n",pOptionHeader->DataDirectory[5].VirtualAddress);
  	printf("内存大小%x\n",pOptionHeader->DataDirectory[5].Size);
  
  
  	int cnt = 0;
      while (true) {
            
  		if (ReloCation->VirtualAddress != 0 && ReloCation->SizeOfBlock !=0)
  		{
  			printf("**********************************\n");
  			printf("%x\n",ReloCation);
  			int num = (ReloCation->SizeOfBlock - 8) / 2;
  			for (int i =0;i<num-1;i++) 
  			{
  				
  			     WORD* offset = (WORD*)((char*)ReloCation+8+2*i);
  				if (*offset >= 0x3000)
  				{
  
  					   printf("第%x项\t地址:%X\t偏移:%X\n", ReloCation->VirtualAddress, *offset-0x3000);
  				}
  			}
  			ReloCation = (_IMAGE_BASE_RELOCATION*)((char*)ReloCation + ReloCation->SizeOfBlock);
  			  cnt++;
  		}else{
  			break;
  		}
      }
      printf("%d\n", cnt);
  
  }
  ```

- 重定位表这样设计有什么好处？

  用最少的空间来记录要修改的地址

#### 移动导出表-重定位表

- 在`DLL`新增一个节，并将导出表信息移动到这个新的节中
- 使用工具打开修改后的`DLL`看能否正常解析
- 在`DLL`中新增一个节，并将重定位表移动到这个新的节中
- 修改`DLL`的`ImageBase`,根据重定位表修正，然后存盘。看`DLL`是否可以使用

#### 导入表

- 打印`notepad.exe`导入表的全部信息

  

### Win32

#### 宽字符

- 分别使用`wchar_t / wprintf / wcslen / wcscpy / wcscat / wcscmp / wcsstr`写一个例子

  ```c++
  #include <windows.h>
  #include "main.h"
  #include <locale.h>
  #include <stdio.h>
  #include <stdlib.h>
  
  int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,LPSTR lpCmdLine, int nCmdShow) {
  	setlocale(LC_ALL,"");
  	wchar_t str1[] = L"你好";
  	wchar_t str2[] = L"世界";
  	wprintf(L"打印：%ls,%ls\n",str1,str2);
  	int Len = wcslen(str1);
  	printf("%d\n",Len);
  	wcscpy(str1,str2);
  	wprintf(L"打印：%ls,%ls\n",str1,str2);
  	wcscat(str1,str1);
  	wprintf(L"打印：%ls,%ls\n",str1,str2);
  	int dif = wcscmp(str1,str2);
  	printf("%d\n",dif);
  	wchar_t* search = wcsstr(str1,L"世");
  	wprintf(L"%ls\n",search);
  	return 0;
  }
  ```

- 查`MSDN`了解`WinMain`其他`3`个参数的意义

  ```c++
  int WINAPI WinMain(
    HINSTANCE hInstance,      // 应用程序当前实例的句柄
    HINSTANCE hPrevInstance,  // 应用程序先前实例的句柄 (现在通常为NULL)
    LPSTR     lpCmdLine,      // 指向应用程序命令行字符串的指针 (就是命令行参数)
    int       nCmdShow        // 指定窗口应如何显示 (是否被最小化，最大化或正常显示)
  );
  ```

#### 事件-消息

- 创建一个窗口程序，学习如何查询文档

  ```c++
  #include <stdlib.h>
  #include <stdio.h>
  #include <Windows.h>
  
  HINSTANCE hAppInstance;
  
  LRESULT CALLBACK WindowProc(  
  	IN  HWND hwnd,  
  	IN  UINT uMsg,  
  	IN  WPARAM wParam,  
  	IN  LPARAM lParam  
  	);  
  
  
  int APIENTRY WinMain(HINSTANCE hInstance,
                       HINSTANCE hPrevInstance,
                       LPSTR     lpCmdLine,
                       int       nCmdShow)
  {
   	// TODO: Place code here.
  	hAppInstance = hInstance;
  	
  	//窗口的类名
  	PSTR className = "My First Window"; 
  	
  	// 创建窗口类的对象 
  	WNDCLASS wndclass = {0};						//一定要先将所有值赋值
  	wndclass.hbrBackground = (HBRUSH)COLOR_MENU;	//窗口的背景色
  	wndclass.hCursor = LoadCursor(NULL,IDC_APPSTARTING);	
  	wndclass.lpfnWndProc = WindowProc;				//窗口过程函数
  	wndclass.lpszClassName = className;				//窗口类的名字	
  	wndclass.hInstance = hInstance;					//定义窗口类的应用程序的实例句柄
  
  	
  	// 注册窗口类  
  	// 参加MSDN文档RegisterClass->Parameters：
  	// You must fill the structure with the appropriate class attributes 
  	// before passing it to the function. 
  	RegisterClass(&wndclass);  
  	
  	// 创建窗口  
  	HWND hwnd = CreateWindow(  
  		className,				//类名
  		"我的第一个窗口",		//窗口标题
  		WS_OVERLAPPEDWINDOW,	//窗口外观样式  
  		10,						//相对于父窗口的X坐标
  		10,						//相对于父窗口的Y坐标
  		600,					//窗口的宽度  
  		300,					//窗口的高度  
  		NULL,					//父窗口句柄，为NULL  
  		NULL,					//菜单句柄，为NULL  
  		hInstance,				//当前应用程序的句柄  
  		NULL);					//附加数据一般为NULL
  	
  	if(hwnd == NULL)			//是否创建成功  
  		return 0;  
  	
  	// 显示窗口  
  	ShowWindow(hwnd, SW_SHOW);  
  	
  	// 更新窗口  
  	UpdateWindow(hwnd);  
  	
  	// 消息循环  
  	MSG msg;  
  	while(GetMessage(&msg, NULL, 0, 0))  
  	{  
  		TranslateMessage(&msg);  
  		DispatchMessage(&msg);  
  	}  
  	
  	return 0;  
  }
  
  
  LRESULT CALLBACK WindowProc(  
  	IN  HWND hwnd,  
  	IN  UINT uMsg,  
  	IN  WPARAM wParam,  
  	IN  LPARAM lParam  
  	)  
  {  
  	switch(uMsg)
  	{
  		//窗口消息
  		case WM_CREATE: 
  			{
  				printf("WM_CREATE %d %d\n",wParam,lParam);
  				CREATESTRUCT* createst = (CREATESTRUCT*)lParam;
  				printf("CREATESTRUCT %s\n",createst->lpszClass);
  				break;
  			}
  		case WM_MOVE:
  			{
  				printf("WM_MOVE %d %d\n",wParam,lParam);
  				POINTS points = MAKEPOINTS(lParam);
  				printf("X Y %d %d\n",points.x,points.y);
  				break;
  			}
  		case WM_SIZE:
  			{
  				printf("WM_SIZE %d %d\n",wParam,lParam);
  				int newWidth  = (int)(short) LOWORD(lParam);    
  				int newHeight  = (int)(short) HIWORD(lParam);   
  				printf("WM_SIZE %d %d\n",newWidth,newHeight);
  				break;
  			}
  		case WM_DESTROY:
  			{
  				printf("WM_DESTROY %d %d\n",wParam,lParam);
  				PostQuitMessage(0);
  				return 0;
  				break;
  			}
  		//键盘消息
  		case WM_KEYUP:
  			{
  				printf("WM_KEYUP %d %d\n",wParam,lParam);
  				break;
  			}
  		case WM_KEYDOWN:
  			{
  				printf("WM_KEYDOWN %d %d\n",wParam,lParam);
  				break;
  			}
  		//鼠标消息
  		case WM_LBUTTONDOWN:
  			{
  				printf("WM_LBUTTONDOWN %d %d\n",wParam,lParam);
  				POINTS points = MAKEPOINTS(lParam);
  				printf("WM_LBUTTONDOWN %d %d\n",points.x,points.y);
  				break;
  			}
  		default:  
  			return DefWindowProc(hwnd,uMsg,wParam,lParam);
  	}
  	return 0;  
  }  
  
  ```

- 查一下`Windows`有多少种消息，概要了解一下每个消息的作用

- `WNDCLASS wndclass = {0};`与`WNDCLASS wndclass;`的区别是什么

  要对里面的成员全面初始化

#### esp寻址-定位回调函数

- 找到那三个字母

  ```asm
  .text:00401124                 cmp     eax, 41h ; 'A'
  .text:00401127                 jz      short loc_401172
  .text:00401129                 cmp     eax, 46h ; 'F'
  .text:0040112C                 jz      short loc_401161
  .text:0040112E                 cmp     eax, 67h ; 'g'
  .text:00401131                 jz      short loc_401150
  ```

  根据`WndClass`里面的回调函数可以找到这个比较。不过这个`67h`好像是小键盘的`7`。

#### 子窗口-消息处理函数

- 找到按钮另外的操作

  ```asm
  .text:0040111A                 cmp     eax, 3E9h
  .text:0040111F                 jnz     short loc_401144
  .text:00401121                 push    0               ; uType
  .text:00401123                 push    offset Caption  ; "Demo"
  .text:00401128                 push    offset Text     ; "Find Me 1"
  .text:0040112D                 push    0               ; hWnd
  .text:0040112F                 mov     dword_408514, 1
  .text:00401139                 call    ds:MessageBoxA
  .text:0040113F                 xor     eax, eax
  .text:00401141                 retn    10h
  .text:00401144 ; ---------------------------------------------------------------------------
  .text:00401144
  .text:00401144 loc_401144:                             ; CODE XREF: sub_401100+1F↑j
  .text:00401144                 cmp     eax, 3EAh
  .text:00401149                 jnz     short loc_40116E
  .text:0040114B                 push    0               ; uType
  .text:0040114D                 push    offset Caption  ; "Demo"
  .text:00401152                 push    offset aFindMe2 ; "Find Me 2"
  .text:00401157                 push    0               ; hWnd
  .text:00401159                 mov     dword_408514, 2
  .text:00401163                 call    ds:MessageBoxA
  .text:00401169                 xor     eax, eax
  .text:0040116B                 retn    10h
  .text:0040116E ; ---------------------------------------------------------------------------
  .text:0040116E
  .text:0040116E loc_40116E:                             ; CODE XREF: sub_401100+49↑j
  .text:0040116E                 cmp     eax, 3EBh
  .text:00401173                 jnz     short loc_401198
  .text:00401175                 push    0               ; uType
  .text:00401177                 push    offset Caption  ; "Demo"
  .text:0040117C                 push    offset aFindMe3 ; "Find Me 3"
  .text:00401181                 push    0               ; hWnd
  .text:00401183                 mov     dword_408514, 3
  .text:0040118D                 call    ds:MessageBoxA
  .text:00401193                 xor     eax, eax
  .text:00401195                 retn    10h
  ```

  应该是向地址`0x408514`分别赋值`1，2，3`

  通过反汇编其实可以看到，因为这三个按钮是属于这个窗口类的所以这些按钮的回调函数也会在窗口的`WndProc`下。点击按钮的消息与点击窗口的消息会分开，似乎是因为`if…else…`隔开了。

#### 资源文件-消息断点

- 找回调1

  ```asm
  00401060   > \8B4C24 08     MOV ECX,DWORD PTR SS:[ESP+8]             ;  Case 3EA of switch 0040104D
  00401064   .  6A 00         PUSH 0                                   ; /Style = MB_OK|MB_APPLMODAL
  00401066   .  68 60604000   PUSH ReverseT.00406060                   ; |Title = "Demo"
  0040106B   .  68 48604000   PUSH ReverseT.00406048                   ; |Text = "Button 3"
  00401070   .  51            PUSH ECX                                 ; |hOwner
  00401071   .  FF15 A0504000 CALL NEAR DWORD PTR DS:[4050A0]          ; \MessageBoxA
  00401077   .  8BC6          MOV EAX,ESI
  00401079   .  5E            POP ESI
  0040107A   .  C2 1000       RETN 10
  0040107D   >  8B5424 08     MOV EDX,DWORD PTR SS:[ESP+8]             ;  Case 3E9 of switch 0040104D
  00401081   .  6A 00         PUSH 0                                   ; /Style = MB_OK|MB_APPLMODAL
  00401083   .  68 60604000   PUSH ReverseT.00406060                   ; |Title = "Demo"
  00401088   .  68 3C604000   PUSH ReverseT.0040603C                   ; |Text = "Button 2"
  0040108D   .  52            PUSH EDX                                 ; |hOwner
  0040108E   .  FF15 A0504000 CALL NEAR DWORD PTR DS:[4050A0]          ; \MessageBoxA
  00401094   .  8BC6          MOV EAX,ESI
  00401096   .  5E            POP ESI
  00401097   .  C2 1000       RETN 10
  0040109A   >  8B4424 08     MOV EAX,DWORD PTR SS:[ESP+8]             ;  Case 3E8 of switch 0040104D
  0040109E   .  6A 00         PUSH 0                                   ; /Style = MB_OK|MB_APPLMODAL
  004010A0   .  68 60604000   PUSH ReverseT.00406060                   ; |Title = "Demo"
  004010A5   .  68 30604000   PUSH ReverseT.00406030                   ; |Text = "Button 1"
  004010AA   .  50            PUSH EAX                                 ; |hOwner
  004010AB   .  FF15 A0504000 CALL NEAR DWORD PTR DS:[4050A0]          ; \MessageBoxA
  ```

- 找密码

  首先是调了一个函数判断`EAX`，后面就是是否输入正确进行跳转：

  ```asm
  004010D3   .  E8 28FFFFFF   CALL ReverseT.00401000
  004010D8   .  83C4 04       ADD ESP,4
  004010DB   .  85C0          TEST EAX,EAX
  004010DD   .  6A 00         PUSH 0                                   ; /Style = MB_OK|MB_APPLMODAL
  004010DF   .  74 18         JE SHORT ReverseT.004010F9               ; |
  ```

  后面的比较的位置应该是下面的代码：

  ```asm
  0040105C  |.  8D7C24 0C     LEA EDI,DWORD PTR SS:[ESP+C]
  00401060  |.  83C9 FF       OR ECX,FFFFFFFF
  00401063  |.  33C0          XOR EAX,EAX
  00401065  |.  F2:AE         REPNE SCAS BYTE PTR ES:[EDI]
  00401067  |.  F7D1          NOT ECX
  00401069  |.  49            DEC ECX
  0040106A  |.  83F9 03       CMP ECX,3
  0040106D  |.  75 20         JNZ SHORT ReverseT.0040108F
  0040106F  |.  8D7C24 5C     LEA EDI,DWORD PTR SS:[ESP+5C]
  00401073  |.  83C9 FF       OR ECX,FFFFFFFF
  00401076  |.  F2:AE         REPNE SCAS BYTE PTR ES:[EDI]
  00401078  |.  F7D1          NOT ECX
  0040107A  |.  49            DEC ECX
  0040107B  |.  83F9 05       CMP ECX,5
  0040107E  |.  75 0F         JNZ SHORT ReverseT.0040108F
  ```

  因为前面是两个`GetWindowTextA`函数，所以有理由说明上面的获取我输入的内容，后面进行比较。

#### 资源表（PE）

- 编写程序，定位某个资源在`PE`文件中的位置
- 编写程序，提供程序图标资源
- 编写程序，修改对话框标题

#### 项目

- 界面实现：

  ```c++
  // project.cpp : Defines the entry point for the application.
  //
  
  #include "stdafx.h"
  #include "resource.h"
  #include <CommCtrl.h>
  #pragma comment(lib,"comctl32.lib")
  
  VOID EnumMoudles(HWND hListProcess, WPARAM wParam, LPARAM lParam) {
  	DWORD dwRowId;
  	TCHAR szPid[21];
  	LV_ITEM lv;
  
  	//初始化
  	memset(&lv, 0, sizeof(LV_ITEM));
  	
  	//获取选择行
  	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM,-1 , LVNI_SELECTED);
  	if (dwRowId == -1) {
  		MessageBox(NULL, TEXT("请选择进程"), TEXT("出错啦"), MB_OK);
  		return;
  	}
  
  	//获取PID
  	lv.iSubItem = 1;
  	lv.pszText = szPid;
  	lv.cchTextMax = 0x20;
  	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);
  
  	MessageBox(NULL, szPid, TEXT("PID"), MB_OK);
  }
  
  VOID InitMoudleListView(HWND hDlg) {
  	//设置窗口风格需要调用结构体
  	LV_COLUMN lv;
  	HWND hListMoudles;
  
  	//初始化
  	memset(&lv, 0, sizeof(LV_COLUMN));
  	//获取模块列表句柄
  	hListMoudles = GetDlgItem(hDlg, IDC_LIST_Down);
  	//设置整行选中
  	SendMessage(hListMoudles, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
  
  	//第一列：
  	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  	lv.pszText = TEXT("模块名称");
  	lv.cx = 330;
  	lv.iSubItem = 0;
  	//ListView_Insertcolumn(hListMoudles,0,&lv);
  	SendMessage(hListMoudles, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
  
  	//第二列：
  	lv.pszText = TEXT("模块位置");
  	lv.cx = 330;
  	lv.iSubItem = 1;
  	SendMessage(hListMoudles, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
  }
  
  VOID EnumProcess(HWND hListProcess) {
  	LV_ITEM vitem;
  
  	//初始化，第一个进程
  	memset(&vitem, 0, sizeof(LV_ITEM));
  	vitem.mask = LVIF_TEXT;
  
  	//假数据：
  	vitem.pszText = TEXT("csrss.exe");
  	vitem.iItem = 0;
  	vitem.iSubItem = 0;
  	//ListView_Insertem(hListProcess,*vitem);
  	SendMessage(hListProcess, LVM_INSERTITEM, 0, (DWORD)&vitem);
  
  	vitem.pszText = TEXT("448");
  	vitem.iItem = 0;
  	vitem.iSubItem = 1;
  	SendMessage(hListProcess, LVM_SETITEM, 0, (DWORD)&vitem);
  	//ListView_SetItem(hListProcess, &vitem);
  
  	vitem.pszText = TEXT("56590000");
  	vitem.iItem = 0;
  	vitem.iSubItem = 2;
  	ListView_SetItem(hListProcess, &vitem);
  
  	vitem.pszText = TEXT("000F0000");
  	vitem.iItem = 0;
  	vitem.iSubItem = 3;
  	ListView_SetItem(hListProcess, &vitem);
  
  
  	//第二个进程假数据：
  	vitem.pszText = TEXT("QQ.exe");
  	vitem.iItem = 1;
  	vitem.iSubItem = 0;
  	SendMessage(hListProcess, LVM_INSERTITEM, 0, (DWORD)&vitem);
  
  	vitem.pszText = TEXT("153");
  	vitem.iItem = 1;
  	vitem.iSubItem = 1;
  	ListView_SetItem(hListProcess, &vitem);
  
  	vitem.pszText = TEXT("65580000");
  	vitem.iItem = 1;
  	vitem.iSubItem = 2;
  	ListView_SetItem(hListProcess, &vitem);
  
  	vitem.pszText = TEXT("001E0000");
  	vitem.iItem = 1;
  	vitem.iSubItem = 3;
  	ListView_SetItem(hListProcess, &vitem);
  
  	//第三个进程假数据：
  	vitem.pszText = TEXT("WeChat.exe");
  	vitem.iItem = 2;
  	vitem.iSubItem = 0;
  	SendMessage(hListProcess, LVM_INSERTITEM, 0, (DWORD)&vitem);
  
  	vitem.pszText = TEXT("256");
  	vitem.iItem = 2;
  	vitem.iSubItem = 1;
  	ListView_SetItem(hListProcess, &vitem);
  
  	vitem.pszText = TEXT("75960000");
  	vitem.iItem = 2;
  	vitem.iSubItem = 2;
  	ListView_SetItem(hListProcess, &vitem);
  
  	vitem.pszText = TEXT("015B0000");
  	vitem.iItem = 2;
  	vitem.iSubItem = 3;
  	ListView_SetItem(hListProcess, &vitem);
  }
  
  VOID InitProcessListView(HWND hDlg) {
  	//设置窗口风格调用结构体
  	LV_COLUMN lv;
  	HWND hListProcess;
  
  	//初始化
  	memset(&lv, 0, sizeof(LV_COLUMN));
  	//获取进程列表句柄
  	hListProcess = GetDlgItem(hDlg, IDC_LIST_Process);
  	//设置整行选中
  	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
  	//出错代码：：：：：
  	//SendMessage(hListProcess, LVM_GETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
  	
  	//第一列：
  	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
  	lv.pszText = TEXT("进程");           //列标题
  	lv.cx = 225;             //行宽
  	lv.iSubItem = 0;
  	//ListView_InsertColumn(hListProcess,0,&lv);
  	SendMessage(hListProcess, LVM_INSERTCOLUMN, 0, (DWORD)&lv);
  	
  	//第二列
  	lv.pszText = TEXT("PID");
  	lv.cx = 150;
  	lv.iSubItem = 1;
  	//ListView_InsertColumn(hListProcess, 1, &lv);
  	SendMessage(hListProcess, LVM_INSERTCOLUMN, 1, (DWORD)&lv);
  
  	//第三列
  	lv.pszText = TEXT("镜像基址");
  	lv.cx = 134;
  	lv.iSubItem = 2;
  	//ListView_InsertColumn(hListProcess, 2, &lv);
  	SendMessage(hListProcess, LVM_INSERTCOLUMN, 2, (DWORD)&lv);
  
  	//第四列
  	lv.pszText = TEXT("镜像大小");
  	lv.cx = 150;
  	lv.iSubItem = 3;
  	//ListView_InsertColumn(hListProcess, 3, &lv);
  	SendMessage(hListProcess, LVM_INSERTCOLUMN, 3, (DWORD)&lv);
  	EnumProcess(hListProcess);
  }
  
  BOOL CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
  	BOOL nRet = FALSE;
  
  	switch (uMsg) {
  		case WM_CLOSE: {
  			EndDialog(hDlg, 0);
  			PostQuitMessage(0);
  			break;
  		}
  		case WM_INITDIALOG: {
  			InitProcessListView(hDlg);         //设置ProcessListView的风格，初始化进程列表
  			InitMoudleListView(hDlg);          //设置MoudleListView的风格，初始化模块列表
  			break;
  		}
  		case WM_COMMAND: {
  			switch (LOWORD(wParam)) {
  				case IDC_BUTTON_protect: {
  					//DialogBox(hIns, MAKEINTRESOURCE(IDD_ABOUTBOX), NULL, NULL);
  				}
  				case IDC_BUTTON_PE: {
  					//打开新的对话框，PE查看器
  
  					return 0;
  				}
  				case IDC_BUTTON_logout: {
  					EndDialog(hDlg, 0);
  					PostQuitMessage(0);
  					return TRUE;
  				}
  			}
  		}
  		case WM_NOTIFY: {
  			NMHDR* pNMHDR = (NMHDR*)lParam;
  			if (wParam == IDC_LIST_Down && pNMHDR->code == NM_CLICK) {
  				EnumMoudles(GetDlgItem(hDlg, IDC_LIST_Down), wParam, lParam);
  			}
  			break;
  		}
  	}
  	return nRet;
  }
  
  int APIENTRY WinMain(HINSTANCE hInstance,
                       HINSTANCE hPrevInstance,
                       LPSTR     lpCmdLine,
                       int       nCmdShow)
  {
   	// TODO: Place code here.
  	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, (DLGPROC)MainDlgProc);
  	return 0;
  }
  ```

#### 创建线程

- 一个加一个减

  ```c++
  // qqqq.cpp : Defines the entry point for the application.
  //
  
  #include "stdafx.h"
  #include "resource.h"
  #include <windows.h>
  #include <stdio.h>
  #include <stdlib.h>
  
  HWND sub;
  HWND plus;
  
  DWORD WINAPI doSub(LPVOID lpParameter){
      //获取文本框内容
      TCHAR szBuffer[10];
      memset(szBuffer, 0, 10);
      GetWindowText(sub, szBuffer, 10);
      //字符转数字
      DWORD time;
      sscanf(szBuffer, "%d", &time);
      //计算并写回文本
      while(time > 0){
          memset(szBuffer, 0, 10);
          Sleep(1000);
          sprintf(szBuffer,"%d", --time);
          SetWindowText(sub,szBuffer);
      }
      return 0;
  }
  
  DWORD WINAPI doPlus(LPVOID lpParameter){
      //获取文本框内容
      TCHAR szBuffer[10];
      memset(szBuffer, 0, 10);
      GetWindowText(plus, szBuffer, 10);
      //字符转数字
      DWORD time;
      sscanf(szBuffer, "%d", &time);
      //计算并写回文本
      while(time < 1000){
          memset(szBuffer, 0, 10);
          Sleep(1000);
          sprintf(szBuffer,"%d", ++time);
          SetWindowText(plus,szBuffer);
      }
      return 0;
  }
  
  BOOL CALLBACK DialogProc(                                    
                           HWND hwndDlg,  // handle to dialog box            
                           UINT uMsg,     // message            
                           WPARAM wParam, // first message parameter            
                           LPARAM lParam  // second message parameter            
                           )            
  {    
      switch(uMsg)                                
      {    
      case WM_INITDIALOG :
          {
              //初始化文本框
              sub = GetDlgItem(hwndDlg,IDC_EDIT_SUB);
              SetWindowText(sub,TEXT("1000"));
              plus = GetDlgItem(hwndDlg, IDC_EDIT_ADD);
              SetWindowText(plus,TEXT("0"));
          }
          return TRUE;     
                                      
      case  WM_COMMAND :                                
          switch (LOWORD (wParam))                            
          {
          case IDC_BUTTON_START:  
              HANDLE hThread = ::CreateThread(NULL, 0, doSub, NULL, 0, NULL);        
              //如果不在其他的地方引用它 关闭句柄                
              ::CloseHandle(hThread);
   
              HANDLE hThread2 = ::CreateThread(NULL, 0, doPlus, NULL, 0, NULL);                     
              ::CloseHandle(hThread2);
              return TRUE;                       
          }                            
          break;   
          
      case WM_CLOSE:
          EndDialog(hwndDlg, 0);
          return TRUE;
      }    
                                      
      return FALSE;                                
  }    
  
  int APIENTRY WinMain(HINSTANCE hInstance,
                       HINSTANCE hPrevInstance,
                       LPSTR     lpCmdLine,
                       int       nCmdShow)
  {
   	// TODO: Place code here.
  	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DialogProc);
  	return 0;
  }
  ```


#### 线程控制

- 值为什么不准确？

  通俗易懂的解释：

  假设有一个公共的白板，上面写着一个数字，比如 “`0`”。  现在有两个小朋友，小明和小红，他们都想轮流在这个白板上把数字加 1，并且每个人都要加 `10000` 次。  我们希望最终白板上的数字是 `20000`。

  1. **小明想加 `1`：** 小明走到白板前，看到上面写着 “`0`”，心里记住了 “现在是 `0`”。
  2. **小红也想加 `1`：**  几乎同时，小红也走到白板前，也看到了上面写着 “`0`”，她也记住了 “现在是 `0`”。
  3. **小明写下新数字：** 小明心算了一下 `0 + 1 = 1`，然后拿起笔，把白板上的 “`0`” 擦掉，写上了 “`1`”。
  4. **小红也写下新数字：** 小红也心算了一下 `0 + 1 = 1` （注意，她看到的是之前的 "`0`"，而不是小明刚写的 "`1`"），然后她也拿起笔，把白板上的 "`0`" （如果还没被擦掉）或者 "`1`" （如果已经被小明写上了，但是小红没注意到）擦掉，也写上了 "`1`"。

  **结果：**  本来我们希望小明和小红都加一次 `1`，白板上应该变成 "`2`"，但是由于他们几乎同时操作，并且没有“协调好”，结果白板上最终只显示了 "`1`"。 有一次加 `1` 的操作 “丢失” 了！

#### 临界区

- 通过使用临界区实现一个死锁程序

  ```c++
  #include <windows.h>
  #include <stdio.h>
  CRITICAL_SECTION cs1;
  CRITICAL_SECTION cs2;
  
  DWORD WINAPI ThreadProc1(LPVOID lpParameter)
  {
      printf("1\n");
      EnterCriticalSection(&cs1);
      Sleep(10000);
      EnterCriticalSection(&cs2);
  
  
      LeaveCriticalSection(&cs2);
      LeaveCriticalSection(&cs1);
      printf("1 1\n");
  	return 0;
  }
  
  DWORD WINAPI ThreadProc2(LPVOID lpParameter)
  {
      printf("2\n");
      EnterCriticalSection(&cs2);
      Sleep(100);
      EnterCriticalSection(&cs1);
  
      LeaveCriticalSection(&cs1);
      LeaveCriticalSection(&cs2);
      printf("2 2\n");
  	return 0;
  }
  
  
  int main(int argc, char* argv[])
  {
  	InitializeCriticalSection(&cs1);
  	InitializeCriticalSection(&cs2);
  
  	//创建一个新的线程
  	HANDLE hThread1 = ::CreateThread(NULL, 0, ThreadProc1,NULL, 0, NULL);
  	//创建一个新的线程
  	HANDLE hThread2 = ::CreateThread(NULL, 0, ThreadProc2,NULL, 0, NULL);
  
  	Sleep(100);
  	//如果不在其他的地方引用它 关闭句柄
  	::CloseHandle(hThread1);
  	::CloseHandle(hThread2);
  
      DeleteCriticalSection(&cs1);
      DeleteCriticalSection(&cs2);
  	return 0;
  }
  ```
  
  会发现输出中没有`1 1`和`2 2`。

#### 互斥体

- 第一步：在第一个文本框中输入一个值，比如`1000`。
  第二步：点击抢红包，同时创建`3`个线程，每个线程循环进行抢红包的操作，每次抢`50`。
  第三步：使用`Mutex`进行线程控制，当第一个文本框中的值`<50`时，强红包线程结束。
  特别说明：
  1、四个文本框中的值总和应该为`1000`
  2、强红包线程每次延时`50`毫秒。
  3、使用`WaitForMultipleObjects`监听所有线程，当线程全部结束后调用`CloseHandle`关闭句柄。

  ```c++
  // test.cpp : Defines the entry point for the application.
  //
  
  #include "stdafx.h"
  #include "resource.h"
  #include <windows.h>
  #include <stdio.h>
  #include <stdlib.h>
  
  HWND main_hwnd;
  HWND hwnd_A;
  HWND hwnd_B;
  HWND hwnd_C;
  HANDLE g_hMutex;
  
  DWORD WINAPI startnew_thread1(LPVOID lpParameter);
  DWORD WINAPI startnew_thread2(LPVOID lpParameter);
  DWORD WINAPI startnew_thread3(LPVOID lpParameter);
  
  DWORD WINAPI startnew_thread1(LPVOID lpParameter) {
      TCHAR szBuffer[10];
      DWORD total_amount;
      DWORD thread_amount;
  
      while (TRUE) {
          WaitForSingleObject(g_hMutex, INFINITE);
  
          memset(szBuffer, 0, sizeof(szBuffer));
          GetWindowText(main_hwnd, szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0]));
          sscanf(szBuffer, "%d", &total_amount);
  
          if (total_amount < 50) {
              ReleaseMutex(g_hMutex);
              break;
          }
  
          sprintf(szBuffer, "%d", total_amount - 50);
          SetWindowText(main_hwnd, szBuffer);
  
          memset(szBuffer, 0, sizeof(szBuffer));
          GetWindowText(hwnd_A, szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0]));
          sscanf(szBuffer, "%d", &thread_amount);
  
          sprintf(szBuffer, "%d", thread_amount + 50);
          SetWindowText(hwnd_A, szBuffer);
  
          ReleaseMutex(g_hMutex);
  
          Sleep(50);
      }
      return 0;
  }
  
  
  DWORD WINAPI startnew_thread2(LPVOID lpParameter) {
      TCHAR szBuffer[10];
      DWORD total_amount;
      DWORD thread_amount;
  
      while (TRUE) {
          WaitForSingleObject(g_hMutex, INFINITE);
  
          memset(szBuffer, 0, sizeof(szBuffer));
          GetWindowText(main_hwnd, szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0]));
          sscanf(szBuffer, "%d", &total_amount);
  
          if (total_amount < 50) {
              ReleaseMutex(g_hMutex);
              break;
          }
  
          sprintf(szBuffer, "%d", total_amount - 50);
          SetWindowText(main_hwnd, szBuffer);
  
          memset(szBuffer, 0, sizeof(szBuffer));
          GetWindowText(hwnd_B, szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0])); 
          sscanf(szBuffer, "%d", &thread_amount);
  
          sprintf(szBuffer, "%d", thread_amount + 50);
          SetWindowText(hwnd_B, szBuffer);
  
          ReleaseMutex(g_hMutex);
          Sleep(50);
      }
      return 0;
  }
  
  
  DWORD WINAPI startnew_thread3(LPVOID lpParameter) {
      TCHAR szBuffer[10];
      DWORD total_amount;
      DWORD thread_amount;
  
      while (TRUE) {
          WaitForSingleObject(g_hMutex, INFINITE);
  
          memset(szBuffer, 0, sizeof(szBuffer));
          GetWindowText(main_hwnd, szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0]));
          sscanf(szBuffer, "%d", &total_amount);
  
          if (total_amount < 50) {
              ReleaseMutex(g_hMutex);
              break;
          }
  
          sprintf(szBuffer, "%d", total_amount - 50);
          SetWindowText(main_hwnd, szBuffer);
  
          memset(szBuffer, 0, sizeof(szBuffer));
          GetWindowText(hwnd_C, szBuffer, sizeof(szBuffer) / sizeof(szBuffer[0]));
          sscanf(szBuffer, "%d", &thread_amount);
  
          sprintf(szBuffer, "%d", thread_amount + 50);
          SetWindowText(hwnd_C, szBuffer);
  
          ReleaseMutex(g_hMutex);
          Sleep(50);
      }
      return 0;
  }
  
  
  DWORD WINAPI startnew(LPVOID lpParameter) {
      g_hMutex = CreateMutex(NULL, FALSE, "XYZ");
      if (g_hMutex == NULL) {
          MessageBox(NULL, TEXT("error"), TEXT("error"), MB_ICONERROR);
          return 1;
      }
  
      HANDLE hThread1 = ::CreateThread(NULL, 0, startnew_thread1, NULL, 0, NULL);
      HANDLE hThread2 = ::CreateThread(NULL, 0, startnew_thread2, NULL, 0, NULL);
      HANDLE hThread3 = ::CreateThread(NULL, 0, startnew_thread3, NULL, 0, NULL);
  
      HANDLE hThreads[3] = {hThread1, hThread2, hThread3};
  
      WaitForMultipleObjects(3, hThreads, TRUE, INFINITE);
  
      ::CloseHandle(hThread1);
      ::CloseHandle(hThread2);
      ::CloseHandle(hThread3);
  
      ::CloseHandle(g_hMutex);
      g_hMutex = NULL;
  
      return 0;
  }
  
  
  BOOL CALLBACK DialogProc(
      HWND hwndDlg,   // handle to dialog box
      UINT uMsg,      // message
      WPARAM wParam,  // first message parameter
      LPARAM lParam   // second message parameter
  )
  {
      switch (uMsg)
      {
      case WM_INITDIALOG:
      {
          main_hwnd = GetDlgItem(hwndDlg, IDC_EDIT_total);
          SetWindowText(main_hwnd, TEXT("1000"));
  
          hwnd_A = GetDlgItem(hwndDlg, IDC_EDIT_1);        // 线程1文本框
          SetWindowText(hwnd_A, TEXT("0"));
          hwnd_B = GetDlgItem(hwndDlg, IDC_EDIT_2);        // 线程2文本框
          SetWindowText(hwnd_B, TEXT("0"));
          hwnd_C = GetDlgItem(hwndDlg, IDC_EDIT_3);        // 线程3文本框
          SetWindowText(hwnd_C, TEXT("0"));
      }
      return TRUE;
  
      case WM_COMMAND:
      {
          switch (LOWORD(wParam))
          {
          case IDC_BUTTON: // 按钮点击事件
              HANDLE hThreadButton = ::CreateThread(NULL, 0, startnew, NULL, 0, NULL);
              ::CloseHandle(hThreadButton);
              return TRUE;
          }
      }
      break;
  
      case WM_CLOSE:
          EndDialog(hwndDlg, 0);
          return TRUE;
      }
  
      return FALSE;
  }
  
  int APIENTRY WinMain(HINSTANCE hInstance,
      HINSTANCE hPrevInstance,
      LPSTR    lpCmdLine,
      int      nCmdShow)
  {
      // TODO: Place code here.
      DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, (DLGPROC)DialogProc);
      return 0;
  }
  ```

#### 鼠标_键盘

- 练习：

  1. 遍历所有打开窗口，等待
  2. 设置鼠标位置，点击
  3. 模拟键盘输入密码
  4. 设置鼠标位置，单击登录

  ```c++
  #include <stdio.h>
  #include <stdlib.h>
  #include <windows.h>
  
  int main() {
  	//ShowWindow(GetConsoleWindow(), SW_HIDE);
  	STARTUPINFO si = { 0 };
  	PROCESS_INFORMATION pi;
  	si.cb = sizeof(si);
  	RECT windowRect;
  	BOOL res = CreateProcess(
  			TEXT("C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2410.21.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe"),
  			NULL,
  			NULL,
  			NULL,
  			FALSE,
  			CREATE_NEW_CONSOLE,
  			NULL,
  			NULL, &si, &pi);
  	HWND hwnd = FindWindow(NULL, TEXT("Notepad"));
  	
      if (GetWindowRect(hwnd, &windowRect)) {
          int centerX = windowRect.left + (windowRect.right - windowRect.left) / 2;
          int centerY = windowRect.top + (windowRect.bottom - windowRect.top) / 2;
  
          if (SetCursorPos(centerX, centerY)) {
          } else {
              return 1;
          }
      } else {
          return 1;
      }
      Sleep(1000);
  	
  	mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);
  	mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);
  	keybd_event(16,0,0,0);
  	keybd_event(67,0,0,0);
  	keybd_event(67,0,KEYEVENTF_KEYUP,0);
  	keybd_event(16,0,KEYEVENTF_KEYUP,0);
  	Sleep(100);
  	keybd_event(54,0,0,0);
  	keybd_event(54,0,KEYEVENTF_KEYUP,0);
  	Sleep(100);
  	keybd_event(53,0,0,0);
  	keybd_event(53,0,KEYEVENTF_KEYUP,0);
  	Sleep(100);
  	keybd_event(77,0,0,0);
  	keybd_event(77,0,KEYEVENTF_KEYUP,0);
  	Sleep(100);
  	keybd_event(65,0,0,0);
  	keybd_event(65,0,KEYEVENTF_KEYUP,0);
  	Sleep(100);
  	keybd_event(69,0,0,0);
  	keybd_event(69,0,KEYEVENTF_KEYUP,0);
  	Sleep(100);
  	keybd_event(76,0,0,0);
  	keybd_event(76,0,KEYEVENTF_KEYUP,0);
      return 0;
  }
  ```

- ```c++
  void test()
  {
  	while (true)
  	{
  		TCHAR szTitle[MAX_PATH] = {0};
  		HWND hwnd1 = ::FindWindow(NULL,TEXT("文件资源管理器"));
  		HWND hwnd2 = ::FindWindow(NULL,TEXT("火绒安全分析工具"));
  		HWND hwnd3 = ::FindWindow(NULL,TEXT("设置"));
  		HWND hwnd4 = ::FindWindow(NULL,TEXT("Windows 安全中心"));
  		HWND hwnd5 = ::FindWindow(NULL,TEXT("注册表编辑器"));
  		HWND hwnd6 = ::FindWindow(NULL,TEXT("Windows PowerShell"));
  		HWND hwnd7 = ::FindWindow(NULL,TEXT("命令提示符"));
  		HWND hwnd8 = ::FindWindow(NULL,TEXT("任务管理器"));
  		SwitchToThisWindow(hwnd1,false);
  		SwitchToThisWindow(hwnd2,false);
  		SwitchToThisWindow(hwnd3,false);
  		SwitchToThisWindow(hwnd4,false);
  		SwitchToThisWindow(hwnd5,false);
  		SwitchToThisWindow(hwnd6,false);
  		SwitchToThisWindow(hwnd7,false);
  		SwitchToThisWindow(hwnd8,false);
  		if(hwnd1 != NULL || hwnd2 != NULL || hwnd3 != NULL || hwnd4 != NULL || hwnd5 != NULL || hwnd6 != NULL || hwnd7 != NULL || hwnd8 != NULL)
  		{
  			::SendMessage(hwnd1,WM_CLOSE,0,0);
  			::SendMessage(hwnd2,WM_CLOSE,0,0);
  			::SendMessage(hwnd3,WM_CLOSE,0,0);
  			::SendMessage(hwnd4,WM_CLOSE,0,0);
  			::SendMessage(hwnd5,WM_CLOSE,0,0);
  			::SendMessage(hwnd6,WM_CLOSE,0,0);
  			::SendMessage(hwnd7,WM_CLOSE,0,0);
  			::SendMessage(hwnd8,WM_CLOSE,0,0);
  		}
  		Sleep(100);
  	}
  	
  }
  ```

### CE

- 第八题

  1. 首先找到是谁修改了这个值

     ```asm
     RAX=00000DD5
     RBX=015F7270
     RCX=E2A9C98E
     RDX=066FC98E
     RSI=01632ED0
     RDI=100290098
     RBP=013FEE40
     RSP=013FED00
     RIP=10002E94D
     
     指针基址可能是 =01632ED0
     
     10002E940 - mov ecx,00000FA0
     10002E945 - call 10000FC10
     10002E94A - mov [rsi+18],eax   <----
     10002E94D - lea rcx,[rbp-08]
     10002E951 - call 100008F10
     ```

     可以看到是`eax`向`[rsi+18]`赋值，为什么要找`rsi`而不是`eax`？

     关注`rsi`是因为它指向存储数据的**内存结构**，其来源可通过指针链关联到静态基址；而`eax`仅是一个临时数值，无法用于基址定位。通过追踪`rsi`的赋值逻辑，才能找到稳定的基址表达式。
  
  2. 由于目前`rsi`里面的值有可能直接是基址，也有可能是新一级的偏移（比如`[基址 + 0x100]`）；是新一级的偏移的话就不能直接通过`0x1632ED0`去寻找了，而是要根据减去偏移后的值去寻找。
  
     直接找谁修改了它发现没有人修改它，就看谁访问了它（这个它就是根据`0x1632ED0`进行新搜索的地址，判断它直接是基址还是偏移）：
  
     这时有两条指令访问了它，其中一个是访问它进行比较，没有价值。我们看另外一个：
  
     ```asm
     RAX=0164AF60
     RBX=015F7270
     RCX=015F7270
     RDX=0000185A
     RSI=01632ED0
     RDI=100290098
     RBP=013FEE40
     RSP=013FED00
     RIP=10002E90B
     
     指针基址可能是 =01632ED0
     
     10002E900 - je 10002E9A7
     10002E906 - nop 2
     10002E908 - mov rsi,[rsi]    <----
     10002E90B - mov rax,rsi
     10002E90E - mov edx,[rax+04]
     ```
  
     这是将`rsi`地址的值赋给`rsi`。
  
  3. 发现它没有偏移，那么就直接用`0x1632ED0`地址的值（`0x164AF60`）再次进行搜索，同样先看一下谁访问了它：
  
     ```asm
     RAX=0164AEE0
     RBX=015F7270
     RCX=015F7270
     RDX=00011DB9
     RSI=0164AF60
     RDI=100290098
     RBP=013FEE40
     RSP=013FED00
     RIP=10002E8C0
     
     指针基址可能是 =0164AEE0
     
     10002E8B5 - je 10002E9A7
     10002E8BB - nop 
     10002E8BC - mov rsi,[rsi+18]    <----
     10002E8C0 - mov rax,rsi
     10002E8C3 - mov edx,[rax+0C]
     ```
  
     这是将`rsi+0x18`地址的值赋给`rsi`。这时就不能用`0x164AF60`地址的值（`0x164AEF8`）直接搜索，因为有`0x18`的偏移。
  
  4. 所以用`0x164AEE0`再次进行搜索，同样先看一下谁访问了它：
  
     ```asm
     RAX=01632C50
     RBX=015F7270
     RCX=015F7270
     RDX=00001C5A
     RSI=0164AEE0
     RDI=100290098
     RBP=013FEE40
     RSP=013FED00
     RIP=10002E878
     
     指针基址可能是 =01632C50
     
     10002E86D - je 10002E9A7
     10002E873 - nop 
     10002E874 - mov rsi,[rsi+10]    <----
     10002E878 - mov rax,rsi
     10002E87B - mov edx,[rax+04]
     ```
  
  5. 同上，所以就直接用`0x1632C50`再次进行搜索，同样先看一下谁访问了它：
  
     ```asm
     RAX=015FBAB0
     RBX=015F7270
     RCX=015F7270
     RDX=015FBAB0
     RSI=01632C50
     RDI=100290098
     RBP=013FEE40
     RSP=013FED00
     RIP=10002E82D
     
     指针基址可能是 =100325B00
     
     10002E81D - mov qword ptr [rbp-08],00000000
     10002E825 - nop 
     10002E826 - mov rsi,[100325B00]    <----
     10002E82D - mov rax,rsi
     10002E830 - mov edx,[rax+04]
     ```
  
     这是可以看到已经不是偏移了，而是硬编码的地址，就是向这个地址进行赋值的。综上找到的结构为：
  
     ```asm
     [[[[[100325B00]+10]+18]]+18] = eax
     ```
  
  6. 我们需要构造这个结构去直接找到被赋值的位置，在`ce`中手动添加地址：
  
     ![image](/homework/ce.png)
  
     就可以看到正常显示数值了，即使改变指针也不怕了。

### 保护模式

#### 段描述符与段选择子

1. 在`windbg`中查看`GDT`表的基址和长度

   查看`xp`的`GDT`表

   ```asm
   0: kd> r gdtr
   gdtr=8003f000		#基址
   0: kd> r gdtl
   gdtl=000003ff		#长度
   ```

2. 分别使用`dd dq`指令查看`GDT`表

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

3. 段描述符查分实验：拆`5`个

   ![image](/myassets/xuanzazi.png)

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

   ```
   8003f000  00000000`00000000 00cf9b00`0000ffff
   8003f010  00cf9300`0000ffff 00cffb00`0000ffff
   8003f020  00cff300`0000ffff 80008b04`200020ab
   8003f030  ffc093df`f0000001 0040f300`00000fff
   8003f040  0000f200`0400ffff 00000000`00000000
   8003f050  80008954`af000068 80008954`af680068
   8003f060  00009302`2f40ffff 0000920b`80003fff
   8003f070  ff0092ff`700003ff 80009a40`0000ffff
   8003f080  80009240`0000ffff 00009200`00000000
   
   00cf9b00`0000ffff
   Base=00 00
   23~20 [c]= 1100
   G=1
   D/B=1
   AVL=0
   Limit=f ffff
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[b]=1011
   Address=0000
   
   00cf9300`0000ffff
   Base=00 00
   23~20 [c]= 1100
   G=1
   D/B=1
   AVL=0
   Limit=f ffff
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[3]=0011
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
   DPL=11
   s=1
   Type=[b]=1011
   Address=0000
   
   00cff300`0000ffff
   Base=00 00
   23~20 [c]= 1100
   G=1
   D/B=1
   AVL=0
   Limit=f ffff
   16~12 [f]=1111
   p=1
   DPL=11
   s=1
   Type=[3]=0011
   Address=0000
   
   80008b04`200020ab
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
   Type=[b]=1011
   Address=2000
   
   ffc093df`f0000001
   Base=ff df
   23~20 [c]= 1100
   G=1
   D/B=1
   AVL=0
   Limit=0 0001
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[3]=0011
   Address=f000
   
   0040f300`00000fff
   Base=00 00
   23~20 [4]= 0100
   G=0
   D/B=1
   AVL=0
   Limit=0 0fff
   16~12 [f]=1111
   p=1
   DPL=11
   s=1
   Type=[3]=0011
   Address=0000
   
   0000f200`0400ffff
   Base=00 00
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 ffff
   16~12 [f]=1111
   p=1
   DPL=11
   s=1
   Type=[2]=0010
   Address=0400
   
   80008954`af000068
   Base=80 54
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 0068
   16~12 [8]=1000
   p=1
   DPL=00
   s=0
   Type=[9]=1001
   Address=af00
   
   00009302`2f40ffff
   Base=00 02
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 ffff
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[3]=0011
   Address=2f40
   
   ff0092ff`700003ff
   Base=ff ff
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 03ff
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[2]=0010
   Address=7000
   
   80009a40`0000ffff
   Base=80 40
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 ffff
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[a]=1001
   Address=0000
   
   80009240`0000ffff
   Base=80 40
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 ffff
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[2]=0011
   Address=0000
   
   00009200`00000000
   Base=00 00
   23~20 [0]= 0000
   G=0
   D/B=0
   AVL=0
   Limit=0 0000
   16~12 [9]=1001
   p=1
   DPL=00
   s=1
   Type=[2]=0011
   Address=0000
   ```

   

4. 段选择子拆分实验：

   ![image](/myassets/xz.png)

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

![image](/myassets/type.png)

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

   ![image](/myassets/dym.png)

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

  ![image](/myassets/pdeptejg.png)

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
  	return 0;
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
  		 (*(UINT32*)pCur)++;
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
  		DriverObject->DriverUnload = (PDRIVER_UNLOAD)UnloadDriver;
  		return STATUS_SUCCESS;
      }
  
  if (DllBase)
      {
          PspTerminateProcess = (_PspTerminateProcess)(DllBase + 0xF1DA4);    //0xF1DA4 就是偏移
          PspTerminateProcess(Extprocess, 0); 
      }
  
  	DbgPrint( "关了\n" );
  
      DriverObject->DriverUnload = (PDRIVER_UNLOAD)UnloadDriver;
      return STATUS_SUCCESS;
  }
  ```
  
  

### 系统调用

###### 01

- 自己编写`WriteProcessMemory`函数（不使用任何`DLL`，直接调用0环函数）并在代码中使用。

  ```c++
  BOOL __declspec(naked) __stdcall WriteProcMemmmm(DWORD handle,DWORD addr,unsigned char* buffer,DWORD len,DWORD sizewrite)
  {
      _asm
      {
          mov eax, 115h ;
          mov edx, 7FFE0300h;
          call dword ptr [edx];
          retn 14h;
      }
  }
  ```


###### 02

- 自己实现通过中断门直接调用内核函数

  ```c++
  BOOL __declspec(naked) __stdcall VirtualAllocMY(DWORD handle,DWORD addr,unsigned char* buffer,DWORD len,DWORD sizewrite)
  {
      _asm
      {
          mov eax, 11h ;
          mov edx, 7FFE0300h;
          lea edx, [esp+8];
          int 2Eh;
          retn;
      }
  }
  ```

###### 03

- 从`Kernel32.dll`中打开某个函数分析执行流程（怎么找到对应的内核函数，怎么找到参数，如何将参数传到0环的）

  ```asm
  ;virtualAlloc() -> VirtualAllocEx() -> NtAllocateVirtualMemory()
  
  ;-------------------Ntdll.dll------------------------------------
  
  .text:7C92CF50 ; __stdcall NtAllocateVirtualMemory(x, x, x, x, x, x)
  .text:7C92CF50                 public _NtAllocateVirtualMemory@24
  .text:7C92CF50 _NtAllocateVirtualMemory@24 proc near   ; CODE XREF: RtlAllocateHeap(x,x,x)+1126↓p
  .text:7C92CF50                                         ; RtlpFindAndCommitPages(x,x,x,x)+93↓p ...
  .text:7C92CF50                 mov     eax, 10001b     ; NtAllocateVirtualMemory服务号
  .text:7C92CF55                 mov     edx, 7FFE0300h
  .text:7C92CF5A                 call    dword ptr [edx] ; 调用共享区对应的SystemCall函数
  .text:7C92CF5C                 retn    18h
  .text:7C92CF5C _NtAllocateVirtualMemory@24 endp
      
  ;在windbg中我u不到，但是可以从一下看到
  /*
  kd> dd 7FFE0300
  7ffe0300  7c92e4f0 7c92e4f4 00000000 00000000
  7ffe0310  00000000 00000000 00000000 00000000
  7ffe0320  00000000 00000000 00000000 00000000
  7ffe0330  ff9d665a 00000000 00000000 00000000
  7ffe0340  00000000 00000000 00000000 00000000
  7ffe0350  00000000 00000000 00000000 00000000
  7ffe0360  00000000 00000000 00000000 00000000
  7ffe0370  00000000 00000000 00000000 00000000
  
  kd> ln 7c92e4f0
  Browse module
  Set bu breakpoint
  
  (7c92e4f0)   ntdll!KiFastSystemCall   |  (7c92e4f4)   ntdll!KiFastSystemCallRet
  Exact matches:
      ntdll!KiFastSystemCall (_KiFastSystemCall@0)
  */
  
  .text:7C92E4F0                 public _KiFastSystemCall@0
  .text:7C92E4F0 _KiFastSystemCall@0 proc near           ; DATA XREF: .text:off_7C923428↑o
  .text:7C92E4F0                 mov     edx, esp     ;保存esp
  .text:7C92E4F2                 sysenter
  .text:7C92E4F2 _KiFastSystemCall@0 endp
  
  ;-------------------------------ntoskrnl.exe------------------------------
  
  ;KiFastCallEntry
  
  ;找到对应的内核函数
  .text:004077A1                 cmp     ecx, 10000b     ; 比较之前的那个第12位是否是1
  .text:004077A4                 jnz     short loc_4077C0 ; 查找第一个系统服务表
  .text:004077A6                 mov     ecx, ds:0FFDFF018h
  .text:004077AC                 xor     ebx, ebx
  .text:004077C0                 inc     dword ptr ds:0FFDFF638h
  .text:004077C6                 mov     esi, edx        ; esi = edx（三环参数的指针（lea edx, [esp+arg_4]））
  .text:004077C8                 mov     ebx, [edi+0Ch]  ; ebx = _SYSTEM_SERVICE_TABLE.ArgmentTable
  .text:004077CB                 xor     ecx, ecx        ; 清空ecx
  .text:004077CD                 mov     cl, [eax+ebx]   ; cl = 这个系统调用对应的参数的字节大小
  .text:004077D0                 mov     edi, [edi]      ; edi = _SYSTEM_SERVICE_TABLE.ServiecTable（函数地址表）
  .text:004077D2                 mov     ebx, [edi+eax*4] ; ebx = 0环函数的地址
  
  ;找到参数,并将参数传到0环的
  .text:004077D5                 sub     esp, ecx        ; 提升对应的参数个数个堆栈（这里的ecx是要执行的参数的字节大小）
  .text:004077D7                 shr     ecx, 2          ; 参数长度/4 = 参数个数（四字节），一次拷贝4字节，这是拷贝的次数
  .text:004077DA                 mov     edi, esp        ; edi指向函数参数的位置
  .text:004077E8                 rep movsd               ; 循环拷贝
  .text:004077EA                 call    ebx
  ```

###### 04

-  写代码保护指定进程（比如记事本），防止别人关闭它，而自己关闭正常退出

  模板：

  ```c++
  #include <ntddk.h>
  #include <ntstatus.h>
   
  /************************************************************************/
  /* 类型声明                                                             */
  /************************************************************************/
   
  // 系统服务表
  typedef struct _KSYSTEM_SERVICE_TABLE
  {
  	PULONG ServiceTableBase;			// 函数地址表
  	PULONG ServiceCounterTableBase;		// SSDT 函数被调用的次数
  	ULONG NumberOfService;				// 函数个数
  	PULONG ParamTableBase;				// 函数参数表
  } KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;
   
  // SSDT表
  typedef struct _KSERVICE_TABLE_DESCRIPTOR
  {
  	KSYSTEM_SERVICE_TABLE ntoskrnl;		// 内核函数
  	KSYSTEM_SERVICE_TABLE win32k;		// win32k.sys 函数
  	KSYSTEM_SERVICE_TABLE unUsed1;
  	KSYSTEM_SERVICE_TABLE unUsed2;
  } KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
   
  // NTOPENPROCESS
  typedef NTSTATUS (*NTOPENPROCESS) (PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
   
   
  /************************************************************************/
  /* 函数声明                                                             */
  /************************************************************************/
   
  VOID DriverUnload(PDRIVER_OBJECT pDriver);
  NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING reg_path);
  VOID PageProtectOff();
  VOID PageProtectOn();
  VOID HookNtOpenProcess();
  VOID UnHookNtOpenProcess();
  NTSTATUS HbgNtOpenProcess(PHANDLE  ProcessHandle, ACCESS_MASK  DesiredAccess, POBJECT_ATTRIBUTES  ObjectAttributes, PCLIENT_ID  ClientId);
   
   
  /************************************************************************/
  /* 全局变量                                                             */
  /************************************************************************/
   
  extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable; // ntoskrnl.exe 导出的全局变量
  ULONG uOldNtOpenProcess; // 旧的函数地址
   
   
  /************************************************************************/
  /* 函数定义                                                             */
  /************************************************************************/
   
  // 驱动入口
  NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING reg_path)
  {
  	// HOOK
  	HookNtOpenProcess();
   
  	pDriver->DriverUnload = DriverUnload;
   
  	return STATUS_SUCCESS;
  }
   
  // 卸载驱动
  VOID DriverUnload(PDRIVER_OBJECT pDriver)
  {
  	UnHookNtOpenProcess();
  	DbgPrint("Driver unloaded.\n");
  }
   
  // 关闭页保护
  VOID PageProtectOff()
  {
  	__asm
  	{
  		cli; // 关闭中断
  		mov eax, cr0;
  		and eax, not 0x10000; // WP位置0
  		mov cr0, eax;
  	}
  }
   
  // 开启页保护
  VOID PageProtectOn()
  {
  	__asm
  	{
  		mov eax, cr0;
  		or eax, 0x10000; // WP位置1
  		mov cr0, eax;
  		sti; // 恢复中断
  	}
  }
   
  // HOOK NtOpenProcess
  VOID HookNtOpenProcess()
  {
  	PageProtectOff();
  	uOldNtOpenProcess = KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0x7A];
  	KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0x7A] = (ULONG)HbgNtOpenProcess;
  	PageProtectOn();
  }
   
  // UnHOOK NtOpenProcess
  VOID UnHookNtOpenProcess()
  {
  	PageProtectOff();
  	KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0x7A] = uOldNtOpenProcess;
  	PageProtectOn();
  }
   
  // 被修改的 NtOpenProcess 函数，简单打印参数
  NTSTATUS HbgNtOpenProcess(PHANDLE  ProcessHandle, ACCESS_MASK  DesiredAccess, POBJECT_ATTRIBUTES  ObjectAttributes, PCLIENT_ID  ClientId)
  {
  	DbgPrint("%x %x %x %x\n", ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
  	return ((NTOPENPROCESS)uOldNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
  }
   
  ```


### 进程与线程

###### 01

- 断链进程结构体，实现隐藏，并思考为什么断链进程为什么还能够执行。

  ```
  Failed to get VadRoot
  PROCESS 89512978  SessionId: 0  Cid: 0684    Peb: 7ffd5000  ParentCid: 0580
      DirBase: 10240220  ObjectTable: e1778238  HandleCount:  85.
      Image: ctfmon.exe
  
  Failed to get VadRoot
  PROCESS 8944d640  SessionId: 0  Cid: 0710    Peb: 7ffdb000  ParentCid: 0580
      DirBase: 10240260  ObjectTable: e26f6560  HandleCount:  50.
      Image: notepad.exe
  
  Failed to get VadRoot
  PROCESS 897d36e8  SessionId: 0  Cid: 07a8    Peb: 7ffdb000  ParentCid: 0298
      DirBase: 102401a0  ObjectTable: e22ba310  HandleCount:  60.
      Image: VGAuthService.exe
  
  ```

- 使用`DebugPort`清零实现反调试。

###### 05

- 分析`KiSwapContext`函数：

  1. `SwapContext`有几个参数，分别是什么？

     三个，`int *a1@<ebx>, int a2@<edi>, int a3@<esi>`

  2. `SwapContext`在哪里实现了线程切换？

     切换`esp`就是切换线程了：

     ```asm
     .text:0040498F loc_40498F:                             ; CODE XREF: SwapContext+66↑j
     .text:0040498F                 mov     ecx, [ebx+40h]
     .text:00404992                 mov     [ecx+4], eax
     .text:00404995                 mov     esp, [esi+28h]
     .text:00404998                 mov     eax, [esi+20h]
     .text:0040499B                 mov     [ebx+18h], eax
     ```

  3. 线程切换的时候，会切换`Cr3`吗？切换`Cr3`的条件是什么？

     ```asm
     .text:0040499F                 mov     eax, [edi+44h]
     .text:004049A2                 cmp     eax, [esi+44h]
     .text:004049A5                 mov     byte ptr [edi+50h], 0
     .text:004049A9                 jz      short loc_4049D7
     如果[edi+44h] != [esi+44h]就切换cr3
     ```

  4. 中断门提权时，`CPU`会从`TSS`得到`ESP0`和`SS0`，`TSS`中存储的一定是当前线程的`ESP0`和`SS0`吗？如何做到的？

      

  5. `FS:[0]`在3环时指向`TEB`但是线程有很多，`FS:[0]`指向的是哪个线程的`TEB`如何做到的？

  6. 0环的`ExceptionList`在哪里备份的?

  7. `IdleThread`是什么？什么时候执行？如何找到这个函数？

  8. 分析`KiFindReadyThread`，查看是怎样查找就绪线程的。

  9. 模拟线程切换与`Windows`的线程切换有哪些区别?

  10. 走一遍时钟中断流程，分析`KeUpdateRunTine`函数。
