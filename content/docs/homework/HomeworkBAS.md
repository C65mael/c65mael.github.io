---
title: HomeworkBAS
cascade:
  type: docs
---

###### 进制

- 编制`7`进制加法表，乘法表，并计算下面的结果：`23456+54356=？5621-654=？234*65=？`

  | 7进制   |         |         |         |         |         |
  | ------- | ------- | ------- | ------- | ------- | ------- |
  | 1+1 =2  |         |         |         |         |         |
  | 1+2 =3  | 2+2 =4  |         |         |         |         |
  | 1+3 =4  | 2+3 =5  | 3+3 =6  |         |         |         |
  | 1+4 =5  | 2+4 =6  | 3+4 =10 | 4+4 =11 |         |         |
  | 1+5 =6  | 2+5 =10 | 3+5 =11 | 4+5 =12 | 5+5 =13 |         |
  | 1+6 =10 | 2+6 =11 | 3+6 =12 | 4+6 =13 | 5+6 =14 | 6+6 =15 |

  | 7进制  |         |         |         |         |         |
  | ------ | ------- | ------- | ------- | ------- | ------- |
  | 1*1 =1 |         |         |         |         |         |
  | 1*2 =2 | 2*2 =4  |         |         |         |         |
  | 1*3 =3 | 2*3 =6  | 3*3 =12 |         |         |         |
  | 1*4 =4 | 2*4 =11 | 3*4 =15 | 4*4 =22 |         |         |
  | 1*5 =5 | 2*5 =13 | 3*5 =21 | 4*5 =26 | 5*5 =34 |         |
  | 1*6 =6 | 2*6 =15 | 3*6 =24 | 4*6 =33 | 5*6 =42 | 6*6 =51 |
  
  ```
  23456 + 54356 = 111145
    23456
  + 54356
  ---------
   111145
   
  5621 - 654 = 4634
    5621
  -  654
  --------
    4634
    
  234 * 65 = 12566
    234
  *  65
  -------
   1536
  2103
  -------
  12566
  ```
  
- 编制`16`进制加法表，乘法表，并计算下面的结果：`2D4E6+CF3A6=？5FD1-E5A=？2CA*A5=？`

  | 16进制  |         |         |         |         |         |
  | ------- | ------- | ------- | ------- | ------- | ------- |
  | 1+1 =2  |         |         |         |         |         |
  | 1+2 =3  | 2+2 =4  |         |         |         |         |
  | 1+3 =4  | 2+3 =5  | 3+3 =6  |         |         |         |
  | 1+4 =5  | 2+4 =6  | 3+4 =7  | 4+4 =8  |         |         |
  | 1+5 =6  | 2+5 =7  | 3+5 =8  | 4+5 =9  | 5+5 =A  |         |
  | 1+6 =7  | 2+6 =8  | 3+6 =9  | 4+6 =A  | 5+6 =B  | 6+6 =C  |
  | 1+7 =8  | 2+7 =9  | 3+7 =A  | 4+7 =B  | 5+7 =C  | 6+7 =D  |
  | 1+8 =9  | 2+8 =A  | 3+8 =B  | 4+8 =C  | 5+8 =D  | 6+8 =E  |
  | 1+9 =A  | 2+9 =B  | 3+9 =C  | 4+9 =D  | 5+9 =E  | 6+9 =F  |
  | 1+A =B  | 2+A =C  | 3+A =D  | 4+A =E  | 5+A =F  | 6+A =10 |
  | 1+B =C  | 2+B =D  | 3+B =E  | 4+B =F  | 5+B =10 | 6+B =11 |
  | 1+C =D  | 2+C =E  | 3+C =F  | 4+C =10 | 5+C =11 | 6+C =12 |
  | 1+D =E  | 2+D =F  | 3+D =10 | 4+D =11 | 5+D =12 | 6+D =13 |
  | 1+E =F  | 2+E =10 | 3+E =11 | 4+E =12 | 5+E =13 | 6+E =14 |
  | 1+F =10 | 2+F=11  | 3+F =12 | 4+F =13 | 5+F =14 | 6+F =15 |

  | 16进制 |         |         |         |         |         |
  | ------ | ------- | ------- | ------- | ------- | ------- |
  | 1*1 =1 |         |         |         |         |         |
  | 1*2 =2 | 2*2 =4  |         |         |         |         |
  | 1*3 =3 | 2*3 =6  | 3*3 =9  |         |         |         |
  | 1*4 =4 | 2*4 =8  | 3*4 =C  | 4*4 =10 |         |         |
  | 1*5 =5 | 2*5 =A  | 3*5 =F  | 4*5 =14 | 5*5 =19 |         |
  | 1*6 =6 | 2*6 =C  | 3*6 =12 | 4*6 =18 | 5*6 =1E | 6*6 =24 |
  | 1*7 =7 | 2*7 =E  | 3*7 =15 | 4*7 =1C | 5*7 =23 | 6*7 =2A |
  | 1*8 =8 | 2*8 =10 | 3*8 =18 | 4*8 =20 | 5*8 =28 | 6*8 =30 |
  | 1*9 =9 | 2*9 =12 | 3*9 =1B | 4*9 =24 | 5*9 =2D | 6*9 =36 |
  | 1*A =A | 2*A =14 | 3*A =1E | 4*A =28 | 5*A =32 | 6*A =3C |
  | 1*B =B | 2*B =16 | 3*B =21 | 4*B =2C | 5*B =37 | 6*B =42 |
  | 1*C =C | 2*C =18 | 3*C =24 | 4*C =30 | 5*C =3C | 6*C =48 |
  | 1*D =D | 2*D =1A | 3*D =27 | 4*D =34 | 5*D =41 | 6*D =4E |
  | 1*E =E | 2*E =1C | 3*E =27 | 4*E =38 | 5*E =46 | 6*E =54 |
  | 1*F =F | 2*F=1E  | 3*F =2D | 4*F =3C | 5*F =4B | 6*F =5A |

  ```
  2D4E6 + CF3A6 = 0xfc88c
  5FD1 - E5A = 0x5177
  2CA * A5 =  0x1cc32
  ```

- `9`进制定义：由`9`个符号组成，分别是：`2、9、1、7、6、5、4、8、3`，逢`9`进`1`，计算：`123 + 234 = ?` 

  ​                                                                  `0、1、2、3、4、5、6、7、8`

  先转为一般`9`进制：`208 + 086`

  ```
    208
  + 086
  -------
    305
  ```

  转为定义的`9`进制：`725`

- `10`进制定义：由`10`个符号组成，分别是：`!、@、$、%、^、&、*、A、B、C`，逢`10`进`1`，计算：`@$$B + %AC& = ?` 

  ​                                                                     `0、1、2、3、4、5、6、7、8、9`

  转为一般`10`进制并计算：`1228 + 3795 = 5023`

  转为定义的`10`进制：`&!$%`

- 使用异或对`87AD6`进行加密后再进行解密，加解密密钥：`5`

  ```c
  #include <stdio.h>
  #include <string.h>
  
  char xor_with_key(char data, char key) {
      int hex_value = (data >= '0' && data <= '9') ? data - '0' : data - 'A' + 10;
      int xor_result = hex_value ^ key;
      return (xor_result < 10) ? (xor_result + '0') : (xor_result - 10 + 'A');
  }
  
  void encrypt_decrypt(char *input, char key) {
      for (int i = 0; i < strlen(input); i++) {
          input[i] = xor_with_key(input[i], key);
      }
  }
  
  int main() {
      char input[] = "87AD6";
      char key = 5; // XOR key
  
      printf("Original: %s\n", input);
  
      // Encrypt
      encrypt_decrypt(input, key);
      printf("Encrypted: %s\n", input);
  
      // Decrypt
      encrypt_decrypt(input, key);
      printf("Decrypted (Original): %s\n", input);
  
      return 0;
  }
  ```


###### 逻辑运算

- 八进制数`2-5`在计算器中的的结果是：`1777777777777777777775`为什么？

  算是负数溢出了

- 只用逻辑运算计算`2-3=？`（涉及内容：逻辑运算、移位、数据宽度）

  ```
  2+(-3)
      0010    
      1101    
  xor-----------      
      1111    r：1111
      
      0010    
      1101    
  and-----------      
      0000    r：0000
  
  result ==1111 = -1  
  ```
  

###### 堆栈操作

- 使用`EBX`存储栈底地址，`EDX`存储栈顶地址，连续存储`5`个不同的数

  ```asm
  mov edx,esp
  
  mov eax,11111111
  mov dword ptr ss:[edx],eax
  sub edx,4
  ↑x5
  ```

- 分别使用栈底加偏移、栈顶加偏移的方式读取这`5`个数，并存储到寄存器中

  ```asm
  mov eax,dword ptr ss:[edx+4]
  
  mov eax,dword ptr ss:[ebx-4]
  ```

- 弹出这`5`个数，恢复栈顶到原来的位置

  ```asm
  pop eax
  ↑x5
  mov ebx,dword ptr ss:[ebx+0x4*5]
  ```

- 使用`2`种方式实现：`push ecx`

  ```asm
  sub esp,4
  mov dword ptr ss:[esp],ecx
  
  mov esp,dword ptr ss:[esp-4]
  mov dword ptr ss:[esp],ecx
  ```

- 使用`2`种方式实现：`pop ecx`

  ```asm
  mov ecx,dword ptr ss:[esp]
  add esp,4
  
  mov ecx,dword ptr ss:[esp]
  mov esp,dword ptr ss:[esp+4]
  ```

- 使用`2`种方式实现：`push esp`

  ```asm
  sub esp,4
  mov dword ptr ss:[esp],esp
  
  mov dword ptr ss:[esp-4],esp
  lea esp,dword ptr ss:[esp-4]      
  ```

- 使用`2`种方式实现：`pop esp`

  ```asm
  add esp,4
  mov esp,dword ptr ss:[esp-4]
  
  lea esp,dword ptr ss:[esp+4]
  mov esp,dword ptr ss:[esp-4]
  ```


###### 标志寄存器

- 写汇编指令只影响`CF`位的值（不能影响其他标志位）

  ```asm
  mov ax,0xf000
  add ax,0x1000
  ```

- 写汇编指令只影响`PF`位的值（不能影响其他标志位）

  ```asm
  MOV ax,0x3
  add ax,0xC0
  ```

- 写汇编指令只影响`AF`位的值（不能影响其他标志位)

  ```asm
  mov ax,0xf0
  add ax,0x10
  ```

- 写汇编指令只影响`SF`位的值（不能影响其他标志位）

  ```asm
  MOV ax,0x8000
  add ax,0xc
  ```

- 写汇编指令只影响`OF`位的值（不能影响其他标志位）

  ```asm
  MOV AL,0x80
  SUB AL,0x10
  ```

- 用`MOVS`指令分别移动`5`个字节、`5`个字、`5`个双字

  ```asm
  MOVS BYTE PTR ES:[EDI],BYTE PTR DS:[ESI]
  MOVS WORD PTR ES:[EDI],BYTE PTR DS:[ESI]
  MOVS DWORD PTR ES:[EDI],BYTE PTR DS:[ESI]
  ```

- 用`STOS`指令分别存储`5`个字节、`5`个字、`5`个双字

  ```asm
  STOS BYTE PTR ES:[EDI]
  STOS WORD PTR ES:[EDI]
  STOS DWORD PTR ES:[EDI]
  ```

- 使用`REP`指令重写上面两题

  ```asm
  MOV ECX,5
  REP MOVSD
  REP STOSD
  ```


###### JCC

- `CALL`执行时堆栈有什么变化？`EIP`有变化吗？

  将`call`下一行代码的地址`push`进栈，然后将`eip`跳到要`call`的地址处

- `RET`执行时堆栈有什么变化？`EIP`有变化吗？

  将栈顶的值`pop`给`eip`，这个值是之前`call`时的下一行的地址

- 使用汇编指令修改标志寄存器中的某个位的值，实现`JCC`的十六种跳转

  不允许在`OD`中通过双击的形式修改标志寄存器

  要通过汇编指令的执行去影响标志位，能用`CMP`和`TEST`实现的优先考虑

  ```asm
  1、	JE, JZ       		结果为零则跳转(相等时跳转)						ZF=1
  mov eax,0x1337
  mov ecx,0x1337
  cmp eax,ecx
  jz 0x00400000
  
  2、	JNE, JNZ        		结果不为零则跳转(不相等时跳转)  						ZF=0
  mov eax,0x1337
  test eax,eax
  jnz 0x00400000
  
  3、	JS 		结果为负则跳转						SF=1
  mov eax,0x100
  mov ecx,0x200
  cmp eax,ecx
  js  0x00401045
  
  4、	JNS 		结果为非负则跳转						SF=0
  mov eax,0x100
  mov ecx,0x200
  cmp ecx,eax
  js  0x00401045
  
  5、	JP, JPE   		结果中1的个数为偶数则跳转						PF=1
  mov eax,0x100
  mov ecx,0x200
  cmp ecx,eax
  jp  0x4010B2
  
  6、	JNP, JPO   		结果中1的个数为偶数则跳转						PF=0
  mov eax,0x101
  mov ecx,0x100
  cmp eax,ecx
  jpo 0x40101C
  
  7、	JO    		结果溢出了则跳转						OF=1
  
  
  8、	JNO    		结果没有溢出则跳转						OF=0
  
  
  9、	JB, JNAE   		小于则跳转 (无符号数)						CF=1
  
  
  10、	JNB, JAE    		大于等于则跳转 (无符号数)						CF=0
  
  
  11、	JBE, JNA    		小于等于则跳转 (无符号数)						CF=1 or ZF=1
  
  
  12、	JNBE, JA    		大于则跳转(无符号数)						CF=0 and ZF=0
  
  
  13、	JL, JNGE    		小于则跳转 (有符号数)						SF≠ OF
  
  
  14、	JNL, JGE    		大于等于则跳转 (有符号数)						SF=OF
  
  
  15、	JLE, JNG    		小于等于则跳转 (有符号数)						ZF=1 or SF≠ OF
  
  
  16、	JNLE, JG    		大于则跳转(有符号数)						ZF=0 and SF=OF
  
  
  ```

###### 堆栈图

- `0x401174`

  ![image](/homework-bas/1.png)

  ![image](/homework-bas/2.png)

- `0x401182`

  ![image](/homework-bas/3.png)

- `0x40118E`

  ![image](/homework-bas/4.png)

### c

- 编写一个函数能够对任意`2`个整数实现加法,并分析函数的反汇编

  ```c
  int Plus1(int x,int y)
  {
      return x+y;
  }
  ```

  ```asm
  0000000000001129 <Plus1>:
      1129:	f3 0f 1e fa          	endbr64
      112d:	55                   	push   rbp
      112e:	48 89 e5             	mov    rbp,rsp
      1131:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi    ;第一个参数
      1134:	89 75 f8             	mov    DWORD PTR [rbp-0x8],esi    ;第二个参数
      1137:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
      113a:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
      113d:	01 d0                	add    eax,edx    ;操作过程
      113f:	5d                   	pop    rbp
      1140:	c3                   	ret
  
  ```

- 编写一个函数，能够对任意`3`个整数实现加法,并分析函数的反汇编

  ```c
  int Plus2(int x,int y,int z)
  {
      return x+y+z;
  }
  ```

  ```asm
  0000000000001129 <Plus2>:
      1129:	f3 0f 1e fa          	endbr64
      112d:	55                   	push   rbp
      112e:	48 89 e5             	mov    rbp,rsp
      1131:	89 7d fc             	mov    DWORD PTR [rbp-0x4],edi    ;第一个参数
      1134:	89 75 f8             	mov    DWORD PTR [rbp-0x8],esi    ;第二个参数
      1137:	89 55 f4             	mov    DWORD PTR [rbp-0xc],edx    ;第三个参数
      113a:	8b 55 fc             	mov    edx,DWORD PTR [rbp-0x4]
      113d:	8b 45 f8             	mov    eax,DWORD PTR [rbp-0x8]
      1140:	01 c2                	add    edx,eax    ;是前两个参数先相加
      1142:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]
      1145:	01 d0                	add    eax,edx    ;之后与第四个参数相加
      1147:	5d                   	pop    rbp
      1148:	c3                   	ret
  
  ```

- 编写一个函数，能够实现对任意`5`个整数实现加法（使用`Plus1`和`Plus2`）并分析一个函数的反汇编代码

  ```c
  int Plus3(int a,int b,int c,int d,int e)
  {
      return Plus2(a,b,c)+Plus1(d,e);
  }
  ```

  ```asm
  0000000000001161 <Plus3>:
      1161:	f3 0f 1e fa          	endbr64
      1165:	55                   	push   rbp
      1166:	48 89 e5             	mov    rbp,rsp
      1169:	53                   	push   rbx
      116a:	48 83 ec 18          	sub    rsp,0x18
      116e:	89 7d f4             	mov    DWORD PTR [rbp-0xc],edi
      1171:	89 75 f0             	mov    DWORD PTR [rbp-0x10],esi
      1174:	89 55 ec             	mov    DWORD PTR [rbp-0x14],edx
      1177:	89 4d e8             	mov    DWORD PTR [rbp-0x18],ecx
      117a:	44 89 45 e4          	mov    DWORD PTR [rbp-0x1c],r8d
      117e:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]    ;参数3
      1181:	8b 4d f0             	mov    ecx,DWORD PTR [rbp-0x10]    ;参数2
      1184:	8b 45 f4             	mov    eax,DWORD PTR [rbp-0xc]    ;参数1
      1187:	89 ce                	mov    esi,ecx
      1189:	89 c7                	mov    edi,eax
      118b:	e8 b1 ff ff ff       	call   1141 <Plus2>    ;调用函数
      1190:	89 c3                	mov    ebx,eax
      1192:	8b 55 e4             	mov    edx,DWORD PTR [rbp-0x1c]
      1195:	8b 45 e8             	mov    eax,DWORD PTR [rbp-0x18]
      1198:	89 d6                	mov    esi,edx    ;参数1
      119a:	89 c7                	mov    edi,eax    ;参数2
      119c:	e8 88 ff ff ff       	call   1129 <Plus1>    ;调用函数
      11a1:	01 d8                	add    eax,ebx
      11a3:	48 8b 5d f8          	mov    rbx,QWORD PTR [rbp-0x8]
      11a7:	c9                   	leave
      11a8:	c3                   	ret
  
  ```


###### 数据类型

- 定义`4`个`int`类型的全局变量，分别是`g_x,g_y,g_z,g_r`，使用`if..else..`分支语句，将最大的值存储到`g_r`中

  ```c
  int g_x = 5;
  int g_y = 4;
  int g_z = 7;
  int g_r = 0;
  
  void Max()
  {
      if (g_x >= g_y && g_x >= g_z) {
          g_r = g_x; // g_x 最大
      } else if (g_y >= g_x && g_y >= g_z) {
          g_r = g_y; // g_y 最大
      } else {
          g_r = g_z; // g_z 最大
      }
  }
  ```

- 找出数组里面最大的值，并存储到全局变量中（`if..esle`）

  ```c
  int arr[4] = {2,5,7,9};
  int g_r;
  
  void ArrMax()
  {
          if (arr[0] >= arr[1] && arr[0] >= arr[2] && arr[0]>=arr[3]) {
          g_r = arr[0]; // arr[0] 最大
      } else if (arr[1] >= arr[0] && arr[1] >= arr[2] && arr[1]>=arr[3]) {
          g_r = arr[1]; // arr[1] 最大
      } else if (arr[2] >= arr[0] && arr[2] >= arr[1] && arr[2]>=arr[3]) {
          g_r = arr[2]; // arr[2] 最大
      } else{
      	g_r = arr[3]; // arr[3] 最大
      }
  }
  ```

- 将数组所有的元素相加，将结果存储到`g_r`中

  ```c
  int arr[10] = {2,5,7,9,22,4,8,22,3,18};
  int g_r;
  
  void ArrMax()
  {
  	for (int i = 0; i < 10; i++) { 
          g_r += arr[i];
      }
  }
  ```

- 俩俩比较数组的值，将最大的一个存储到数组的最后一个位置（要求使用for循环实现）

  ```c
  int arr[10] = {2,7,5,9,22,4,8,22,3,18};
  int g_r;
  
  void ArrMax()
  {
      for (int i = 0; i < 10; i++) { 
          if(g_r <= arr[i]){
              g_r = arr[i];
          }
      }
      arr[9] = g_r;
  }
  ```

- 有一个字符串是这样的：`china中国verygood天朝nice`，里面既含有中文又含义英文，请编写一个函数，能截取任意长度的字符串n（n<=总长度）

  ```c
  char* fn(int n) {
      const char* str = "china中国verygood天朝nice";
      int len = strlen(str); // 获取字符串的总长度
      int count = 0; // 用于计数有效字符数
      int i;
  
      // 为输出字符串分配足够的内存
      char* output = (char*)malloc((n + 1) * sizeof(char));
      if (output == NULL) {
          return NULL; // 内存分配失败
      }
  
      // 遍历原始字符串
      for (i = 0; i < len && count < n; i++) {
          // 判断当前字符是否为中文
          if ((str[i] & 0x80) != 0) { // 如果高位为1，则为中文字符
              // 中文字符占用两个字节
              if (count + 1 < n) {
                  output[count++] = str[i++];
                  output[count++] = str[i]; // 复制中文字符的第二个字节
              }
          } else {
              // 英文字符占用一个字节
              output[count++] = str[i];
          }
      }
  
      // 确保输出字符串以'\0'结尾
      output[count] = '\0';
  
      return output; // 返回输出字符串
  }
  ```


###### if

- ```asm
  00401030   push        ebp							
  00401031   mov         ebp,esp
  00401033   sub         esp,44h							
  00401036   push        ebx							
  00401037   push        esi							
  00401038   push        edi
  00401039   lea         edi,[ebp-44h]							
  0040103C   mov         ecx,11h							
  00401041   mov         eax,0CCCCCCCCh							
  00401046   rep stos    dword ptr [edi]							
  
  00401048   mov         eax,[004225c4]
  0040104D   mov         dword ptr [ebp-4],eax							
  00401050   mov         ecx,dword ptr [ebp+8]							
  00401053   cmp         ecx,dword ptr [ebp+0Ch]							
  00401056   jg          00401064							
  00401058   mov         edx,dword ptr [ebp+0Ch]
  0040105B   add         edx,dword ptr [ebp-4]							
  0040105E   mov         dword ptr [004225c4],edx							
  
  00401064   pop         edi							
  00401065   pop         esi
  00401066   pop         ebx							
  00401067   mov         esp,ebp							
  00401069   pop         ebp							
  0040106A   ret
  ```
  
  函数内部功能分析：
  
  1. 分析参数
  
     ```asm
     [ebp+8]:X
     [ebp+0Ch]:Y
     ```
  
  2. 分析局部变量
  
     ```asm
     [ebp-4]=A=[004225c4]
     ```
  
  3. 分析全局变量
  
     ```asm
     [004225c4] = G
     ```
  
  4. 返回值分析
  
     无
  
  5. 还原成C函数
  
     ```c
     int A = G;
     if (X <= Y)
     {
         G=Y+A;
     }
     return G;
     ```
  
- ```asm
  004010B0   push        ebp
  004010B1   mov         ebp,esp
  004010B3   sub         esp,48h
  004010B6   push        ebx
  004010B7   push        esi
  004010B8   push        edi
  004010B9   lea         edi,[ebp-48h]
  004010BC   mov         ecx,12h
  004010C1   mov         eax,0CCCCCCCCh
  004010C6   rep stos    dword ptr [edi]
  
  004010C8   mov         eax,[004225c4]
  004010CD   mov         dword ptr [ebp-4],eax
  004010D0   mov         dword ptr [ebp-8],2
  004010D7   mov         ecx,dword ptr [ebp+8]
  004010DA   cmp         ecx,dword ptr [ebp+0Ch]
  004010DD   jl          004010e8
  004010DF   mov         edx,dword ptr [ebp-8]
  004010E2   add         edx,1
  004010E5   mov         dword ptr [ebp-8],edx
  004010E8   mov         eax,dword ptr [ebp+8]
  004010EB   cmp         eax,dword ptr [ebp+0Ch]
  004010EE   jge         004010fb
  004010F0   mov         ecx,dword ptr [ebp-8]
  004010F3   mov         dword ptr [004225c4],ecx
  004010F9   jmp         00401107
  
  004010FB   mov         edx,dword ptr [ebp-4]
  004010FE   add         edx,dword ptr [ebp-8]
  00401101   mov         dword ptr [004225c4],edx
  
  00401107   pop         edi
  00401108   pop         esi
  00401109   pop         ebx
  0040110A   mov         esp,ebp
  0040110C   pop         ebp
  0040110D   ret
  ```
  
  函数内部功能分析：
  
  1. 分析参数
  
     ```asm
     [ebp+8]:X
     [ebp+0Ch]:Y
     ```
  
  2. 分析局部变量
  
     ```asm
     [ebp-4]=A=[004225c4]
     [ebp-8]=B=2
     ```
  
  3. 分析全局变量
  
     ```asm
     [004225c4] = G
     ```
  
  4. 返回值分析
  
     无
  
  5. 还原成C函数
  
     ```c
     int A = G;
     int B = 2;
     if(X >= Y)
     {
         B=B+2;
     }else if(X > Y)
     {
         G=B;
     }else
     {
         G=A+B;
     }
     return G;
     ```
  
- ```asm
  004010B0   push        ebp
  004010B1   mov         ebp,esp							
  004010B3   sub         esp,4Ch
  004010B6   push        ebx							
  004010B7   push        esi							
  004010B8   push        edi							
  004010B9   lea         edi,[ebp-4Ch]
  004010BC   mov         ecx,13h							
  004010C1   mov         eax,0CCCCCCCCh							
  004010C6   rep stos    dword ptr [edi]							;init
  
  004010C8   mov         dword ptr [ebp-4],0							
  004010CF   mov         dword ptr [ebp-8],1
  004010D6   mov         dword ptr [ebp-0Ch],2							
  004010DD   mov         eax,dword ptr [ebp+8]							
  004010E0   cmp         eax,dword ptr [ebp+0Ch]							;x < y
  004010E3   jg         004010f0							
  004010E5   mov         ecx,dword ptr [ebp-8]
  004010E8   sub         ecx,1							
  004010EB   mov         dword ptr [ebp-4],ecx							
  004010EE   jmp         00401123							
  
  004010F0   mov         edx,dword ptr [ebp+0Ch]
  004010F3   cmp         edx,dword ptr [ebp+10h]							;Y >= Z
  004010F6   jl          00401103							
  004010F8   mov         eax,dword ptr [ebp-0Ch]							
  004010FB   add         eax,1
  004010FE   mov         dword ptr [ebp-4],eax							
  00401101   jmp         00401123							
  
  00401103   mov         ecx,dword ptr [ebp+8]							
  00401106   cmp         ecx,dword ptr [ebp+10h]							
  00401109   jle         00401116							;X > Z
  0040110B   mov         edx,dword ptr [ebp-8]							
  0040110E   add         edx,dword ptr [ebp-0Ch]							
  00401111   mov         dword ptr [ebp-4],edx							
  00401114   jmp         00401123							
  
  00401116   mov         eax,dword ptr [ebp-0Ch]							
  00401119   mov         ecx,dword ptr [ebp-8]							
  0040111C   lea         edx,[ecx+eax-1]							
  00401120   mov         dword ptr [ebp-4],edx							
  
  00401123   mov         eax,dword ptr [ebp-4]							
  00401126   add         eax,1							
  
  00401129   pop         edi							
  0040112A   pop         esi							
  0040112B   pop         ebx							
  0040112C   mov         esp,ebp							
  0040112E   pop         ebp							
  0040112F   ret	
  ```
  
  函数内部功能分析：
  
  1. 分析参数
  
     ```asm
     [ebp+8]:X
     [ebp+0Ch]:Y
     [ebp+10h]:Z
     ```
  
  2. 分析局部变量
  
     ```asm
     [ebp-4]=A=0
     [ebp-8]=B=1
     [ebp-0Ch]=C=2
     ```
  
  3. 分析全局变量
  
     无
  
  5. 返回值分析
  
     无
  
  6. 还原成C函数
  
     ```c
     int A = 0;
     int B = 1;
     int C = 2;
     if(x < y)
     {
         A=B-1;
     }else if(Y >= Z)
     {
         A=C+1;
     }else if(X > Z)
     {
         A=B+C;
     }else{
         A=C+B+1;
     }
     A++;
     return A;
     ```
     

###### 正向base

- ```c
  #include <stdio.h>
  void HelloWord()			
  {			
  	printf("Hello World");		
  			
  	getchar();		
  }			
  void Fun()			
  {			
  	int arr[5] = {1,2,3,4,5};		
  			
  	arr[6] = (int)HelloWord;	//------------------------------------------------
  			
  }
  
  void main()
  {
  	Fun();
  }
  ```

  跟进代码中标识的那一行，观察栈如下：

  ```
  Fun() line 12
  main() line 19
  mainCRTStartup() line 206 + 25 bytes
  KERNEL32! 768b5d49()
  APP01! 772ccebb()
  APP01! 772cce41()
  ```

  单步执行后的栈如下：

  ```
  Fun() line 14
  1! @ILT+0(_HelloWord) address 0x00401005
  mainCRTStartup() line 206 + 25 bytes
  KERNEL32! 768b5d49()
  APP01! 772ccebb()
  APP01! 772cce41()
  ```

  可以发现这是将函数的返回地址修改了，所以可以调用`HelloWord`函数。

- ```c
  #include <stdio.h>
  void Fun()				
  {				
  	int i;			
  	int arr[5] = {0};			
  				
  	for(i=0;i<=5;i++)			
  	{			
  		arr[i] = 0;		//---------------------------------------------------
  		printf("Hello World!\n");		
  	}			
  }				
  
  void main()
  {
  	Fun();
  }
  ```

  函数在执行到代码中标识的那一行时，如果循环到第5次时会发生数组越界，在`IDA`的堆栈视图中可以清楚的看到：

  ```c
  -000000000000001A                 db ? ; undefined
  -0000000000000019                 db ? ; undefined
  -0000000000000018 arr[0]          dd ?
  -0000000000000014 arr[1]          dd ?
  -0000000000000010 arr[2]          dd ?
  -000000000000000C arr[3]          dd ?
  -0000000000000008 arr[4]          dd ?
  -0000000000000004 i               dd ?//arr[5]
  +0000000000000000  s              db 4 dup(?)
  +0000000000000004  r              db 4 dup(?)
  +0000000000000008
  +0000000000000008 ; end of stack variables
  ```

  重命名之后当`i=5`时`arr[5] = 0`会清空`i`的值，所以会出现无限循环。

###### 循环语句

- 判断数组是否是对称的，如果是返回1，不是返回0

  ```c
  #include <stdio.h>
  
  int arr[5] = {1,2,3,4,5};
  
  int check()
  {
      int i = 0;
      int mid=0;
      int count = sizeof(arr) / sizeof(arr[0]);
  
      mid = count/2;
      while(i<mid)
      {
          if(arr[i]!=arr[count-1])
          {
              return 0;
          }
          i++;
          count--;
      }
      return 1;
  }
  
  int main()
  {
      int x = check();
      printf("%d\n",x);
  }
  ```

- 编写程序实现一个冒泡排序的算法

  ```c
  #include <stdio.h>
  
  int arr[10] = {16, 8, 2, 5, 7, 9, 0, 1, 6, 3};
  
  void order() {
      int count = sizeof(arr) / sizeof(arr[0]);
      int temp;
  
      for (int i = 0; i < count - 1; i++) {
          for (int j = 0; j < count - 1 - i; j++) {
              if (arr[j] > arr[j + 1]) {
                  temp = arr[j];
                  arr[j] = arr[j + 1];
                  arr[j + 1] = temp;
              }
          }
      }
  }
  
  int main() {
      order();
      for (int i = 0; i < 10; i++) {
          printf("%d\n", arr[i]);
      }
      return 0;
  }
  ```

###### 参数-返回值-数组

- 返回值超过32位时，存在哪里？用`long long(__int64)`类型做实验

  `long long`类型在`VC6`中对应的是`__int64`

  ```c
  __int64 Function()
  {
      __int64 x = 0x1234567890;
      return x;
  }
  ```

  查看反汇编可以看到，当返回值超过32位时，会使用多个寄存器将结果返回：

  ```asm
  6:        __int64 x = 0x1234567890;
  00401038   mov         dword ptr [ebp-8],34567890h
  0040103F   mov         dword ptr [ebp-4],12h
  7:        return x;
  00401046   mov         eax,dword ptr [ebp-8]
  00401049   mov         edx,dword ptr [ebp-4]
  ```

- `char arr[3] = {1,2,3};`与 `char arr[4] = {1,2,3,4};`哪个更节省空间，从反汇编的角度来说明你的观点

  根据反汇编，其实都是一个地址空间存储了一个数字：

  ```asm
  8:        char arr0[3] = {1,2,3};
  00401028   mov         byte ptr [ebp-4],1
  0040102C   mov         byte ptr [ebp-3],2
  00401030   mov         byte ptr [ebp-2],3
  9:        char arr1[4] = {1,2,3,4};
  00401034   mov         byte ptr [ebp-8],1
  00401038   mov         byte ptr [ebp-7],2
  0040103C   mov         byte ptr [ebp-6],3
  00401040   mov         byte ptr [ebp-5],4
  ```

  不过观察内存可以发现，在地址`0x19FF2F`处被对齐了，也就是被浪费了：

  ```asm
  0019FF28  01 02 03 04 01 02 03  .......
  0019FF2F  CC 70 FF 19 00 49 11  蘰...I.
  0019FF36  40 00 01 00 00 00 A8  @......
  ```

- 找出下面赋值过程的反汇编代码

  ```C
  void Function()
  {
      int x = 1;
      int y = 2;
      int r;
      int arr[10] = {1,2,3,4,5,6,7,8,9,10};
      
      r = arr[1];
      r = arr[x];
      r = arr[x+y];
      r = arr[x*2+y];
  }
  ```

  抬栈的是`00401023   sub         esp,74h`，因为需要存13个参数，每个参数大小为4，所以为`13*4=34h`，加上要分配的`40h`，就是`74h`了。

  ```asm
  10:       r = arr[1];
  0040108C   mov         eax,dword ptr [ebp-30h]
  0040108F   mov         dword ptr [ebp-0Ch],eax
  11:       r = arr[x];
  00401092   mov         ecx,dword ptr [ebp-4]
  00401095   mov         edx,dword ptr [ebp+ecx*4-34h]    ;ecx*4相当于数组向后索引的偏移
  00401099   mov         dword ptr [ebp-0Ch],edx
  12:       r = arr[x+y];
  0040109C   mov         eax,dword ptr [ebp-4]
  0040109F   add         eax,dword ptr [ebp-8]
  004010A2   mov         ecx,dword ptr [ebp+eax*4-34h]
  004010A6   mov         dword ptr [ebp-0Ch],ecx
  13:       r = arr[x*2+y];
  004010A9   mov         edx,dword ptr [ebp-4]
  004010AC   mov         eax,dword ptr [ebp-8]
  004010AF   lea         ecx,[eax+edx*2]
  004010B2   mov         edx,dword ptr [ebp+ecx*4-34h]
  004010B6   mov         dword ptr [ebp-0Ch],edx
  14:   }
  ```

- 桶排序

  ```c
  #include <stdio.h>
  
  int arr[10] = {1,5,3,8,6,3,7,2,6,3};
  int ret[10] = {0};
  
  int order()
  {
      int count = sizeof(arr) / sizeof(arr[0]);
  	int t;
  	int j=0;
  	int i=0;
      for(;i < count;i++){
          ret[arr[i]]++;
      }
      for(;j < count;j++){
          if(ret[j]>0)
  		{
  			t=ret[j];
  			while(t>0)
  			{
  				printf("%d ",j);
  				t--;
  			}
  		}
      }
  }
  
  
  void main()
  {
      order();
  }
  ```
  

###### 多维数组

- 假设现在有5个班，每个班10个人，设计一个二维数组存储这些人的年龄

  ```c
  int arr[5][10] = {0};
  int i = 0;
  int j = 0;
  for(;i<5;i++)
  {
      for(;j<10;j++)
      {
          printf("[%d][%d]:",i+1,j+1);
          scanf("%d",arr[i][j]);
      }
  }
  ```

- 如果想知道第二个班的第6个人的年龄，应该如何获取？编译器该如何获取？

  ```c
  int memb = 0;
  memb = arr[1][5];
  =====================================================================
  arr[1*10+5*1]
  ```

- 打印所有班级，所有学生的年龄（每个班级打印一行）

  ```c
  int i = 0;
  int j = 0;
  for(;i<5;i++)
  {
      for(;j<10;j++)
      {
          printf("[%d][%d]:%d    ",i+1,j+1,arr[i][j]);
      }
      printf("\n");
  }
  ```

- 将第二个班级的超过20岁的学生的年龄修改为21岁

  ```c
  int j = 0;
  for(;j<10;j++)
  {
      if(arr[1][j]>20)
      {
          arr[1][j]=21;
      }
  }
  ```

- 打印出每个班级学生的年龄的和

  ```c
  int i = 0;
  int j = 0;
  int fin = 0;
  for(;i<5;i++)
  {
      fin=0;
      for(;j<10;j++)
      {
          fin+=arr[i][j];
      }
      printf("%d:%d\n",i+1,fin);
  }
  ```

- 数组一：`[3,5,7,9,12,25,34,55]`

  数组二：`[4,7,9,11,13,16]`

  将两个数组中所有数据进行从小到大的排序，存储到另一个数组中

  ```c
  int arr1[8] = [3,5,7,9,12,25,34,55];
  int arr2[6] = [4,7,9,11,13,16];
  int ret[14] = {0};
  int i = 0;
  int j = 0;
  int k = 0;
  
  while(i<8)
  {
      while(j<6)
      {
          if(arr1[i]<arr2[j])
          {
              ret[k] = arr1[i];
              k++;
              break;
          } else{
              ret[k] = arr2[j];
              k++;
          }
          j++;
      }
      i++;
  }
  //应该是这样吧
  ```

###### 结构体

- 定义一个结构体`Gamer`用来存储一个游戏中的角色的信息，包括血值、等级、坐标等信息

  要求：

  1. 具体包含哪些信息自由设计
  2. 但这些包含的类型中，必须要有一个成员是结构体类型

  ```c
  struct feature
  {
      int i
  }
  struct Gamer
  {
      short blood;
      short grade;
      int x;
      int y;
      feature fea
  }
  ```

- 定义一个函数，用来给这个结构体变量赋值

  ```c
  void function()
  {
      Gamer.blood = 100;
      Gamer.grade = 1;
      Gamer.x = 1000;
      Gamer.y = 1000;
      Gamer.fea.i = 0;
  }
  ```

- 定义一个函数，用来显示这个结构体变量的所有成员信息

  ```c
  void function()
  {
      printf("%d",Gamer.blood);
      printf("%d",Gamer.grade);
      printf("%d",Gamer.x);
      printf("%d",Gamer.y);
      printf("%d",Gamer.feature.i);
  }
  ```

###### 结构体数组

- 定义一个结构体`Monster`，能够存储怪的各种信息（至少有一个成员是结构体类型）

  ```c
  struct S1		
  {		
  	char c;	
  	double i;	
  };
  
  struct Monster		
  {		
  	int ID;	
  	double blood;
      int x;
      int y;
      S1 s;
  };
  ```

- 声明一个`Monster`类型的数组，长度为10

  ```c
  Monster arr[10];
  ```

- 编写一个函数，为第二题中的数组赋值

  ```c
  void fun1()
  {
      arr[0].ID = 1145;
      arr[0].blood = 1000;
      arr[0].x = 100;
      arr[0].y = 10;
      arr[0].s.c = 1;
      arr[0].s.i = 90;
  }
  ```

- 编写一个函数，能够通过怪物`ID`，打印当前这个怪物的所有信息

  ```c
  int i = 0;
  while(i<10)
  {
      if(arr[i].ID==1145)
      {
          print("%d\n",arr[i].blood);
          print("%d\n",arr[i].x);
          print("%d\n",arr[i].y);
          print("%d\n",arr[i].s.c);
          print("%d\n",arr[i].s.i);
      }
      i++;
  }
  ```

- 分析下面结构体的内存分配：

  ```c
  struct S1		
  {		
  	char c;	
  	double i;	
  };
  
  struct S3		
  {		
  	char c1; 	
  	S1 s;    	
  	char c2; 	
  	char c3; 	
  };		
  
  struct S4		
  {		
  	char c1; 	
  	S1 s;    	
  	char c2; 	
  	double c3; 	
  };		
  
  struct S5		
  {		
  	int c1; 	
  	char c2[10]; 	
  };		
  ```

  ```
  S1:
  c 0 0 0
  i i i i
  
  S3:
  c1 0 0 0
  c 0 0 0
  i i i i
  c2 c3 0 0
  
  S4:
  c1 0 0 0
  c 0 0 0
  i i i i
  c2 0 0 0
  c3 c3 c3 c3
  
  S5:
  c1 c1 0 0
  c2 c2 c2 c2
  c2 c2 c2 c2
  c2 c2 0 0    //默认8对齐
  ```


###### Switch

- 写一个switch语句，不生产大表也不生产小表，贴出对应的反汇编

  ```c
  #include <stdio.h>
  #include <string.h>
  
  void fun(x)
  {
  	switch(x)
  	{
  	case 1:
  		printf("1\n");
  	case 2:
  		printf("2\n");
  	case 3:
  		printf("3\n");
  	}
  }
  
  void main()
  {
  	fun(2);
  }
  ```

  ```asm
  6:        switch(x)
  7:        {
  00401038   mov         eax,dword ptr [ebp+8]
  0040103B   mov         dword ptr [ebp-4],eax
  0040103E   cmp         dword ptr [ebp-4],1
  00401042   je          fun+32h (00401052)
  00401044   cmp         dword ptr [ebp-4],2
  00401048   je          fun+3Fh (0040105f)
  0040104A   cmp         dword ptr [ebp-4],3
  0040104E   je          fun+4Ch (0040106c)
  00401050   jmp         fun+59h (00401079)
  8:        case 1:
  9:            printf("1\n");
  00401052   push        offset string "1\n" (00422024)
  00401057   call        printf (004010f0)
  0040105C   add         esp,4
  10:       case 2:
  11:           printf("2\n");
  0040105F   push        offset string "2\n" (00422020)
  00401064   call        printf (004010f0)
  00401069   add         esp,4
  12:       case 3:
  13:           printf("3\n");
  0040106C   push        offset string "3\n" (0042201c)
  00401071   call        printf (004010f0)
  00401076   add         esp,4
  14:
  15:       }
  16:   }
  ```

- 写一个switch语句，只生成大表，贴出对应的反汇编

  ```c
  #include <stdio.h>
  #include <string.h>
  
  void fun(x)
  {
  	switch(x)
  	{
  	case 1:
  		printf("1\n");
  	case 2:
  		printf("2\n");
  	case 3:
  		printf("3\n");
  	case 4:
  		printf("4\n");
  	case 5:
  		printf("5\n");
  	case 6:
  		printf("6\n");
  	case 7:
  		printf("7\n");
  	case 8:
  		printf("8\n");
  	case 9:
  		printf("9\n");
  	}
  }
  
  void main()
  {
  	fun(2);
  }
  ```

  ```asm
  6:        switch(x)
  7:        {
  00401038   mov         eax,dword ptr [ebp+8]
  0040103B   mov         dword ptr [ebp-4],eax
  0040103E   mov         ecx,dword ptr [ebp-4]
  00401041   sub         ecx,1
  00401044   mov         dword ptr [ebp-4],ecx
  00401047   cmp         dword ptr [ebp-4],8
  0040104B   ja          $L622+0Dh (004010cc)
  0040104D   mov         edx,dword ptr [ebp-4]
  00401050   jmp         dword ptr [edx*4+4010DDh]
  8:        case 1:
  9:            printf("1\n");
  00401057   push        offset string "1\n" (0042203c)
  0040105C   call        printf (00401180)
  00401061   add         esp,4
  10:       case 2:
  11:           printf("2\n");
  00401064   push        offset string "2\n" (00422038)
  00401069   call        printf (00401180)
  0040106E   add         esp,4
  12:       case 3:
  13:           printf("3\n");
  00401071   push        offset string "3\n" (00422034)
  00401076   call        printf (00401180)
  0040107B   add         esp,4
  14:       case 4:
  15:           printf("4\n");
  0040107E   push        offset string "4\n" (00422030)
  00401083   call        printf (00401180)
  00401088   add         esp,4
  16:       case 5:
  17:           printf("5\n");
  0040108B   push        offset string "5\n" (0042202c)
  00401090   call        printf (00401180)
  00401095   add         esp,4
  18:       case 6:
  19:           printf("6\n");
  00401098   push        offset string "6\n" (00422028)
  0040109D   call        printf (00401180)
  004010A2   add         esp,4
  20:       case 7:
  21:           printf("7\n");
  004010A5   push        offset string "7\n" (00422024)
  004010AA   call        printf (00401180)
  004010AF   add         esp,4
  22:       case 8:
  23:           printf("8\n");
  004010B2   push        offset string "8\n" (00422020)
  004010B7   call        printf (00401180)
  004010BC   add         esp,4
  24:       case 9:
  25:           printf("9\n");
  004010BF   push        offset string "9\n" (0042201c)
  004010C4   call        printf (00401180)
  004010C9   add         esp,4
  26:       }
  27:   }
  ```

  ```asm
  004010DD  57 10 40 00  W.@.    ;1
  004010E1  64 10 40 00  d.@.    ;2
  004010E5  71 10 40 00  q.@.    ;3
  004010E9  7E 10 40 00  ~.@.    ;4
  004010ED  8B 10 40 00  ..@.    ;5
  004010F1  98 10 40 00  ..@.    ;6
  004010F5  A5 10 40 00  ..@.    ;7
  004010F9  B2 10 40 00  ..@.    ;8
  004010FD  BF 10 40 00  ..@.    ;9
  ```

- 写一个switch语句，生成大表和小表，贴出对应的反汇编

  ```c
  #include <stdio.h>
  #include <string.h>
  
  void fun(x)
  {
  	switch(x)
  	{
  	case 1:
  		printf("1\n");
  		break;
  	case 2:
  		printf("2\n");
  		break;
  	case 50:
  		printf("50\n");
  		break;
  	case 60:
  		printf("60\n");
  		break;
  	}
  }
  
  void main()
  {
  	fun(2);
  }
  ```

  ```asm
  6:        switch(x)
  7:        {
  00401038   mov         eax,dword ptr [ebp+8]
  0040103B   mov         dword ptr [ebp-4],eax
  0040103E   mov         ecx,dword ptr [ebp-4]
  00401041   sub         ecx,1
  00401044   mov         dword ptr [ebp-4],ecx
  00401047   cmp         dword ptr [ebp-4],3Bh
  0040104B   ja          $L612+0Dh (00401099)
  0040104D   mov         eax,dword ptr [ebp-4]
  00401050   xor         edx,edx
  00401052   mov         dl,byte ptr  (004010be)[eax]
  00401058   jmp         dword ptr [edx*4+4010AAh]
  8:        case 1:
  9:            printf("1\n");
  0040105F   push        offset string "1\n" (00422028)
  00401064   call        printf (00401170)
  00401069   add         esp,4
  10:           break;
  0040106C   jmp         $L612+0Dh (00401099)
  11:       case 2:
  12:           printf("2\n");
  0040106E   push        offset string "2\n" (00422024)
  00401073   call        printf (00401170)
  00401078   add         esp,4
  13:           break;
  0040107B   jmp         $L612+0Dh (00401099)
  14:       case 50:
  15:           printf("50\n");
  0040107D   push        offset string "50\n" (00422020)
  00401082   call        printf (00401170)
  00401087   add         esp,4
  16:           break;
  0040108A   jmp         $L612+0Dh (00401099)
  17:       case 60:
  18:           printf("60\n");
  0040108C   push        offset string "60\n" (0042201c)
  00401091   call        printf (00401170)
  00401096   add         esp,4
  19:           break;
  20:       }
  21:   }
  
  ```

  ```asm
  004010AA  5F 10 40 00  _.@.
  004010AE  6E 10 40 00  n.@.
  004010B2  7D 10 40 00  }.@.
  004010B6  8C 10 40 00  ..@.
  004010BA  99 10 40 00  ..@.
  004010BE  00 01 04 04  ....
  004010C2  04 04 04 04  ....
  004010C6  04 04 04 04  ....
  004010CA  04 04 04 04  ....
  004010CE  04 04 04 04  ....
  004010D2  04 04 04 04  ....
  004010D6  04 04 04 04  ....
  004010DA  04 04 04 04  ....
  004010DE  04 04 04 04  ....
  004010E2  04 04 04 04  ....
  004010E6  04 04 04 04  ....
  004010EA  04 04 04 04  ....
  004010EE  04 02 04 04  ....
  004010F2  04 04 04 04  ....
  004010F6  04 04 04 03  ....
  ```

- 为do..while语句生成的反汇编填写注释

  ```c
  #include <stdio.h>
  #include <string.h>
  
  void fun(x)
  {
      do
      {
          x++;
      }
      while(x>20);
  }
  
  void main()
  {
  	fun(2);
  }
  ```

  ```asm
  6:        do
  7:        {
  8:            x++;
  00401038   mov         eax,dword ptr [ebp+8];将参数传给eax
  0040103B   add         eax,1
  0040103E   mov         dword ptr [ebp+8],eax;x++操作
  9:        }
  10:       while(x>20);
  00401041   cmp         dword ptr [ebp+8],14h;参数与14h=20比较
  00401045   jg          fun+18h (00401038);大于就跳转，就是跳出了
  11:   }
  
  ```

- 为while语句生成的反汇编填写注释

  ```c
  #include <stdio.h>
  #include <string.h>
  
  void fun(x)
  {
  
      while(x<20)
      {
          printf("%d\n",x);
          x++;
      }
  }
  
  void main()
  {
  	fun(2);
  }
  ```

  ```asm
  6:
  7:        while(x>20)
  00401038   cmp         dword ptr [ebp+8],14h;首先与20进行比较
  0040103C   jge         fun+3Ah (0040105a);大于等于就跳转，相当于跳出循环
  8:        {
  9:            printf("%d\n",x);
  0040103E   mov         eax,dword ptr [ebp+8]
  00401041   push        eax
  00401042   push        offset string "%d\n" (0042201c)
  00401047   call        printf (004010c0)
  0040104C   add         esp,8;将参数打印的操作
  10:           x++;
  0040104F   mov         ecx,dword ptr [ebp+8]
  00401052   add         ecx,1
  00401055   mov         dword ptr [ebp+8],ecx;将参数自增1的操作
  11:       }
  00401058   jmp         fun+18h (00401038);回到循环的开始
  12:   }
  
  ```

- 为for语句生成的反汇编填写注释

  ```c
  #include <stdio.h>
  #include <string.h>
  
  void fun(x)
  {
  	int i = 0;
      for(;i<20;i++)
      {
          printf("%d\n",x);
          x++;
      }
  }
  
  void main()
  {
  	fun(2);
  }
  ```

  ```asm
  7:        for(;i>20;i++)
  0040103F   jmp         fun+2Ah (0040104a)
  00401041   mov         eax,dword ptr [ebp-4]
  00401044   add         eax,1;i++操作
  00401047   mov         dword ptr [ebp-4],eax
  0040104A   cmp         dword ptr [ebp-4],14h;首次开始执行的地方
  0040104E   jge         fun+4Ch (0040106c);大于等于就跳转，相当于跳出循环了
  8:        {
  9:            printf("%d\n",x);
  00401050   mov         ecx,dword ptr [ebp+8]
  00401053   push        ecx
  00401054   push        offset string "%d\n" (0042201c)
  00401059   call        printf (004010e0)
  0040105E   add         esp,8;自己定义的打印操作
  10:           x++;
  00401061   mov         edx,dword ptr [ebp+8]
  00401064   add         edx,1
  00401067   mov         dword ptr [ebp+8],edx;x++操作
  11:       }
  0040106A   jmp         fun+21h (00401041);跳到i++的地方了
  12:   }
  ```


###### 指针

- `char`类型占几字节？`char*`类型占几字节？`int*****`占几字节？

  ```c
  char占1个字节，char*占4个字节，int*****占4个字节
  ```

- `char** arr[10]`占多少个字节？

  ```
  前面char**是4个字节，后面有10项，所以是40个字节
  ```

- 自定义结构体如下：

  ```c
  struct Student
  {
      int x;
      int y;
  };
  ```

  第一步：

  ```c
  Student**** s;
  s = (Student****)100;
  s++;		//s的值是多少？	104
  			
  s = s+2;		//s的值是多少？	112
  			
  s = s-3;		//s的值是多少？	100
  ```

  第二步：

  ```c
  Student**** s1;				
  Student**** s2;				
  int x;				
  				
  s1 = (Student****)200;				
  				
  s2 = (Student****)100;				
  				
  x = s1-s2;		//x的值是多少？		25
  ```

  第三步：

  ```c
  Student* s;				
  				
  s = (Student*)100;				
  				
  s++;		//s的值是多少？		108
  				
  s = s+2;		//s的值是多少？		124
  				
  s = s-3;		//s的值是多少？		100
  ```

  第四步：

  ```c
  Student* s1;			
  Student* s2;			
  int x;			
  			
  s1 = (Student*)200;			
  			
  s2 = (Student*)100;			
  			
  x = s1-s2;		//x的值是多少？	12
  ```

- 列出每一行的反汇编代码：

  ```c
  char a = 10;		
  short b = 20;		
  int c = 30;		
  		
  char* pa = &a;		
  short* pb = &b;		
  int* pc = &c;		
  		
  char** ppa = &pa;		
  short** ppb = &pb;		
  int** ppc = &pc;		
  ```

  ```asm
  12:       char* pa = &a;
  00401039   lea         eax,[ebp-4]
  0040103C   mov         dword ptr [ebp-10h],eax
  13:       short* pb = &b;
  0040103F   lea         ecx,[ebp-8]
  00401042   mov         dword ptr [ebp-14h],ecx
  14:       int* pc = &c;
  00401045   lea         edx,[ebp-0Ch]
  00401048   mov         dword ptr [ebp-18h],edx
  15:
  16:
  17:
  18:       char** ppa = &pa;
  0040104B   lea         eax,[ebp-10h]
  0040104E   mov         dword ptr [ebp-1Ch],eax
  19:       short** ppb = &pb;
  00401051   lea         ecx,[ebp-14h]
  00401054   mov         dword ptr [ebp-20h],ecx
  20:       int** ppc = &pc;
  00401057   lea         edx,[ebp-18h]
  0040105A   mov         dword ptr [ebp-24h],edx
  
  ```

- 列出每一行的反汇编代码：

  ```c
  int p = 10;		
  		
  int******* p7;		
  int****** p6;		
  int***** p5;		
  int**** p4;		
  int*** p3;		
  int** p2;		
  int* p1;		
  		
  p1 = &p;		
  p2 = &p1;		
  p3 = &p2;		
  p4 = &p3;		
  p5 = &p4;		
  p6 = &p5;		
  p7 = &p6;		
  ```

  ```asm
  16:       p1 = &p;
  0040102F   lea         eax,[ebp-4]
  00401032   mov         dword ptr [ebp-20h],eax
  17:       p2 = &p1;
  00401035   lea         ecx,[ebp-20h]
  00401038   mov         dword ptr [ebp-1Ch],ecx
  18:       p3 = &p2;
  0040103B   lea         edx,[ebp-1Ch]
  0040103E   mov         dword ptr [ebp-18h],edx
  19:       p4 = &p3;
  00401041   lea         eax,[ebp-18h]
  00401044   mov         dword ptr [ebp-14h],eax
  20:       p5 = &p4;
  00401047   lea         ecx,[ebp-14h]
  0040104A   mov         dword ptr [ebp-10h],ecx
  21:       p6 = &p5;
  0040104D   lea         edx,[ebp-10h]
  00401050   mov         dword ptr [ebp-0Ch],edx
  22:       p7 = &p6;
  00401053   lea         eax,[ebp-0Ch]
  00401056   mov         dword ptr [ebp-8],eax
  
  ```

- 完成代码，实现数组值的互换

  ```c
  void Function()					
  {					
  	int arr[5] = {1,2,3,4,5};				
  					
  	//..此处添加代码，使用指针，将数组的值倒置				
  					
  	//打印数组值的代码已经写完，不需要修改				
  	for(int k=0;k<5;k++)				
  	{				
  		printf("%d\n",*(p+k));			
  	}				
  					
  }					
  ```

  ```c
  void Function()					
  {					
  	int arr[5] = {1,2,3,4,5};				
      int *p = arr; 
      int k=0;
      int i = 0;
      int t;
      
      for (i = 0; i < 5 / 2; i++) 
      {
          t = *(p + i);
          *(p + i) = *(p + 4 - i);
          *(p + 4 - i) = t;
      }
  	for(;k<5;k++)				
  	{				
  		printf("%d\n",*(p+k));			
  	}				
  					
  }	
  ```

- 模拟实现CE的数据搜索功能：

  这一堆数据中存储了角色的血值信息，假设血值的类型为`int`类型，值为100（10进制），请列出所有可能的值以及该值对应的地址

  ```c
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
  0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
  0x00,0x33,0x00,0x47,0x0C,0x0E,0x00,0x0D,0x00,0x11,					
  0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
  0x00,0x00,0x64,0x10,0x00,0x00,0x00,0x00,0x00,0x00,					
  0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
  0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
  0x00,0x02,0x74,0x0F,0x41,0x00,0x06,0x08,0x00,0x00,					
  0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
  0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00					
  ```

  ```c
  char arr[100] = {
      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
  	0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
  	0x00,0x33,0x00,0x47,0x0C,0x0E,0x00,0x0D,0x00,0x11,					
  	0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
  	0x00,0x00,0x64,0x10,0x00,0x00,0x00,0x00,0x00,0x00,					
  	0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
  	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
  	0x00,0x02,0x74,0x0F,0x41,0x00,0x06,0x08,0x00,0x00,					
  	0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
  	0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00	
  };
  
  void findaddr(int num)
  {
      char* start = arr;
      int i = 0;
      int*  pt = (int*)start;
      while(i<100)
      {
          if(*pt==num)
          {
              printf("[%x]=%d\n", start, *pt);
          }
          i++; 
          start++;
          pt = (int*)start;
      }
  }
  
  void main()
  {
      findaddr(0x64);
  }
  ```

- 模拟实现CE的数据搜索功能：

  这一堆数据中存储了角色的名字信息（`WOW`），请列出角色名的内存地址

  ```c
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
  0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
  0x00,0x33,0x00,0x47,0x0C,0x0E,0x00,0x0D,0x00,0x11,					
  0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
  0x00,0x00,0x64,0x10,0x00,0x00,0x00,0x00,0x00,0x00,					
  0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
  0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
  0x00,0x02,0x57,0x4F,0x57,0x00,0x06,0x08,0x00,0x00,					
  0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
  0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00					
  ```

  ```c
  #include <stdio.h>
  char arr[100] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x09,
      0x00, 0x20, 0x10, 0x03, 0x03, 0x0C, 0x00, 0x00, 0x44, 0x00,
      0x00, 0x33, 0x00, 0x47, 0x0C, 0x0E, 0x00, 0x0D, 0x00, 0x11,
      0x00, 0x00, 0x00, 0x02, 0x64, 0x00, 0x00, 0x00, 0xAA, 0x00,
      0x00, 0x00, 0x64, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x02, 0x00, 0x74, 0x0F, 0x41, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00,
      0x00, 0x02, 0x57, 0x4F, 0x57, 0x00, 0x06, 0x08, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x64, 0x00, 0x0F, 0x00, 0x00, 0x0D, 0x00,
      0x00, 0x00, 0x23, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00
  };
  
  
  void Findasc()
  {
  	char* p=arr;
  	char * z="WOW";
  	int* x;
  	int* y;
  	int i=0;
  	for(; i<98; i++)
  	{
  		x=(int*)(p+i);
  		y=(int*)z;
  		if (*(p + i) == z[0] && *(p + i + 1) == z[1] && *(p + i + 2) == z[2])
  			printf("%x == %s",x,y);
  	}
  }
  
  void main()
  {
      Findasc();
  }
  ```

- 编写函数，返回角色名字信息的地址，如果没有返回0

  ```c
  char* FindRoleNameAddr(char* pData,char* pRoleName)
  {
      size_t nameLength = strlen(pRoleName);
      for (char* ptr = pData; *ptr != '\0'; ptr++) {
          if (strncmp(ptr, pRoleName, nameLength) == 0) {
              return ptr; 
          }else return 0;
      }
  }
  ```

- 编写函数，遍历上面数据中所有角色名字

  ```c
  #include <stdio.h>
  
  char arr[100] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x07, 0x09,
      0x00, 0x20, 0x10, 0x03, 0x03, 0x0C, 0x00, 0x00, 0x44, 0x00,
      0x00, 0x33, 0x00, 0x47, 0x0C, 0x0E, 0x00, 0x0D, 0x00, 0x11,
      0x00, 0x00, 0x00, 0x02, 0x64, 0x00, 0x00, 0x00, 0xAA, 0x00,
      0x00, 0x00, 0x64, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x02, 0x00, 0x74, 0x0F, 0x41, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00,
      0x00, 0x02, 0x57, 0x4F, 0x57, 0x00, 0x06, 0x08, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x64, 0x00, 0x0F, 0x00, 0x00, 0x0D, 0x00,
      0x00, 0x00, 0x23, 0x00, 0x00, 0x64, 0x00, 0x00, 0x64, 0x00
  };
  
  void FindAllRoleNames(char* pData) {
      char* start = pData;
      char name[50]; 
      int i = 0;
  
      while (i < 100) {
          if (*(start + i) != 0) {
              int j = 0;
              while (i < 100 && *(start + i) != 0) {
                  name[j++] = *(start + i);
                  i++;
              }
              name[j] = '\0'; 
              printf("name: %s\n", name);
          }
          i++;
      }
  }
  
  int main() {
      FindAllRoleNames(arr); 
      return 0;
  }
  ```

- 创建一个`int* arr[5]`数组，并为数组赋值（使用&）

  ```c
  int a1 = 1;	
  int a2 = 2;	
  int a3 = 3;	
  int a4 = 4;	
  int a5 = 5;	
  	
  int* p1 = &a1;	
  int* p2 = &a2;	
  int* p3 = &a3;	
  int* p4 = &a4;	
  int* p5 = &a5;	
  int* arr[5] = {p1,p2,p3,p4,p5};
  
  for (int i = 0; i < 5; i++) {
  	printf("arr[%d] = %d\n", i, *arr[i]);
  }
  ```

- 创建一个字符指针数组，存储所有的`C`的关键词（查资料找），并全部打印出来

  ```c
  #include <stdio.h>
  
  int main() {
      char* a1 = "auto";
      char* a2 = "break";
      char* a3 = "case";
      char* a4 = "char";
      char* a5 = "const";
      char* a6 = "continue";
      char* a7 = "default";
      char* a8 = "do";
      char* a9 = "double";
      char* a10 = "else";
      char* a11 = "enum";
      char* a12 = "extern";
      char* a13 = "float";
      char* a14 = "for";
      char* a15 = "goto";
      char* a16 = "if";
      char* a17 = "int";
      char* a18 = "long";
      char* a19 = "register";
      char* a20 = "restrict";
      char* a21 = "return";
      char* a22 = "short";
      char* a23 = "signed";
      char* a24 = "sizeof";
      char* a25 = "static";
      char* a26 = "struct";
      char* a27 = "switch";
      char* a28 = "typedef";
      char* a29 = "union";
      char* a30 = "unsigned";
      char* a31 = "void";
      char* a32 = "volatile";
      char* a33 = "while";
      char* a34 = "_Alignas";
      char* a35 = "_Alignof";
      char* a36 = "_Atomic";
      char* a37 = "_Bool";
      char* a38 = "_Complex";
      char* a39 = "_Generic";
      char* a40 = "_Imaginary";
      char* a41 = "_Noreturn";
      char* a42 = "_Static_assert";
      char* a43 = "_Thread_local";
  
      char* sym[] = {
          a1, a2, a3, a4, a5, a6, a7, a8, a9, a10,
          a11, a12, a13, a14, a15, a16, a17, a18, a19, a20,
          a21, a22, a23, a24, a25, a26, a27, a28, a29, a30,
          a31, a32, a33, a34, a35, a36, a37, a38, a39, a40,
          a41, a42, a43
      };
  
      int num_keywords = sizeof(sym) / sizeof(sym[0]);
      for (int i = 0; i < num_keywords; i++) {
          printf("%s\n", sym[i]);
      }
  
      return 0;
  }
  ```

- 查找这些数据中，有几个`id=1 level=8`的结构体信息。

  ```c
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
  0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
  0x00,0x33,0x01,0x00,0x00,0x08,0x00,0x00,0x00,0x00,					
  0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
  0x00,0x00,0x64,0x01,0x00,0x00,0x00,0x08,0x00,0x00,					
  0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
  0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
  0x00,0x02,0x57,0x4F,0x57,0x00,0x06,0x08,0x00,0x00,					
  0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
  0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00					
  					
  结构体定义如下：					
  					
  typedef struct TagPlayer					
  {					
  	int id;				
  	int level;				
  }Player;					
  ```

  ```c
  char arr[] = {
  	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
  	0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
  	0x00,0x33,0x01,0x00,0x00,0x08,0x00,0x00,0x00,0x00,					
  	0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
  	0x00,0x00,0x64,0x01,0x00,0x00,0x00,0x08,0x00,0x00,					
  	0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
  	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
  	0x00,0x02,0x57,0x4F,0x57,0x00,0x06,0x08,0x00,0x00,					
  	0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
  	0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00			
  };
  
  typedef struct TagPlayer					
  {					
  	int id;				
  	int level;				
  }Player;
  
  void Fun()
  {
  	Player* p;
  	p = (Player*)arr;
  	char* q = (char*)p;
  
  	for(int i=0;i<92;i++)
  	{
  		if(p->id == 0x1 && p->level == 0x8)
  		{			
  			printf("%x\n",p);
  		}		
  		q++;
  		p = (Player*)q;
  	}
  }
  
  int main(int argc, char* argv[])
  {
  	Fun();
  	return 0;
  }
  ```

- `*(p+1)[2]`是否一定等于`p[1][2]`呢？ 通过反汇编进行论证。

  ```c
  #include <stdio.h>
  
  int main() {
      {% raw %}
      int arr[3][3] = {{1, 2, 3}, {4, 5, 6}, {7, 8, 9}};
      {% endraw %}
      int (*p)[3] = arr;
  
      printf("*(p+1)[2]: %d\n", *(p+1)[2]);
      printf("p[1][2]: %d\n", p[1][2]);
  
      return 0;
  }
  ```

  ```asm
  差别：
  .text:0000000000001188 ; 15:   printf("*(p+1)[2]: %d\n", (unsigned int)v4[9]);
  
  .text:0000000000001188                 mov     rax, [rbp+var_8]
  
  .text:000000000000118C                 add     rax, 24h ; '$'
  .text:0000000000001190                 mov     eax, [rax]
  
  .text:0000000000001192                 mov     esi, eax
  
  
  .text:00000000000011A8 ; 16:   printf("p[1][2]: %d\n", (unsigned int)v5[5]);
  
  .text:00000000000011A8                 mov     rax, [rbp+var_8]
  
  .text:00000000000011AC                 add     rax, 0Ch
  .text:00000000000011B0                 mov     eax, [rax+8]
  
  .text:00000000000011B3                 mov     esi, eax
  ```

- 使用数组指针遍历一个一维数组

  ```c
  #include <stdio.h>
  
  int main() {
      int arr[] = {1, 2, 3, 4, 5};
      
  
      int *ptr = arr;
  
      for (int i = 0; i < 5; i++) {
          printf("Element %d: %d\n", i, *(ptr + i));
      }
  
      return 0;
  }
  ```

- 将一个函数存储到数据区，通过指针进行访问

  ```c
  #include <stdio.h>
  
  unsigned char arr[] = 
  {
      0x55,
  	0x8B, 0xEC,
  	0x83, 0xEC, 0x40,
  	0x53,
  	0x56,
  	0x57,
  	0x8D, 0x7D, 0xC0,
  	0xB9, 0x10, 0x00, 0x00, 0x00,
  	0xB8, 0xCC, 0xCC, 0xCC, 0xCC,
  	0xF3, 0xAB,
  	0x8B, 0x45, 0x08,
  	0x2B, 0x45, 0x0C,
  	0x5F,
  	0x5E,
  	0x5B,
  	0x8B, 0xE5,
  	0x5D,
  	0xC3
  };
  
  int main() {
      typedef int (*pFun)(int,int);
      pFun p = (int (*)(int ,int ))&arr;
      int x = 0;
  	x = p(9,5);
      printf("%d",x);
      return 0;
  }
  ```
  
- `char`数组内容如下：

  ```c
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x07,0x09,					
  0x00,0x20,0x10,0x03,0x03,0x0C,0x00,0x00,0x44,0x00,					
  0x00,0x33,0x00,0x47,0x0C,0x0E,0x00,0x0D,0x00,0x11,					
  0x00,0x00,0x00,0x02,0x64,0x00,0x00,0x00,0xAA,0x00,					
  0x00,0x00,0x64,0x10,0x00,0x00,0x00,0x00,0x00,0x00,					
  0x00,0x00,0x02,0x00,0x74,0x0F,0x41,0x00,0x00,0x00,					
  0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x0A,0x00,					
  0x00,0x02,0x74,0x0F,0x41,0x00,0x06,0x08,0x00,0x00,					
  0x00,0x00,0x00,0x64,0x00,0x0F,0x00,0x00,0x0D,0x00,					
  0x00,0x00,0x23,0x00,0x00,0x64,0x00,0x00,0x64,0x00					
  					
  不运行说出下面的结果：			指针定义如下：		
  					
  *(*(px+0)+0) => 03020100			int (*px)[2]; 		
  					
  *(*(px+1)+0)			int (*py)[2][3]; 		
  					
  *(*(px+2)+3)			char (*pz)[2];		
  					
  *(*(*(py+1)+2)+3)			char (*pk)[2][3];		
  					
  *(*(pz+2)+3)					
  					
  *(*(*(pk+2)+3)+4)					
  ```

###### 位运算

- 定义一个`unsiged char`类型，通过程序为第3、5、7位赋值，赋值时不能影响到其它位原来的值（使用位操作指令、比如：`& | ! ^ << >>`等）

  ```c
  #include <stdio.h>
  
  int main()
  {
      unsiged char x = 9;
      x = x | (1 << 2);
      x = x | (1 << 4);
      x = x | (1 << 6);
      return 0;
  }
  ```

- 判断某个位的值是否为1（使用位操作指令、比如：`& | ! ^ << >>`等）

  ```c
  int main() {
      unsigned char x = 85;
      int bit = 3;
      
      unsigned char mask = 1 << bit; 
  
      if (x & mask) {
          printf("1");
      } else {
          printf("0");
      }
      return 0;
  }
  ```

- 读取第7、6、5位的值，以十进制显示（`unsigned`）

  ```c
  int main() {
      unsigned char x = 85;
      unsigned char ge = 0;
      unsigned char shi = 0;
      unsigned char bai = 0;
      
      unsigned char mask = 111 << 4; 
      x = x ^ mask;
      ge = x & 1;
      shi = x & (1<<1) >> 1;
      bai = x & (1<<2) >> 2;
      printf("%d",ge+shi*2+bai*4);
      return 0;
  }
  ```

- 用十六进制文本编辑器分别打开一个`.exe  .dll  .sys  .txt  .doc  .jpg  .pdf`等将前四个字节写在下面

  ```asm
  .exe => 4D  5A
  .dll => 4D  5A
  .sys => 4D  5A
  .txt => 00  00
  .doc => 50  4B
  .jpg => FF  D8
  .pdf => 25  50
  ```

- 将一个在十六进制编辑器中打开的`.exe`文件，拖拽到最后，观察文件中的大小和硬盘上的大小

  ```
  相同
  ```


### C++

###### this指针

- 设计一个结构体，有两个`int`类型的成员`X`，`Y`在结构体内部定义`4`个函数分别实现对`XY`的加法、减法、乘法与除法的功能

  ```c++
  struct start
  {
      int X;
      int Y;
      
      int add()
      {
          return this->X + this->Y;
      }
      int sub()
      {
          return this->X - this->Y;
      }
      int mul()
      {
          return this->X * this->Y;
      }
      int div()
      {
          return this->X / this->Y;
      }
  };
  ```

- 观察这些函数调用的时候，与其他的函数调用有哪些不同？从参数传递、压栈顺序、堆栈平衡来总结

  其他的函数调用是通过寄存器或栈传递参数的，而这些则是通过`[rbp-8]`来传递第一个参数

  ```asm
  start::add():
          push    rbp
          mov     rbp, rsp
          mov     QWORD PTR [rbp-8], rdi    ;栈中存储指针，后续解引用操作内存数据
          mov     rax, QWORD PTR [rbp-8]
          mov     edx, DWORD PTR [rax]
          mov     rax, QWORD PTR [rbp-8]
          mov     eax, DWORD PTR [rax+4]
          add     eax, edx
          pop     rbp
          ret
          
   add(int, int):
          push    rbp
          mov     rbp, rsp
          mov     DWORD PTR [rbp-4], edi    ;栈中直接存储整数，直接加载至寄存器进行算术运算
          mov     DWORD PTR [rbp-8], esi
          mov     edx, DWORD PTR [rbp-4]
          mov     eax, DWORD PTR [rbp-8]
          add     eax, edx
          pop     rbp
          ret
  ```

- 结构体的大小是多少？为什么？

  ```c
  8
  ```

- 下面代码能否执行？（√）

  ```c++
  struct Person
  {
      void Fn_1()
  	{
  		printf("Person:Fn_1()\n");
  	}
      void Fn_2()
  	{
  		printf("Person:Fn_2()%x\n");
  	}
  };
  
  int main(int argc, char* argv[])
  {
  
  	Person* p = NULL;
  	p->Fn_1();
  	p->Fn_2();
  
  	return 0;
  }
  ```

- 下面代码能否执行？（×）

  ```c++
  struct Person
  {
  	int x ;
      void Fn_1()
  	{
  		printf("Person:Fn_1()\n");
  	}
      void Fn_2()
  	{
  		x = 10;
  		printf("Person:Fn_2()%x\n");
  	}
  };
  
  int main(int argc, char* argv[])
  {
  	Person* p = NULL;
  
  	p->Fn_1();
  	p->Fn_2();
  
  	return 0;
  }
  ```


###### 构造-析构函数

- 设计一个结构`DateInfo`，要求其满足下述要求。

  1. 有三个成员： `int year; int month; int day;`
  2. 要求有个带参数的构造函数，其参数分别为对应年、月、日。
  3. 有一个无参数的构造函数，其初始的年、月、日分别为：`2015、4、2`。
  4. 要求有一个成员函数实现日期的设置：`SetDay(int day)`
  5. 要求有一个成员函数实现日期的获取：`GetDay()`
  6. 要求有一个成员函数实现年份的设置：`SetYear(int year)`
  7. 要求有一个成员函数实现年份的获取：`GetYear()`
  8. 要求有一个成员函数实现月份的设置：`SetMonth(int month)`
  9. 要求有一个成员函数实现月份的获取：`GetMonth()`

  ```c++
  struct DateInfo
  {
      int year;
      int month;
      int day;
      
      DateInfo(int year,int month,int day)
      {
          this -> year = year;
  		this -> month = month;
  		this -> day = day;
      }
      DateInfo()
      {
          this -> year = 2015;
          this -> month = 4;
          this -> day = 2;
      }
      
      void SetDay(int day)
      {
          this -> day = day;
      }
      int GetDay()
      {
          return this -> day;
      }
      
      void SetYear(int year)
      {
          this -> year = year;
      }
      int GetYear()
      {
          return this -> year;
      }
      
      void SetMonth(int month)
      {
          this -> month = month;
      }
      int GetMonth()
      {
          return this -> month;
      }
  }
  ```

- 设计一个结构`TimeInfo`，要求其满足下述要求。

  1. 该结构中包含表示时间的时、分、秒。
  2. 设置该结构中时、分、秒的函数。
  3. 获取该结构中时、分、秒的三个函数：`GetHour()`，`GetMinute()`和`GetSecond()`。

  ```c++
  struct TimeInfo
  {
      int hour;
      int minute;
      int second;
      
      TimeInfo(int hour,int minute,int second)
      {
         this -> hour= hour; 
         this -> minute= minute;
         this -> second= second;
      }
      
      void GetHour()
      {
          return this -> hour;
      }
      void GetMinute()
      {
          return this -> minute;
      }
      void GetSecond()
      {
          return this -> second;
      }
  }
  ```

- 让`TimeInfo`继承`DateInfo`分别使用`DataInfo`和`TimeInfo`的指针访问`TimeInfo`

  ```c++
  struct DateInfo
  {
      int year;
      int month;
      int day;
      
      DateInfo(int year,int month,int day)
      {
          this -> year = year;
  		this -> month = month;
  		this -> day = day;
      }
      DateInfo()
      {
          this -> year = 2015;
          this -> month = 4;
          this -> day = 2;
      }
      
      void SetDay(int day)
      {
          this -> day = day;
      }
      int GetDay()
      {
          return this -> day;
      }
      
      void SetYear(int year)
      {
          this -> year = year;
      }
      int GetYear()
      {
          return this -> year;
      }
      
      void SetMonth(int month)
      {
          this -> month = month;
      }
      int GetMonth()
      {
          return this -> month;
      }
  }
  
  struct TimeInfo:DateInfo
  {
      int hour;
      int minute;
      int second;
      
      TimeInfo(int hour,int minute,int second)
      {
         this -> hour= hour; 
         this -> minute= minute;
         this -> second= second;
      }
      
      void GetHour()
      {
          return this -> hour;
      }
      void GetMinute()
      {
          return this -> minute;
      }
      void GetSecond()
      {
          return this -> second;
      }
  }
  ```

- 设计一个结构叫做`MyString`，要求该结构能够完成以下功能：

  1. 构造函数能够根据实际传入的参数分配实际存储空间；
  2. 提供一个无参的构造函数，默认分配大小为`1024`个字节；
  3. 析构函数释放该空间；
  4. 编写成员函数`SetString`，可以将一个字符串赋值给该结构（申请的空间）；
  5. 编写成员函数`PrintString`，可以将该结构的内容打印到屏幕上；
  6. 编写成员函数`AppendString`，用于向已有的数据后面添加数据；
  7. 编写成员函数`Size`，用于得到当前数据的真实长度。

  编写测试程序，测试这个结构。

  ```c++
  struct MyString
  {
      char* addr;
      MyString(int size)
      {
          addr = (char*)malloc(size);
      }
      MyString()
      {
          addr = (char*)malloc(1024);
      }
      
      ~MyString()
      {
          free(addr);
          addr = NULL;
      }
      
      void SetString(char* addr)
      {
          strcpy(this -> addr,addr);
      }
      void PrintString()
      {
          print("%s",addr);
      }
      void AppendString(char* addr)
      {
          strcat(this -> addr,addr);
      }
      void Size()
      {
          return strlen(this -> addr);
      }
  }
  ```


###### 权限控制

- 将上一节课的所有练习改为`class`实现

  1. 添加`private/public`进行权限控制
  2. 将类的定义与实现分开来写：定义写到`xxx.h`中，函数实现写在`xxx.cpp`中

  ```c++
  //xxx.h
  struct DateInfo
  {
      private:
          int year;
          int month;
          int day;
      
      public:
          DateInfo(int year,int month,int day)
          {
              this -> year = year;
              this -> month = month;
              this -> day = day;
          }
          DateInfo()
          {
              this -> year = 2015;
              this -> month = 4;
              this -> day = 2;
          }
  
          void SetDay(int day)
          int GetDay()
          void SetYear(int year)
          int GetYear()
          void SetMonth(int month)
          int GetMonth()
  }
  
  struct TimeInfo:public DateInfo
  {
      private:
          int hour;
          int minute;
          int second;
      
      public:
          TimeInfo(int hour,int minute,int second)
          {
             this -> hour= hour; 
             this -> minute= minute;
             this -> second= second;
          }
  
          void GetHour()
          void GetMinute()
          void GetSecond()
  }
  ```

  ```c++
  //xxx.cpp
  void DataInfo::SetDay(int day)
  {
      this -> day = day;
  }
  int DataInfo::GetDay()
  {
      return this -> day;
  }
  
  void DataInfo::SetYear(int year)
  {
      this -> year = year;
  }
  int DataInfo::GetYear()
  {
      return this -> year;
  }
  
  void DataInfo::SetMonth(int month)
  {
      this -> month = month;
  }
  int DataInfo::GetMonth()
  {
      return this -> month;
  }
  
  
  void TimeInfo::GetHour()
  {
      return this -> hour;
  }
  void TimeInfo::GetMinute()
  {
      return this -> minute;
  }
  void TimeInfo::GetSecond()
  {
      return this -> second;
  }
  ```

###### 虚函数

```c++
int main()
{
    Sub sub;
    void** vtable = *(void***)&sub;
    printf("base :%p\n",vtable);
    for(int i = 0; i < 9; i++)
    {
        printf("[%d]: %p\n", i, vtable[i]);
    }
    return 0;
}
```

- 单继承无函数覆盖（打印`Sub`对象的虚函数表）

  ```c++
  struct Base
  {
  public:
      virtual void Function_1()
      {
          printf("Base:Function_1...\n");
      }
      virtual void Function_2()
      {
          printf("Base:Function_2...\n");
      }
      virtual void Function_3()
      {
          printf("Base:Function_3...\n");
      }
  };
  struct Sub:Base
  {
  public:
      virtual void Function_4()
      {
          printf("Sub:Function_4...\n");
      }
      virtual void Function_5()
      {
          printf("Sub:Function_5...\n");
      }
      virtual void Function_6()
      {
          printf("Sub:Function_6...\n");
      }
  };
  ```

  ```c++
  base :00007ff77ca73c80
  [0]: 00007ff77ca71a90
  [1]: 00007ff77ca71ab0
  [2]: 00007ff77ca71ad0
  [3]: 00007ff77ca71a30
  [4]: 00007ff77ca71a50
  [5]: 00007ff77ca71a70
  [6]: 0000000000000000
  [7]: 00007ff77ca73b60
  [8]: 00007ff77ca719e0
  ```

- 单继承有函数覆盖（打印`Sub`对象的虚函数表）

  ```c++
  struct Base
  {
  public:
      virtual void Function_1()
      {
          printf("Base:Function_1...\n");
      }
      virtual void Function_2()
      {
          printf("Base:Function_2...\n");
      }
      virtual void Function_3()
      {
          printf("Base:Function_3...\n");
      }
  };
  struct Sub:Base
  {
  public:
      virtual void Function_1()
      {
          printf("Sub:Function_1...\n");
      }
      virtual void Function_2()
      {
          printf("Sub:Function_2...\n");
      }
      virtual void Function_6()
      {
          printf("Sub:Function_6...\n");
      }
  };
  ```

  ```c++
  base :00007ff78c643c60
  [0]: 00007ff78c641a30
  [1]: 00007ff78c641a50
  [2]: 00007ff78c641a90
  [3]: 00007ff78c641a70
  [4]: 0000000000000000
  [5]: 00007ff78c643b40
  [6]: 00007ff78c6419e0
  [7]: 00007ff78c6419b0
  [8]: 00007ff78c641e50
  ```

  似乎继承了重写的虚函数不会出现在虚表中？

###### 动态绑定

- 写一个例子程序，能体现多态的作用

  ```c++
  #include <stdio.h>
  #include <stdlib.h>
  
  class Animal {
  public:
      virtual void makeSound() {
          printf("mo ren\n");
      }
  };
  
  class Dog : public Animal {
  public:
      void makeSound() override {
          printf("wang wang\n");
      }
  };
  
  class Cat : public Animal {
  public:
      void makeSound() override {
          printf("miao miao\n");
      }
  };
  
  int main() {
      Animal* animalPtr;
  
      Dog dog;
      Cat cat;
  
      animalPtr = &dog;
      animalPtr->makeSound(); // 输出 "wang wang"
  
      animalPtr = &cat;
      animalPtr->makeSound(); // 输出 "miao miao"
  
      return 0;
  }
  ```

###### 模板

- 使用模版实现`swap(x,y)`函数，功能：交换`x`，`y`的值

  ```c++
  template<class I>
      
  void swap(I x,I y)
  {
      I temp = x;
      x = y;
      y = temp;
  }
  ```

- 冒泡排序：对结构体或者类进行排序，如果不能实现，找出问题所在

  ```c++
  //正常冒泡排序
  void Sort(int* arr,int nLength)
  {
  	int i;
  	int k;
  	for(i=0;i<nLength-1;i++)
  	{
  		for(k=0;k<nLength-1-i;k++)
  		{
  			if(arr[k]>arr[k+1])
  			{
  				int temp = arr[k];
  				arr[k] = arr[k+1];
  				arr[k+1] = temp;
  			}
  		}
  	}
  }
  ```

  在代码中`if(arr[k]>arr[k+1])`中的`>`号无法对类或结构体进行比较。

- 观察下面两个`Sort`方法的反汇编代码（看内存地址和内容）：

  ```c++
  int arr[] = {2,6,1,5,4};
  char arr1[] = {2,6,1,5,4};
  Sort(arr,5);
  Sort(arr1,5);
  ```

  ```asm
  .text:0000000140001640                 mov     [rbp+var_20], 2
  .text:0000000140001647                 mov     [rbp+var_1C], 6
  .text:000000014000164E                 mov     [rbp+var_18], 1
  .text:0000000140001655                 mov     [rbp+var_14], 5
  .text:000000014000165C                 mov     [rbp+var_10], 4
  .text:0000000140001663                 mov     [rbp+var_25], 5010602h    ;'\x05\x01\x06\x02'
  .text:000000014000166A                 mov     [rbp+var_21], 4
  .text:000000014000166E                 lea     rax, [rbp+var_20]
  .text:0000000140001672                 mov     edx, 5
  .text:0000000140001677                 mov     rcx, rax
  .text:000000014000167A                 call    Sort
  .text:000000014000167F                 lea     rax, [rbp+var_25]
  .text:0000000140001683                 mov     edx, 5
  .text:0000000140001688                 mov     rcx, rax
  .text:000000014000168B                 call    Sort
  .text:0000000140001690                 mov     eax, 0
  .text:0000000140001695                 add     rsp, 50h
  .text:0000000140001699                 pop     rbp
  .text:000000014000169A                 retn
  ```

###### 引用-友元-运算符重载

- 定义一个类，使用友元函数实现：`+、-、*、/、>、<、>=、<=`等运算符重载（什么情况下，一定要用友元函数?）

  ```c++
  class Test
  {
  private:
  	int x;
  	int y;
  public:
  	Test(int x,int y);
      friend Test operator+(const Test& p1, const Test& p2);
      friend Test operator-(const Test& p1, const Test& p2);
      friend Test operator*(const Test& p1, const Test& p2);
      friend Test operator/(const Test& p1, const Test& p2);
      friend bool operator>(const Test& p1, const Test& p2);
      friend bool operator<(const Test& p1, const Test& p2);
      friend bool operator>=(const Test& p1, const Test& p2);
      friend bool operator<=(const Test& p1, const Test& p2);
  };
  
  Test::Test(int x,int y)
  {
      this -> x = x;
      this -> y = y;
  }
  Test operator+(const Test& p1, const Test& p2) {
      return Test(p1.x + p2.x, p1.y + p2.y);
  }
  
  Test operator-(const Test& p1, const Test& p2) {
      return Test(p1.x - p2.x, p1.y - p2.y);
  }
  
  Test operator*(const Test& p1, const Test& p2) {
      return Test(p1.x * p2.x, p1.y * p2.y);
  }
  
  Test operator/(const Test& p1, const Test& p2) {
      if (p2.x == 0 || p2.y == 0) 
      {
          return Test(0, 0);
      }
      return Test(p1.x / p2.x, p1.y / p2.y);
  }
  
  bool operator>(const Test& p1, const Test& p2) {
      return p1.x > p2.x && p1.y > p2.y;
  }
  
  bool operator<(const Test& p1, const Test& p2) {
      return p1.x < p2.x && p1.y < p2.y;
  }
  
  bool operator>=(const Test& p1, const Test& p2) {
      return p1.x >= p2.x && p1.y >= p2.y;
  }
  
  bool operator<=(const Test& p1, const Test& p2) {
      return p1.x <= p2.x && p1.y <= p2.y;
  }
  
  int main()
  {
      Test t1;
      Test t2;
      int add;
      add = t1 + t2;
      return 0;
  }
  ```

- 从反汇编的角度说说引用与指针的区别

  似乎没有什么区别

### 数据结构

###### Vector

- 实现一个`Vector`类

  ```c++
  #define SUCCESS           			 1 // 成功
  #define ERROR            			 -1 // 失败
  #define MALLOC_ERROR				 -2 // 申请内存失败
  #define INDEX_ERROR		 			 -3 // 错误的索引号
  
  
  template <class T_ELE>
  class Vector
  {
  public:
  	Vector();
  	Vector(DWORD dwSize);
  	~Vector();
  public:
  	DWORD	at(DWORD dwIndex,OUT T_ELE* pEle);					//根据给定的索引得到元素				
      DWORD   push_back(T_ELE Element);							//将元素存储到容器最后一个位置
  	VOID	pop_back();											//删除最后一个元素				
  	DWORD	insert(DWORD dwIndex, T_ELE Element);				//向指定位置新增一个元素				
  	DWORD	capacity();											//返回在不增容的情况下，还能存储多少元素
  	VOID	clear();											//清空所有元素				
  	BOOL	empty();											//判断Vector是否为空 返回true时为空
  	VOID	erase(DWORD dwIndex);								//删除指定元素				
  	DWORD	size();												//返回Vector元素数量的大小				
  private:
  	BOOL	expand();	
  private:
  	DWORD  m_dwIndex;							//下一个可用索引				
  	DWORD  m_dwIncrement;						//每次增容的大小				
  	DWORD  m_dwLen;								//当前容器的长度
  	DWORD  m_dwInitSize;						//默认初始化大小				
  	T_ELE *m_pVector;							//容器指针				
  };
  
  template <class T_ELE>
  Vector<T_ELE>::Vector():m_dwInitSize(100),m_dwIncrement(5)
  {
      					//默认初始化大小	//每次增容的大小
  	//1.创建长度为m_dwInitSize个T_ELE对象
      m_Obj = new T_ELE[m_dwInitSize];
  	//2.将新创建的空间初始化
      memset(m_Obj,0,m_dwInitSize*sizeof(T_ELE));
  	//3.设置其他值
      m_dwIndex = 0;
      m_dwInitSize = m_dwInitSize;    //可能初始化的大小是按照一个成员为单位的，所以就不用乘sizeof(T_ELE)吧
  }
  template <class T_ELE>
  Vector<T_ELE>::Vector(DWORD dwSize):m_dwIncrement(5)
  {
  	//1.创建长度为dwSize个T_ELE对象
      m_Obj = new T_ELE[dwSize];
  	//2.将新创建的空间初始化
      memset(m_Obj,0,dwSize*sizeof(T_ELE));
      //3.设置其他值
      m_dwIndex=0;
  	m_dwLen = dwSize;
  }
  template <class T_ELE>
  Vector<T_ELE>::~Vector()
  {
  	//释放空间 delete[]
      delete[] m_Obj;
      m_Obj = NULL;   //防uaf
  }
  
  template <class T_ELE>
  BOOL Vector<T_ELE>::expand()
  {
  	// 1. 计算增加后的长度 = 当前容器的长度 + 每次增容的大小
      int added = m_dwLen + m_dwIncrement;
  	// 2. 申请空间
      T_ELE* addr = new T_ELE[added];    //指向 T_ELE 类型数据的指针
  	// 3. 将数据复制到新的空间
      memcpy(addr,m_Obj,m_dwInitSize*sizeof(T_ELE));
  	// 4. 释放原来空间
      delete[] m_Obj;
  	// 5. 为各种属性赋值
      m_Obj = addr;
      addr = NULL;
      m_dwLen = added;
      return SUCCESS;
  }
  
  template <class T_ELE>
  DWORD  Vector<T_ELE>::push_back(T_ELE Element)
  {
  	//1.判断是否需要增容，如果需要就调用增容的函数
      if(m_dwIndex>=m_dwLen)
      {
          expand();
      }
  	//2.将新的元素复制到容器的最后一个位置
      memcpy(&m_Obj[m_dwIndex],&Element,sizeof(T_ELE));
  	//3.修改属性值
      m_dwIndex++;
      return SUCCESS;
  }
  
  template <class T_ELE>
  DWORD  Vector<T_ELE>::insert(DWORD dwIndex, T_ELE Element)    //向指定位置新增一个元素
  {
  	//1.判断是否需要增容，如果需要就调用增容的函数
      if(m_dwIndex>=m_dwLen)
      {
          expand();
      }
  	//2.判断索引是否在合理区间
      if(dwIndex < 0 || dwIndex > m_dwIndex)
      {
      	return INDEX_ERROR;
      }
  	//3.将dwIndex之后的元素后移
      memcpy(((int*)(&m_Obj[dwIndex]))+1,&m_Obj[dwIndex],sizeof(T_ELE)*(m_dwIndex-dwIndex));
  	//4.将Element元素复制到dwIndex位置
      memcpy(&m_pVector[dwIndex],&Element,sizeof(T_ELE));
  	//5.修改属性值
      dwIndex++;
      return SUCCESS;
  }
  template <class T_ELE>
  DWORD Vector<T_ELE>::at(DWORD dwIndex,T_ELE* pEle)    //根据给定的索引得到元素
  {
  	//判断索引是否在合理区间
      if(dwIndex < 0 || dwIndex > m_dwIndex)
      {
      	return INDEX_ERROR;
      }
  	//将dwIndex的值复制到pEle指定的内存
      memcpy(pEle,m_Obj[dwIndex],sizeof(T_ELE));
  }
  //其他函数。。自己实现
  ```

- 读懂每一个方法的反汇编实现

###### 链表

- 实现一个单项链表

  ```c++
  #define SUCCESS           1 // 执行成功
  #define ERROR            -1 // 执行失败
  #define INDEX_IS_ERROR   -2 // 错误的索引号
  #define BUFFER_IS_EMPTY  -3 // 缓冲区已空
  
  
  template <class T_ELE>
  class LinkedList
  {
  public:
  	LinkedList();
  	~LinkedList();
  public:
  	BOOL  IsEmpty();						                        //判断链表是否为空 空返回1 非空返回0
  	void  Clear();						                            //清空链表
  	DWORD GetElement(IN DWORD dwIndex,OUT T_ELE& Element);			//根据索引获取元素
  	DWORD GetElementIndex(IN T_ELE& Element);						//根据元素获取链表中的索引
  	DWORD Insert(IN T_ELE Element);						            //新增元素
  	DWORD Insert(IN DWORD dwIndex, IN T_ELE Element);				//根据索引新增元素
  	DWORD Delete(IN DWORD dwIndex);									//根据索引删除元素
  	DWORD GetSize();												//获取链表中元素的数量
  private:
  	typedef struct _NODE
  	{
  		T_ELE  Data;
  		_NODE *pNext;
  	}NODE,*PNODE;
  	PNODE GetIndexCurrentNode(DWORD dwIndex);						//获取索引为dwIndex的指针
  	PNODE GetIndexPreviousNode(DWORD dwIndex);						//获取索引为dwIndex的前一个节点指针
  	PNODE GetIndexNextNode(DWORD dwIndex);							//获取索引为dwIndex的后一个节点指针
  private:
  	PNODE m_pList;													//链表头指针，指向第一个节点
  	DWORD m_dwLength;												//元素的数量
  };
  
  //无参构造函数 初始化成员
  template<class T_ELE> LinkedList<T_ELE>::LinkedList():m_pList(NULL),m_dwLength(0)
  {
  
  }
  //析构函数 清空元素
  template<class T_ELE> LinkedList<T_ELE>::~LinkedList()
  {
  	Clear();
  }
  //判断链表是否为空
  template<class T_ELE> BOOL LinkedList<T_ELE>::IsEmpty()
  {
      if(m_pList = 0 || m_dwLength = 0)
      {
          return SUCCESS;
      }
      else
      {
          return 0;
      }
  }
  //清空链表
  template<class T_ELE> void LinkedList<T_ELE>::Clear()
  {
  	// 1. 判断链表是否为空
      if(IsEmpty() == SUCCESS)
      {
          printf("BUFFER_IS_EMPTY");
      }
      else
      {
  	// 2. 循环删除链表中的节点
          NODE* pList = m_pList;
          NODE* pDelete = NULL;
          for(int i = 0;i < m_dwLength;i++)
          {
              pDelete = pList;
  			pList = pList -> pNext;
  			delete pDelete;
          }
  	// 3. 删除最后一个节点并将链表长度置为0
          delete pList;
          m_dwLength = 0;
      }
  }
  //根据索引获取元素
  template<class T_ELE> DWORD LinkedList<T_ELE>::GetElement(IN DWORD dwIndex,OUT T_ELE& Element)
  {
  	// 1. 判断索引是否有效
      if(dwIndex < 0 || dwIndex > m_dwLength)
      {
          return INDEX_IS_ERROR;
      }
  	// 2. 取得索引指向的节点
      NODE* pList1 = m_pList;
      for(int i = 0;i < dwIndex;i++)
      {
          pList1 = pList1 -> pNext;
      }
  	// 3. 将索引指向节点的值复制到OUT参数
      Element pList1 -> pNext;
      return SUCCESS;
  }
  //根据元素内容获取索引
  template<class T_ELE> DWORD LinkedList<T_ELE>::GetElementIndex(IN T_ELE& Element)
  {
  	// 1. 判断链表是否为空
      if(IsEmpty() == SUCCESS)
      {
          return BUFFER_IS_EMPTY;
      }
  	// 2. 循环遍历链表，找到与Element相同的元素
      for(int i = 0;i < m_dwLength;i++)
      {
          if(pList1 -> Data ==Element)
          {
              Index = i;
          }
          else
          {
              pList1 = pList1 -> pNext;
          }
      }
      return Index;
  }
  //在链表尾部新增节点
  template<class T_ELE> DWORD LinkedList<T_ELE>::Insert(IN T_ELE Element)
  {
      NODE* pNewNode = new NODE;
      memset(pNewNode,0,sizeof(NODE));
      memcpy(&pNewNode -> Data,&Element,sizeof(T_ELE));
  	// 1. 判断链表是否为空
      if(IsEmpty() == SUCCESS)
      {
          m_pList = pNewNode;
          m_dwLength++;
          return SUCCESS;
      }
  	// 2. 如果链表中已经有元素
      NODE* TempNODE = m_pList;
      for(int i = 0;i < m_dwLength - 1;i++)
      {
          TempNODE = TempNODE -> pNext;
      }
      TempNODE -> pNext = pNewNode;
      m_dwLength++;
      return SUCCESS;
  }
  //将节点新增到指定索引的位置
  template<class T_ELE> DWORD LinkedList<T_ELE>::Insert(IN DWORD dwIndex, IN T_ELE Element)
  {
      NODE* pNewList = new NODE;
  	memset(pNewList, 0, sizeof(NODE));
  	memcpy(pNewList, &Element, sizeof(T_ELE));
  	//  1. 判断链表是否为空
      if(IsEmpty() == SUCCESS)
      {
          m_pList = pNewList;
          m_dwLength++;
          return SUCCESS;
      }
  	//  2. 判断索引值是否有效
      if (dwIndex <0 || dwIndex > m_dwLength)
  	{
  		return INDEX_IS_ERROR;
  	}
  	//  3. 如果索引为0
  	if (dwIndex == 0)
  	{
  		pNewList -> pNext = m_pList;
  		m_pList = pNewList;
  		m_dwLength++;
  		return SUCCESS;
  	}
  	//  4. 如果索引为链表尾
  	NODE* pList1 = m_pList;
  	for (int i = 0; i < m_dwLength - 1; i++)
  	{
  		pList1 = pList1 -> pNext;
  	}
  	pList1 -> pNext = pNewList;
  	m_dwLength++;
  	//  5. 如果索引为链表中
  }
  //根据索引删除节点
  template<class T_ELE> DWORD LinkedList<T_ELE>::Delete(IN DWORD dwIndex)
  {
  	//  1. 判断链表是否为空
      if(IsEmpty() == SUCCESS)
      {
          return BUFFER_IS_EMPTY;
      }
  	//  2. 判断索引值是否有效
  	if (dwIndex <0 || dwIndex > m_dwLength)
  	{
  		return INDEX_IS_ERROR;
  	}
  	//  3. 如果链表中只有头节点，且要删除头节点
  	if (m_pList -> pNext == NULL && dwIndex == 0)
  	{
  		delete m_pList;
  		m_dwLength--;
  		return SUCCESS;
  	}
  	//  4. 如果要删除头节点
  	if (dwIndex == 0)
  	{
  		NODE* pTemp = m_pList;
  		m_pList = m_pList -> pNext;
  		delete pTemp;
  		m_dwLength--;
  		return SUCCESS;
  	}
  	//  5. 如果是其他情况
      else
      {
  		NODE* pNList = m_pList;
  		GetIndexPreviousNode(dwIndex) -> pNext = GetIndexCurrentNode(dwIndex) -> pNext;
  		delete GetIndexCurrentNode(dwIndex);
  		m_dwLength--;
  	}
  }
  //获取链表中节点的数量
  template<class T_ELE> DWORD LinkedList<T_ELE>::GetSize()
  {
  
  }
  //获取dwIndex前面节点的地址
  template<class T_ELE>
  LinkedList<T_ELE>::PNODE LinkedList<T_ELE>::GetIndexPreviousNode(DWORD dwIndex)
  {
  	// 就是一个循环
  
  }
  //获取dwIndex节点的地址
  template<class T_ELE>
  LinkedList<T_ELE>::PNODE LinkedList<T_ELE>::GetIndexCurrentNode(DWORD dwIndex)
  {
  	// 就是一个循环
  
  }
  //获取dwIndex后面节点的地址
  template<class T_ELE>
  LinkedList<T_ELE>::PNODE LinkedList<T_ELE>::GetIndexNextNode(DWORD dwIndex)
  {		
  	// 就是一个循环
  
  }
  ```

- 读懂每一个方法的反汇编实现

###### 二叉树

- 遍历二叉树中的怪物列表

- 完成析构函数中的代码

  ```mermaid
  graph TD
      A[5] --> B[4]
      A --> C[6]
      B --> D[1]
      B --> E[NULL]
      C --> F[3]
      C --> G[NULL]
      D --> H[NULL]
      D --> I[2]
      F --> J[NULL]
      F --> K[7]
  ```

  ```c++
  class Monster
  {
  public:
  	int ID;
  	int Level;
  	char Name[20];
  public:
  	Monster(){}
  	Monster(int ID,int Level,char* Name)
  	{
  		this->ID = ID;
  		this->Level = Level;
  		memcpy(&this->Name,Name,strlen(Name)+1);
  	}
  };
  template<class T>
  class TreeNode{
  public:
  	T element;							//当前节点存储的数据
  	TreeNode<T>* pLeft;					//指向左子节点的指针
  	TreeNode<T>* pRight;				//指向右子节点的指针
  
  	TreeNode(T& ele){
  		//初始化Node节点
  		memset(&element,0,sizeof(TreeNode));
  		//为元素赋值
  		memcpy(&element,&ele,sizeof(T));
  		pLeft = pRight = NULL;
  	}
  };
  
  template<class T>
  class BSortTree{
  public:
  	BSortTree();					//构造函数
  	~BSortTree();					//析构函数
  public:
  	void InOrderTraverse(TreeNode<T>* pNode);					//中序遍历
  	void PreOrderTraverse(TreeNode<T>* pNode);					//前序遍历
  	void PostOrderTraverse(TreeNode<T>* pNode);					//后序遍历
  	TreeNode<T>* GetRoot();									//返回根节点
  	int GetDepth(TreeNode<T>* pNode);						//返回某个节点的高度/深度
  private:
  	void Init();
  private:
  	TreeNode<T>* m_pRoot;					//根结点指针
  	int size;							//树中元素总个数
  };
  
  template<class T>
  BSortTree<T>::BSortTree()
  {
  	Init();
  }
  template<class T>
  BSortTree<T>::~BSortTree(){
  	//释放所有节点空间
      Clear(m_pRoot);
  }							
  
  template<class T>
  void BSortTree<T>::Init()
  {
  
  	Monster m1(1,1,"刺猬");
  	Monster m2(2,2,"野狼");
  	Monster m3(3,3,"野猪");
  	Monster m4(4,4,"士兵");
  	Monster m5(5,5,"火龙");
  	Monster m6(6,6,"独角兽");
  	Monster m7(7,7,"江湖大盗");
  
  
  	TreeNode<Monster>* n1 = new TreeNode<Monster>(m1);
  	TreeNode<Monster>* n2 = new TreeNode<Monster>(m2);
  	TreeNode<Monster>* n3 = new TreeNode<Monster>(m3);
  	TreeNode<Monster>* n4 = new TreeNode<Monster>(m4);
  	TreeNode<Monster>* n5 = new TreeNode<Monster>(m5);
  	TreeNode<Monster>* n6 = new TreeNode<Monster>(m6);
  	TreeNode<Monster>* n7 = new TreeNode<Monster>(m7);
  
  	m_pRoot = n5;
  	n5->pLeft = n4;
  	n5->pRight = n6;
  	n4->pLeft = n1;
  	n1->pRight = n2;
  	n6->pLeft = n3;
  	n3->pRight = n7;
  	size = 7;
  }
  template<class T>
  TreeNode<T>* BSortTree<T>::Clear(TreeNode<T>* pNode)
  {
  	if(pNode != 0)
      {
          Clear(pNode -> pLeft);
          Clear(pNode -> pRight);
          delete pNode;
          pNode = NULL;
      }
  }
  template<class T>
  TreeNode<T>* BSortTree<T>::GetRoot()
  {
  	return m_pRoot;
  }
  template<class T>
  int BSortTree<T>::GetDepth(TreeNode<T>* pNode)
  {
       if(pNode==NULL)
      {
  		return 0;
      }
      else
      {
          int m = GetDepth(pNode->pLeft);
          int n = GetDepth(pNode->pRight);
          return (m > n) ? (m+1) : (n+1);
      }
  }
  template<class T>
  void BSortTree<T>::InOrderTraverse(TreeNode<T>* pNode)
  {
  	//中序遍历所有怪物,列出怪的名字
      if(pNode!==NULL)
      {
          InOrderTraverse(pNode -> pLeft);
          pName = (char*)&pNode -> element;
          pName = pName + 8;
          printf("%d\n",pName);
          InOrderTraverse(pNode -> pRight);
      }
  }
  
  template<class T>
  void BSortTree<T>::PreOrderTraverse(TreeNode<T>* pNode)
  {
  	//前序遍历所有怪物,列出怪的名字
      if(pNode!==NULL)
      {
          pName = (char*)&pNode -> element;
          pName = pName + 8;
          printf("%d\n",pName);
          PreOrderTraverse(pNode -> pLeft);
          PreOrderTraverse(pNode -> pRight);
      }
  }
  
  template<class T>
  void BSortTree<T>::PostOrderTraverse(TreeNode<T>* pNode)
  {
  	//后序遍历所有怪物,列出怪的名字
      if(pNode!==NULL)
      {
          pName = (char*)&pNode -> element;
          pName = pName + 8;
          PostOrderTraverse(pNode -> pLeft);
          PostOrderTraverse(pNode -> pRight);
          printf("%d\n",pName);
      }
  }
  
  //对应循环遍历的话是最深的对应子节点，到最深后在对应循环遍历会跳过（因为pNode!==NULL），后面就会循环遍历对应的另一个节点，自然也是最深的
  ```

- `Thinking`：如何区分二叉树还是双向链表？

  双向链表会有两个地址成员，而且有一个成员指向前一个成员。二叉树如果要指向前一个成员的话要有三个地址成员（就是父节点）。

###### 搜索二叉树

- 完成搜索二叉树的删除功能

  ```c++
  #define SUCCESS           			  1 // 执行成功						
  #define ERROR			 -1 // 执行失败			         			
  	
  template<class T>	
  class TreeNode{	
  public:	
  	T element;					//当前节点存储的数据			
  	TreeNode<T>* pLeft;					//指向左子节点的指针			
  	TreeNode<T>* pRight;					//指向右子节点的指针			
  	TreeNode<T>* pParent;					//指向父结点的指针			
  	
  	
  	TreeNode(T& ele){
  		//初始化Node节点							
  		memset(&element,0,sizeof(TreeNode));							
  		//为元素赋值							
  		memcpy(&element,&ele,sizeof(T));							
  		pLeft = pRight = pParent = NULL;							
  	}
  	//重载== 比较两结点是否相等
  	bool operator==(TreeNode<T>* node){ 
  		return node->element == element?true:false;							
  	}
  };	
  	
  template<class T>	
  class BSortTree{	
  public:	
  	BSortTree();						//构造函数		
  	~BSortTree();						//析构函数		
  public:							//判断树是否为空		
  	bool IsEmpty();						//新增节点		
  	DWORD Insert(T element);						//删除节点		
  	void Delete(T element);
  	TreeNode<T>* Search(T element);						//查找节点		
  	void InOrderTraverse(TreeNode<T>* pNode);						//中序遍历		
  	void PreOrderTraverse(TreeNode<T>* pNode);						//前序遍历		
  	void PostOrderTraverse(TreeNode<T>* pNode);						//后序遍历		
  private:	
  	TreeNode<T>* GetMaxNode(TreeNode<T>* pNode);						//获取以pNode为根的最大节点		
  	TreeNode<T>* GetMinNode(TreeNode<T>* pNode);						//获取以pNode为根的最小节点		
  	TreeNode<T>* SearchNode(TreeNode<T>* pNode,T element);						//获取以pNode为根的最小节点		
  	DWORD InsertNode(T element, TreeNode<T>* pNode);						//新增节点		
  	TreeNode<T>* DeleteNode(T element, TreeNode<T>* pNode);						//删除节点		
  	void Clear(TreeNode<T>* pNode);						//清空所有节点		
  private:	
  	TreeNode<T>* m_pRoot;						//根结点指针		
  	int size;						//树中元素总个数		
  };	
  	
  template<class T> 	
  BSortTree<T>::BSortTree()	
  {	
  	m_pRoot = NULL;
  	size = 0;
  }	
  template<class T> 	
  BSortTree<T>::~BSortTree(){	
  	
  	Clear(m_pRoot);
  }	
  template<class T> 	
  DWORD BSortTree<T>::Insert(T element)	
  {	
  	//如果根节点为空
  	if ( !m_pRoot )
  	{
  		m_pRoot = new TreeNode<T>(element);							
  		size++;							
  		return SUCCESS;							
  	}
  	//如果根节点不为空
  	return InsertNode(element, m_pRoot);
  }	
  template<class T> 	
  DWORD BSortTree<T>::InsertNode(T element, TreeNode<T>* pNode)	
  {	
  	//将元素封装到节点中
  	TreeNode<T>* pNewNode = new TreeNode<T>(element);
  	//如果element == 当前节点 直接返回
  	if(element == pNode->element)
  	{
  		return SUCCESS;							
  	}
  	//如果pNode的左子节点为NULL 并且element < 当前节点
  	if(pNode->pLeft == NULL && element < pNode->element)
  	{
  		pNode->pLeft = pNewNode;							
  		pNewNode->pParent = pNode;							
  		size++;							
  		return SUCCESS;							
  	}
  	//如果pNode的右子节点为NULL 并且element > 当前节点
  	if(pNode->pRight == NULL && element > pNode->element){
  		pNode->pRight = pNewNode;							
  		pNewNode->pParent = pNode;							
  		size++;							
  		return SUCCESS;							
  	}
  	//如果element<当前节点 且当前节点的左子树不为空
  	if(element < pNode->element)
  	{
  		InsertNode(element,pNode->pLeft);							
  	}
  	else
  	{
  		InsertNode(element,pNode->pRight);							
  	}
  	return SUCCESS;
  }	
  	
  template<class T> 	
  void BSortTree<T>::Clear(TreeNode<T>* pNode)	
  {	
  	if(pNode!=NULL)
  	{
  		Clear(pNode->pLeft);							
  		Clear(pNode->pRight);							
  		delete pNode;							
  		pNode=NULL;							
  	}
  }	
  	
  template<class T> 	
  bool BSortTree<T>::IsEmpty()	
  {	
  	return size==0?true:false;
  }	
  	
  template<class T> 	
  TreeNode<T>* BSortTree<T>::Search(T element)	
  {	
  	return SearchNode(m_pRoot, element);
  }	
  template<class T> 	
  TreeNode<T>* BSortTree<T>::SearchNode(TreeNode<T>* pNode,T element)	
  {	
  	if(pNode == NULL)					//如果节点为NULL			
  	{
  		return NULL;							
  	}
  	else if(element == pNode->element)					//如果相等			
  	{
  		return pNode;							
  	}					//如果比节点的元素小 向左找			
  	else if(element < pNode->element)
  	{
  		return SearchNode(pNode->pLeft,element);							
  	}
  	else					//如果比节点的元素大 向右找			
  	{
  		return SearchNode(pNode->pRight,element);							
  	}
  }	
  	
  template<class T> 	
  void BSortTree<T>::Delete(T element)	
  {	
  	if (m_pRoot !== NULL)
      {
          TreeNode<T>* ptemp = SearchNode(m_pRoot , element);
          DeleteNode(element, ptemp);
      }
  }	
  	
  template<class T> 	
  TreeNode<T>* BSortTree<T>::DeleteNode(T element,TreeNode<T>* pNode)	
  {	
  	if (!pNode->pLeft && !pNode->pRight)
      {
          if (pNode->element < pNode->pParent->element)
          {
              pNode->pParent->pLeft = NULL;
          }
          else
  		{
  			pNode->pParent->pRight = NULL;
  		}
          delete pNode;
      }else if(pNode->pLeft && !pNode->pRight)    //有左无右
      {
          if (pNode->element < pNode->pParent->element)    //在父左
          {
              pNode->pParent->pLeft = pNode->pLeft;    //父节点的左地址写入左孙节点
              pNode->pLeft->pParent = pNode->pParent;    //左孙节点的父地址写入父节点的地址
          }
          else    //在父右
  		{
              pNode->pParent->pRight = pNode->pLeft;
              pNode->pLeft->pParent = pNode->pParent;
  		}
          delete pNode;
      }else if(!pNode->pLeft && pNode->pRight)
      {
          if (pNode->element < pNode->pParent->element)
          {
              pNode->pParent->pLeft = pNode->pRight;    //父节点的左地址写入右孙节点
              pNode->pRight->pParent = pNode->pParent;    //右孙节点的父地址写入父节点的地址
          }
          else
  		{
              pNode->pParent->pRight = pNode->pRight;
              pNode->pRight->pParent = pNode->pParent;
  		}
          delete pNode;
      }else if(pNode->pLeft && pNode->pRight)
      {
          TreeNode<T>* pLeftMinNode = GetLeftMinNode(pNode->pLeft);    //找到最小的那个节点
          pNode->element = pLeftMinNode->element;    //把最小的节点与我要删的节点替换内容
          DeleteNode(pLeftMinNode->element,pLeftMinNode);   //就是删除那个找到的最小的节点
      }
  	
  	return NULL;
  }	
  	
  	
  	
  	
  //测试代码：	
  	
  	
  void TestInsert()	
  {	
  	//12 8 5 9 17 15 13
  	/*
  				12					
  	
  		8				17			
  	
  	5		9		15				
  	
  				13					
  	
  	*/
  	
  	BSortTree<int> tree;
  	
  	tree.Insert(12);
  	tree.Insert(8);
  	tree.Insert(5);
  	tree.Insert(9);
  	tree.Insert(17);
  	tree.Insert(15);
  	tree.Insert(13);
  }	
  	
  void TestSerch()	
  {	
  	//12 8 5 9 17 15 13
  	
  	BSortTree<int> tree;
  
  	tree.Insert(12);
  	tree.Insert(8);
  	tree.Insert(5);
  	tree.Insert(9);
  	tree.Insert(17);
  	tree.Insert(15);
  	tree.Insert(13);
  
  	TreeNode<int>* p = tree.Search(17);
  	printf("%x %d\n",p,p->element);
  }
  ```
