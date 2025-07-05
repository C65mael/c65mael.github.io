---
title: Program Analysis
cascade:
  type: docs
---

###### 介绍

- 原则：
  - 查找程序的错误宁可误报，不可漏报。在确保正确的前提下，尽可能的提高分析速度与精确度。
  - 遍历程序的执行流要全面，不全面可能会漏报错误。

###### Intermediate Representation

- 编译流程：

  ```mermaid
  graph TB
      A[源代码]
      B[Scanner\n词法分析]
      C[Parser\n语法分析]
      D[Type Checker\n语义分析]
      E[Translator]
      F[Code Generator]
      G[机器码]
      A --> B
      B --Tokens--> C
      C --AST--> D
      D --Decorated AST--> E
      E --IR(静态分析)--> F
      F --> G
  ```

- `AST IR`

  对于一下的代码：

  ```c++
  do i = i + 1; while (a[i] < v);
  ```

  可以通过`GCC`使用指令查看`GIMPLE`：

  ```shell
  gcc -O0 -fdump-tree-all test.cpp
  ```

  `GCC`会将源代码首先转换为`GENERIC`（一种树状表示），然后降级为`GIMPLE`（一种简化的、线性的、基于寄存器的3-地址形式），最后再转换为`RTL`（更低级的表示）。
  
  `GIMPLE`如下（`.gimple`）：
  
  ```c++
  <D.4674>:
  i = i + 1;
  _1 = a[i];
  if (v > _1) goto <D.4674>; else goto <D.4672>;
  <D.4672>:
  ```
  
  `AST`如下：
  
  ```mermaid
  graph TD
      A[DoWhile] --> B(Body);
      A --> C(Condition);
  
      B --> D[=];
      D --> E(Target);
      D --> F(Value);
  
      E --> G[i];
  
      F --> H[+];
      H --> I(Left);
      H --> J(Right);
  
      I --> K[i];
      J --> L[1];
  
      C --> M[<];
      M --> N(Left);
      M --> O(Right);
  
      N --> P[Array];
      P --> Q(Base);
      P --> R(Index);
  
      Q --> S[a];
      R --> T[i];
  
      O --> U[v];
  ```
  
- `Static Single Assisnment`（`SSA`）

  相较于3-地址码而言，每一个变量都有自己的一个定义。如果遇到不同的执行流所影响的变量则在受影响的变量前添加`Φ(x0,x1)`（如下`x0`与`x1`影响`x2`）。

  ```mermaid
  graph TB
      A[if e]
      B[x0 = 0]
      C[x1 = 1]
      D[y = x + 7]
      E[if e]
      F[x0 = 0]
      G[x1 = 1]
      H[Φ（x0,x1）\ny = x2 + 7]
      A --> B
      A --> C
      C --> D
      B --> D
      
      E --> F
      E --> G
      F --> H
      G --> H
  ```

- `Control Flow Analysis`（`CFG`）

  控制流图，就是在`IDA`中的汇编界面按空格就能看到类似的。

  执行流程总体是自上到下的，遇到判断等会有两个两个执行流；遇到强行跳转等则不会有下一行的执行流。

  ```mermaid
  graph TB
      A[Entry]
      B[x = input\ny = x - 1]
      C[z = x * y\nif z < x goto B4]
      D[p = x / y\np = q + y]
      E[a = q\nb = x + a\nc = 2a - b\nif p == q goto B6]
      F[goto B2]
      G[return]
      H[Exit]
      
      A~~~B~~~C~~~D~~~E~~~F~~~G~~~H
      
      A --> B
      B --> C
      C --> E
      C --> D
      D --> E
      E --> F
      E --> G
      F --> B
      G --> H
  ```

  

  - `Basic Blocks`

    应该就是起始的代码块，要求不能有其他的入口，结束为最后一条语句

###### Data Flow Analysis1

- 输入输出状态

  对于某段代码或函数，用`IN[s1]`代表输入的信息（参数等）；用`OUT[s1]`代表输出的信息（返回值等）

  在一条执行流上相邻的代码，前面代码的输出信息等于后面代码的输入信息；一条执行流分为多条的情况下，多条执行流的输入信息为那一条执行流的输出信息；多条执行流合为一条执行流，这一条执行流的输入信息为多条执行流的输出信息（用`^`连接，意为相遇）
