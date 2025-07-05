---
title: Bypass
cascade:
  type: docs
---

###### DLL劫持

- 导入要劫持的`DLL`，使用`AheadLib+`生成模板
- 在入口函数处编写`payload`
- 将转发`DLL`放到原`DLL`同目录下，并将原`DLL`改名
