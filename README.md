审计日志声称只追加，结果中间一段被替换成了另一段，校验器只看了首尾两块：封印只含段内条目摘要，不含前封印，链断可重接；段号不参与封印，段可整体互换；校验从第二段开始，首段未校验；整链校验遇到失败继续走，返回最后一个失败段；截断检测比较条目数而不是段数；缺口检测只看相邻段号大小，重复段号漏检；读取范围用开区间，末尾段读不到；读取越界时返回空列表而不是抛异常；校验不检查条目是否追加，时间戳倒序被接受；批量封存复用前封印，第二条流接到第一条流的链上。engine/log/seal.py 是核心，tests/log/test_seal.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

# sec-immutable-log

只追加审计日志的分段封印、链校验与局部替换检测。仓库初始状态为 8 个未实现桩，15 条严格测试全部因 NotImplementedError 失败。

## 运行方式

```powershell
cd D:/gsb-20261119/sec-immutable-log
python -m pytest tests -q
```

初始状态应恰好为：

```text
15 failed
```

15 个失败必须全部来自测试调用 engine/log/seal.py 中 raise NotImplementedError 的桩函数；不允许出现 collection error、import error 或 syntax error，也不允许跳过测试。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录

```text
sec-immutable-log/
  README.md
  conftest.py
  engine/__init__.py
  engine/log/__init__.py
  engine/log/seal.py
  tests/log/test_seal.py
```

## engine 嵌套布局

engine 是顶层包，engine/log 是它的子包，唯一实现文件是 engine/log/seal.py。测试通过 from engine.log.seal import ... 导入；不要改成扁平布局，也不要新增第二份实现或把函数放到 engine/log/__init__.py。

## 数据契约

段号从 0 开始连续增长，每条流都以第 0 段为创世段。条目是至少含 ts、actor、action、detail 的 JSON 可序列化字典，摘要覆盖条目字典的全部键值。段字典字段为 index、prev_seal、entries、digest、seal。

摘要和封印都使用无空白的规范 JSON 与 SHA-256：digest 是 entries 的摘要，seal 是 index、prev_seal、digest 三者的摘要。因此封印同时绑定段号、前封印和段内全部条目；first 段的 prev_seal 为 None。

## 约束

- 只使用标准库与 pytest，离线运行，不使用随机数。
- engine/log/seal.py 的 8 个函数当前全部是桩，函数契约写在各函数 docstring 中，容差为 0。
- tests/log/test_seal.py 是不可修改的验收标准；不要改测试、加 skip 或 xfail、放宽断言或加 monkeypatch 来制造绿色，只实现 engine/log/seal.py。
- 修复必须覆盖分段边界、封印链、局部替换、读一致性、缺口与乱序；不要只让某一条测试变绿。
- 不得联网，不得引入第三方依赖，不得 git init 或 push。