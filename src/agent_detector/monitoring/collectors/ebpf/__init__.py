"""eBPF 采集通道（Tetragon）。

 Tetragon → JSON 导出文件 → parser（本包）→ BehaviorFact → 复用 auditd/sysmon
 同一条 ingest 管线（规则→归属→抑制→落库）。采集端只 tail 导出文件，不直接
 接触内核；通道探测与安装命令打印见 tetragon.py。
"""
