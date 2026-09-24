# 隔离采集器：iperf 3.18 / omit0

用途是为UL连续进展实验提供一致计数，不是PPP性能补丁。系统iperf保持不变，A2规则保持不变。

固定官方归档：`https://downloads.es.net/pub/iperf/iperf-3.18.tar.gz`

SHA256：`c0618175514331e766522500e20c94bfb293b4424eb27d7207fb427b88d20bab`

在全新临时目录解包，对解包根目录执行：

```sh
patch -p1 < /home/openppp2/tools/iperf-patches/0001-coherent-interval-capture.patch
./configure --disable-shared
make -j8
```

不执行系统安装。通过仅该次命令的PATH前缀选择 `src/iperf3`，**显式使用 `--omit 0`**。需要C11 stdatomic，无该功能编译失败。新旧PPP对比双方都必须使用同一采集器及参数；不得将不同采集器的性能差异归为PPP优化收益。

补丁由GLM实现，独立GLM审阅PASS后主代理核对原始diff并归档；仅更改统计回调，收发路径、CC、缓冲不变。原计数先读再清零存在并发漏计窗口；使用atomic exchange把该窗口消除。每轮共享一个报告批次时间，**不表示各worker在完全相同瞬间原子采样**，区间公平性是在报告批次层面估计。

限制：未修复omit>0重置统计的并发问题，不用于带预热重置的严格统计验收；短暂停顿仍受采样粒度限制，不证明接收端交付或应用需求。原版与新采集器的native P4对照见 `artifacts/g6-b-native-capture-preflight-0908/` 和 `artifacts/g6-b-capture-fixed-preflight-0908/`。

本环境构建的iperf二进制SHA256：`7531a7baa5b3a3a223558916cf1cd9ec2d55630a21d9199826c47b0e22f2a634`；构建路径 `/tmp/g6-iperf-capture-FhlwLB/iperf-3.18/src/iperf3`。重新构建可能因编译器、路径/调试信息得到不同指纹，应重新记录。

`make check`为4/5通过。`t_auth`在OpenSSL解码测试报告output buffer too small；新解包的未修改原版在相同src工作目录也复现同一断言失败，没有修改测试或计作通过。本轮仅运行无认证的本地隔离TCP测试。
