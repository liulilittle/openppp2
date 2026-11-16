# Design Documents
> Status: Active
> Type: Design
> Last verified: 2026-10-07

> **Purpose:** Index active, status-bound design evidence that has not become stable reference material.
> **Audience:** OPENPPP2 maintainers and reviewers.
> **Status:** Current design index.
> **Last verified against:** Current design tree, desktop client implementation under `desktop/client/`, and documentation governance, 2026-07-22.
> **Parent index:** [Architecture](../architecture/README.md)

Design documents describe behavior before implementation and remain status-bound evidence. Stable behavior moves
to paired reference documentation once verified. The Chinese desktop Client design notes below are likewise
status-bound and deliberately do not imply English stable-reference peers. Worktree-specific plans and specifications
are intentionally not indexed in this repository snapshot; they are not current-behavior or
stable-reference claims.

- [Authenticated L3 session roaming](session-recovery/l3-roaming.md)
- [Noise/PSK authenticated carrier compatibility](session-recovery/noise-psk-carrier-compatibility.md)
- [P2P direct-channel protocol](p2p-direct-channel/protocol.md)
- [P2P direct-channel state machine](p2p-direct-channel/state-machine.md)
- [P2P direct-channel threat model](p2p-direct-channel/threat-model.md)
- [XTCP platform build notes](XTCP_INTEGRATION.md)
- [仅代理模式接入虚拟子网与 P2P 直连（计划）](p2p-direct-channel/proxy-only-subnet-plan_CN.md)
- [OpenPPP2 Sub / Client 方案设计](SUB_CLIENT_DESIGN_CN.md)
- [桌面客户端手动节点与启动参数设计](CLIENT_MANUAL_PROFILES_DESIGN_CN.md)
- [OpenPPP2 Client 管理器 UI/UX 设计](CLIENT_UIUX_DESIGN_CN.md)
- [VMUX 可靠性子协议设计(ACK + 快速重传 + FEC)](MUX_RELIABILITY_FEC_DESIGN_CN.md)
- [XTCP 接入设计与依赖门禁](XTCP_INTEGRATION_CN.md)
- [OpenPPP2 易用性路线图](USABILITY_ROADMAP_CN.md)
- [Linux Tap 边缘 GSO 合并设计](PPP-DATAPATH-GSO-CONTRACT_CN.md)
- [Datapath 网络损伤验收设计](PPP-DATAPATH-NETEM-ACCEPTANCE_CN.md)
- [DNS 与分流策略 P0 现状基线](DNS_ROUTING_POLICY_BASELINE_CN.md)
- [DNS 与分流策略 P1 离线编译和诊断](DNS_ROUTING_POLICY_P1_CN.md)
- [DNS 与分流策略 P2 执行路径接入](DNS_ROUTING_POLICY_P2_CN.md)
- [DNS 与分流策略 P3 DNS/Fake-IP](DNS_ROUTING_POLICY_P3_CN.md)
- [DNS 与分流策略 P4 数据包更新](DNS_ROUTING_POLICY_P4_CN.md)
- [DNS 与分流策略 P5 旧适配与 CLI](DNS_ROUTING_POLICY_P5_CN.md)
- [DNS、域名/IP 分流与规则集重构总方案](DNS_ROUTING_POLICY_REFACTOR_CN.md)
- [Linux 实机验证报告](../testing/DNS_ROUTING_POLICY_LINUX_LIVE_CN.md)
- [Client UI mockup](mockups/client-connected.html)
