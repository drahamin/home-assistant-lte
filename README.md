# Baiamonte LTE

A Home Assistant app (formerly called an add-on) for controlling Baiamonte’s internal LTE network. It provides a light/dark vineyard operations interface for EPC and Nokia eNodeB health, subscriber traffic and connection gauges, an expanded network visibility board, incident history, safe troubleshooting tools, searchable logs, vineyard-zone device grouping, availability alerts, UE subscriber provisioning, guarded EPC Internet routing, optional PBX voice/text dispatch, commissioning-file intake, and programmable test-SIM preparation with Milenage OPc generation.

Preconfigured defaults:

- EPC / MME: configured in Home Assistant (documentation example: `192.0.2.151`)
- Nokia eNodeB management: configured in Home Assistant (documentation example: `192.0.2.100`)
- eNodeB software: FLF21
- S1AP: SCTP 36412
- Subscriber backend: legacy NextEPC MongoDB
- Default example UE data subnet: `10.45.0.0/16` via EPC uplink `eth0` (both configurable)

See [lte_manager/DOCS.md](lte_manager/DOCS.md) for installation and safe commissioning steps.

## Updates

Tagged releases publish multi-architecture containers to GitHub Container Registry. Home Assistant will show a new version when the repository version is bumped. Turn on **Automatic updates** on the app's Info page if you want Home Assistant to install offered updates automatically.

The private Nokia commissioning backup is intentionally excluded from Git. Import it on the BTS page after installation.
