# Baiamonte LTE

A Home Assistant app (formerly called an add-on) for controlling Baiamonte’s internal LTE network. It provides a single admin-only page for EPC and Nokia eNodeB health, UE subscriber provisioning, commissioning-file intake, diagnostics, and guarded programmable-SIM preparation.

Preconfigured defaults:

- EPC / MME: `192.168.1.151`
- Nokia eNodeB management: `192.168.1.100`
- eNodeB software: FLF21
- S1AP: SCTP 36412
- Subscriber backend: legacy NextEPC MongoDB

See [lte_manager/DOCS.md](lte_manager/DOCS.md) for installation and safe commissioning steps.

## Updates

Tagged releases publish multi-architecture containers to GitHub Container Registry. Home Assistant will show a new version when the repository version is bumped. Turn on **Automatic updates** on the app's Info page if you want Home Assistant to install offered updates automatically.

The private Nokia commissioning backup is intentionally excluded from Git. Import it on the BTS page after installation.
