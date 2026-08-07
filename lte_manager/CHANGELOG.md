# Changelog

## 0.4.2

- Added a guarded, read-only EPC Console for system, LTE core, network, routing, and recent-log views.
- Added an SSH connectivity test that distinguishes refused ports, timeouts/firewalls, non-SSH services, and working SSH servers.
- Improved fingerprint-scan errors so the exact remediation remains visible in the interface.

## 0.4.1

- Fixed EPC private-key uploads for standard extensionless filenames such as `id_ed25519`.
- Added persistent, specific guidance for public, encrypted, empty, and invalid SSH key files.
- Added a clear one-click “Generate & store private key” workflow; only its public key is displayed.

## 0.4.0

- Added a guarded EPC Routing Assistant with SSH host-key verification, preview, apply, status checks, and rollback.
- Added a live subscriber traffic test using NAT, outbound, and established-return packet counters.
- Added EPC, S1, Nokia radio, and verified UE Internet status lights to Overview.
- Added a standards-correct Milenage OPc calculator and secure test-value generator to the SIM workbench.
- Improved repeated page headings with clearer task-oriented section titles.

## 0.3.0

- Added editable vineyard-zone grouping and filtering for estate devices.
- Added 6-hour, 24-hour, and 7-day EPC/radio connection-history charts.
- Added configurable Home Assistant alerts for repeated EPC or radio failures, with cooldowns and recovery notices.
- Added a lightweight background monitor that retains 30 days of availability samples.

## 0.2.0

- Reworked the dashboard as a vineyard-operations console with estate-focused language and branding.
- Added one-click shortcuts for device provisioning, network checks, radio service, and SIM preparation.
- Added an estate health summary, last-check time, persistent page navigation, and saved BTS pre-flight checks.
- Improved the responsive navigation for smoother use inside the Home Assistant mobile app.

## 0.1.2

- Added custom Baiamonte LTE icon and store logo artwork for Home Assistant.

## 0.1.1

- Isolated the ingress service from the Home Assistant host network to prevent port 8099 conflicts.
- Listen on the app container interface so Home Assistant ingress can reach the dashboard.
- Added an optional, user-selectable external web port in Home Assistant's Network settings.

## 0.1.0

- Initial Home Assistant ingress dashboard.
- Preconfigured NextEPC and Nokia FLF21 endpoints.
- UE subscriber registry with NextEPC/Open5GS MongoDB provisioning.
- Private Nokia commissioning-file intake.
- Guarded pySim worksheet and reader readiness view.
- Live activity log, guided diagnostics, EPC log analysis, and redacted support bundles.
