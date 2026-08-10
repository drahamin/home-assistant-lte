# Changelog

## 0.6.0

- Removed the synthetic roaming lab to keep the interface focused on the production Baiamonte camera and IoT network.
- Added a six-stage SIM commissioning pipeline covering identity, authentication, physical USIM programming, HSS provisioning, device configuration, and live acceptance.
- Added LTE network-selection guidance for EF.PLMNwAcT, EF.OPLMNwAcT, EF.HPLMNwAcT, EF.FPLMN, EF.EPSLOCI, EF.LOCI, EF.AD, and EF.ACC.
- Clarifies that CDMA PRLs are not used by LTE and maps the requested function to the correct USIM PLMN selector files.
- Added one-click EPC/HSS provisioning from the SIM workbench and an independent production confirmation view for HSS, EPC, S1, Nokia reachability, attach evidence, and subscriber data.
- Expanded the private production worksheet with camera/IoT role, vineyard zone, optional ICCID, protected credentials, PLMN/APN settings, and a read-back checklist.

## 0.5.5

- Expanded the offline roaming lab into a closed synthetic infrastructure emulator.
- Added component health lights for the test UE, visited MME, Diameter edge, home HSS, SGW/PGW, and data probe.
- Added an 11-message NAS, S6a, bearer, and data trace with scenario-specific failure and blocked states.
- Generates short-lived synthetic lab identities and authentication-vector metadata without retaining secrets or controlling live RF.

## 0.5.4

- Added an offline roaming-data simulator for external-carrier and public-safety-style attach flows.
- Models visited-MME detection, authorized Diameter routing, home-HSS policy, EPS-AKA, bearer creation, and subscriber data breakout.
- Includes controlled success, missing-peer, roaming-denied, authentication-failure, and data-path-failure scenarios.
- Uses only synthetic test identities and never transmits a carrier PLMN, contacts AT&T/FirstNet, or modifies the live EPC.

## 0.5.3

- Added a pending-registration approval queue for explicit unknown-subscriber failures found in uploaded or remotely inspected EPC logs.
- Added administrator review and provisioning from both Estate Devices and Network Care.
- Preserves only safe attach metadata such as IMSI, requested APN, failure cause, source, timestamps, and observation count; SIM authentication secrets are never inferred or captured from logs.
- Requires the administrator to confirm the exact IMSI and supply matching K, OPc, and AMF values before provisioning.
- Added dismissal controls and prevents authentication failures for existing profiles from being treated as new subscriber requests.

## 0.5.2

- Added a light/dark appearance control to the app header.
- Uses the device color-scheme preference on first visit and remembers an explicit choice in that browser.
- Added a vineyard-toned dark palette across gauges, panels, forms, tables, charts, dialogs, tools, and mobile navigation.
- Replaced Nokia physical-connection checkboxes with non-interactive MAIN, DIV, GPS, power/Ethernet, and authorized-RF inspection cards.
- Added safe, read-only Nokia polling for radio reachability, HTTPS/TLS identity, management ports, and the EPC S1 listener.
- Added a private commissioning summary that identifies HTTPS OAM / Nokia BTS Site Manager as the intended access method while making disabled SSH and absent SNMP configuration explicit.
- Added Radio Site tools to open or copy the supported Nokia HTTPS address, inspect the container route to the radio, and download a safe status snapshot.

## 0.5.1

- Added subscriber traffic and connection gauges to the Overview page.
- Added live connection-fabric readiness, last-known EPC routing readiness, bidirectional packet evidence, and subscriber-profile completeness.
- Added explicit measurement freshness and unmeasured states so stale or unavailable EPC data is never shown as live throughput.

## 0.5.0

- Added an expanded network visibility board for EPC, S1, MongoDB, Nokia administration, SSH, DNS, site Internet, EPC routing, UE traffic, and communications.
- Added a health score, prioritized next actions, incident history, monitoring freshness, routing counters, and inventory-readiness metrics.
- Added safe one-click known-port, route, DNS/uplink, inventory, and incident tools.
- Added read-only EPC traffic, S1/session, GTP, connection-tracking, and clock-synchronization tools.
- Added searchable activity logs, log-type filters, and a redacted activity-log download.
- Added an optional outbound PBX gateway for confirmed voice announcements and text dispatch, plus SIP readiness checks and clear IMS/VoLTE guidance.

## 0.4.3

- Aligned LTE with the Baiamonte AIS and ADS-B visual system across desktop and mobile Home Assistant views.
- Added camera and vineyard-IoT roles, critical-device marking, operations notes, search, and role filtering.
- Added camera, field-IoT, and critical-asset counts to the Overview page.
- Added a redacted inventory export that excludes SIM authentication keys and OPc values.
- Added practical deployment guidance for cameras, field sensors, controls, and gateways.

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
