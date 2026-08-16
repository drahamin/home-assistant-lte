# Changelog

## 0.6.7

- Added a two-way Nokia radio-profile editor for MCC, MNC, TAC, eNodeB/cell identity, PCI, LTE band, DL/UL EARFCN, bandwidth, and transmit power.
- Added live Nokia-to-app comparison states with exact matches, differences, unavailable fields, validation errors, and fresh readback confirmation.
- Added guarded import of reported Nokia values into the persistent Baiamonte LTE target profile.
- Added guarded app-to-Nokia configuration through the explicitly configured licensed control gateway; gateway acceptance is kept separate from verified Nokia readback.
- Added range, PLMN-length, bandwidth-choice, and FDD EARFCN-pair validation before either side can be changed.

## 0.6.6

- Added the same physical-card ATR lookup used by Rahamin Pi LTE for the Gialer programmable LTE USIM.
- Recognizes the known Gialer profile only after the inserted card's ATR matches and labels the detected card/profile source in the SIM workbench.
- Uses the matched `gialersim` pySim card type automatically while keeping ADM in Home Assistant's private password setting or accepting it for one guarded write.
- Added a configurable SIM carrier profile with the default friendly name `rNET`; physical programming writes it through pySim to EF.SPN and reads it back when the card exposes that file.
- Displays the rNET friendly name, home PLMN, APN, selection policy, and SIM files together as one production carrier profile.

## 0.6.5

- Added guarded replacement-card programming from an existing Baiamonte subscriber while keeping K and OPc server-side and out of the browser.
- Added recoverable SIM write transactions: if ICCID/IMSI read-back succeeds but EPC/HSS provisioning fails, the retained private profile can be recovered after the inserted card identity is verified again.
- Added server-side SIM programming progress, single-operation locking, and live write/verify/provision status in the SIM workbench.
- Added inserted-card verification against the subscriber registry and non-secret production inventory.
- Keeps vendor ADM credentials private and out of logs; known-card lookup is introduced separately in 0.6.6.

## 0.6.4

- Added a guarded **Program SIM + EPC** transaction that writes registration-critical ICCID, IMSI, K, OPc, MCC/MNC, MNC length, and access class with pinned official Osmocom pySim, reads ICCID/IMSI back, and only then provisions the matching EPC/HSS record.
- Added private Home Assistant settings for the vendor ADM credential, ADM format, and optional exact pySim card type; ADM, K, and OPc are excluded from public settings and logs.
- Expanded the SIM readiness view and production checklist for PLMN selectors, forbidden-network review, cached-location reset, APN, and EPC/HSS policy.
- Added measured download/upload traffic-history graphs with 6-hour, 24-hour, and 7-day ranges, totals, current rates, and explicit not-measured states.
- Added configurable background EPC traffic sampling and byte counters alongside the existing packet evidence.

## 0.6.3

- Reduced the web service from two worker processes to one four-thread worker with bounded request recycling for a smaller Home Assistant memory footprint.
- Stopped phone log and Nokia polling while the page is hidden, slowed background refreshes, and prevented overlapping radio polls.
- Initialized and migrated SQLite once per process instead of on every database operation, and added a supporting event-time index.
- Added configurable monitor cadence plus bounded history/event retention, hourly cleanup, and 2 MB rotating application logs.
- Added a compact Home Assistant resource panel showing web-process memory, local database/log storage, monitor cadence, retained samples, and worker profile.

## 0.6.2

- Added one-tap generation of a unique PLMN-matching IMSI, K, OP, OPc, AMF, PIN, PUK, APN, and an ICCID programming candidate for owned programmable USIMs.
- Added read-only PC/SC card inspection for ICCID, IMSI, ATR, administrative data, access class, PLMN selectors, forbidden networks, and location data.
- Added local private-profile import and a guarded replacement-card copy workflow without claiming protected USIM authentication keys can be extracted.
- Added Home Assistant reader name, reader index, and T=0/T=1 protocol configuration plus separate reader/writer discovery lights.
- Added a live SIM commissioning-process strip and compacted the requested radio, network-health, gauge, physical-connection, PLMN, and guided-handoff sections.
- Added subtle animated state lights, gauge breathing, and staged card entrances with reduced-motion support.

## 0.6.1

- Added a filtered Nokia operations feed for cell, RF, GNSS, synchronization, S1/MME, active-UE, temperature, VSWR, channel, software, alarm, and event data.
- Added guarded Nokia cell lock/unlock, synchronization, alarm acknowledgement, and restart controls through an explicitly configured licensed HTTPS adapter.
- Added a configured LTE channel panel with eNodeB TX/downlink and RX/uplink frequencies, EARFCNs, duplex spacing, bandwidth, PCI, identity, and power target.
- Expanded Home Assistant configuration for the complete production radio, core, subscriber, PLMN, Nokia status, and Nokia control profile.
- Compacted the radio overview and guided SIM commissioning steps for mobile operation.

## 0.6.0

- Removed the synthetic roaming lab to keep the interface focused on the production Baiamonte camera and IoT network.
- Added a six-stage SIM commissioning pipeline covering identity, authentication, physical USIM programming, HSS provisioning, device configuration, and live acceptance.
- Added LTE network-selection guidance for EF.PLMNwAcT, EF.OPLMNwAcT, EF.HPLMNwAcT, EF.FPLMN, EF.EPSLOCI, EF.LOCI, EF.AD, and EF.ACC.
- Added complete LTE USIM home/preferred/forbidden network-selection guidance and cached-location review.
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
