# Baiamonte LTE

## Install

1. In Home Assistant, open **Settings → Apps → App store**.
2. Open the menu, choose **Repositories**, and add this GitHub repository URL.
3. Install **Baiamonte LTE** and start it.
4. Enable **Show in sidebar**. Optionally enable **Automatic updates** on the Info page.

Use the moon/sun button in the app header to switch between light and dark appearance. On the first visit the app follows the device preference; afterward the selection is remembered separately in each browser or Home Assistant companion app.

Set the EPC and Nokia eNodeB addresses in the add-on configuration before first use. The public defaults use the documentation-only `192.0.2.0/24` range so private estate infrastructure is not published. Existing Home Assistant options are preserved during updates.

## Nokia commissioning

Connect the MAIN antenna to MAIN and the diversity antenna to DIV before enabling RF. Connect the GPS antenna and confirm a valid GPS lock in licensed Nokia BTS Site Manager. Import the supplied commissioning backup on the BTS page; the app stores it privately with mode `0600` but does not impersonate or automate Nokia Site Manager.

The Radio Site page presents these connections as non-interactive inspection cards. It does not use checkboxes or claim to detect cable presence; confirm the hardware physically and use Nokia alarms or BTS Site Manager for electronic status.

The commissioning backup identifies **HTTPS OAM through Nokia BTS Site Manager/WebEM** as the available management route: OAM TLS is forced, while the service-account SSH interface is disabled and no SNMP management configuration is present. The Radio Site poll therefore performs safe, read-only ICMP, HTTPS/TLS, HTTP, SSH-port, and EPC S1-listener checks. It displays the radio certificate SHA-256 fingerprint for identity comparison, but does not automatically trust the certificate or attempt to sign in. Live GPS lock, RF state, temperature, alarms, and Nokia operational counters still require the licensed Nokia management software or a vendor-supported export/API.

Radio Operations includes shortcuts to open or copy the Nokia HTTPS management address, inspect the Home Assistant app container's route to the radio, and download the current safe diagnostic snapshot. These tools do not enable RF, change the commissioning profile, bypass the Nokia login, or accept arbitrary network commands.

In Site Manager, verify:

- eNodeB management address: the address configured for your estate radio
- MME/S1 target: the configured EPC address, SCTP port `36412`
- MCC, MNC, TAC, and LTE band match the EPC, SIMs, license, and authorized spectrum
- GPS is locked and alarms are clear before enabling RF

## UEs and SIMs

The UE page writes subscribers to NextEPC/Open5GS MongoDB and keeps a local index for the dashboard. Assign each device to a vineyard zone for filtering and operations. K and OPc are sensitive; keep Baiamonte LTE and Home Assistant access private.

### Pending registration approvals

When an uploaded EPC log or the guarded **Recent EPC logs** tool contains an explicit missing-subscriber failure with a numeric IMSI, Baiamonte LTE adds it to the Pending Registrations queue. The queue stores only the IMSI, requested APN when present, a normalized failure cause, source label, timestamps, and the number of scans that observed it. Raw log lines and SIM secrets are not retained.

An administrator can review the request from **Estate devices** or **Network care**, verify the IMSI against the physical SIM inventory, and provision it using the matching K, OPc, AMF, APN, device role, and vineyard zone. The exact IMSI must be confirmed by the approval request. LTE attach signaling does not reveal K or OPc, so those values must come from the secure SIM programming record. Provisioning is never automatic. Authentication failures for existing subscribers remain troubleshooting findings and are not turned into new-subscriber approvals.

### Offline roaming lab

Network Care includes an offline external-carrier roaming simulator. It uses synthetic `001/01` and `001/02` test PLMNs to model visited-MME identification, an authorized Diameter/S6a route, home-HSS policy, EPS-AKA, default-bearer creation, and data breakout. The administrator can select a successful flow or inject a missing peer, roaming denial, authentication mismatch, or data return-path failure.

The lab is educational and diagnostic only. It never contacts AT&T or FirstNet, never broadcasts a carrier identity, never uses a retail IMSI, and never changes the Nokia or live EPC. A successful simulation does not authorize an external SIM; live roaming still requires a carrier agreement and authenticated home-HSS connectivity.

The SIM page supports USB CCID readers through PC/SC, validates a profile, reports the detected reader name, and generates a reviewable pySim worksheet. Physical writing remains disabled by default. Enable it only when a compatible USB reader and programmable test SIM are attached. The exact administrative key and command sequence depend on the SIM vendor. A non-CCID programmer may require its vendor driver.

## Subscriber Internet access

Set `ue_subnet` to the address pool configured on the NextEPC PGW and set `epc_uplink_interface` to the EPC server's Internet-facing interface. Network Care then shows the expected UE → APN → PGW → NAT → Internet path and includes these checks in diagnostics.

On the EPC host, an administrator must:

1. Confirm the APN address pool matches `ue_subnet`.
2. Enable IPv4 forwarding.
3. Masquerade the UE subnet out `epc_uplink_interface` and allow established return traffic.
4. Persist those settings using the EPC operating system's supported firewall method.
5. Attach a subscriber and open a public HTTPS site from that UE. This is the required end-to-end proof that subscriber Internet routing works.

### EPC Routing Assistant

Version 0.4.0 can apply and verify these changes from **LTE → Network care → Configure routing on the EPC**. It is disabled by default.

1. In the app Configuration, enable `epc_routing_management_enabled`.
2. Confirm `epc_ssh_user`, `epc_ssh_port`, `ue_subnet`, and `epc_uplink_interface`, then restart the app.
3. Select **Generate dedicated SSH key**, copy the displayed public key, and add it to the configured EPC user’s `authorized_keys` file. Alternatively, upload an existing unencrypted private key whose public key is already authorized. The account must be `root` or have passwordless `sudo` for the managed commands.
4. Scan the EPC host fingerprint and compare it with the fingerprint shown locally on the EPC before selecting **Trust this fingerprint**.
5. Review the plan, apply it, and run **Check current routing**.
6. Start the live traffic test, turn off Wi-Fi on an attached LTE device, open a new public HTTPS site, and finish the test. The Overview Internet light turns green only when outbound, NAT, and established-return counters all increase.

The assistant does not accept arbitrary commands or install packages. It creates only `baiamonte-lte-routing.service`, `/usr/local/sbin/baiamonte-lte-routing`, `/etc/sysctl.d/99-baiamonte-lte.conf`, and three exact iptables rules. Rollback removes those items and restores the forwarding value captured before the first apply. The EPC must use Linux with systemd and iptables.

## SIM authentication utilities

The SIM workbench calculates Milenage OPc from K and OP using `OPc = AES-128(K, OP) XOR OP`. It also generates cryptographically random K and OP values for owned programmable test SIMs. These values are returned to the browser only and are not written to the app database or activity log. Use **Use in profile** to copy K and OPc into the pySim worksheet without retyping them.

## Availability alerts

The app samples EPC and radio reachability every minute and retains 30 days of connection history. On the Overview page, choose which offline conditions should notify Home Assistant, how many failed checks trigger an alert, and the minimum repeat interval. A recovery notification replaces the offline notification when service returns.

## Network visibility and troubleshooting

The Overview page distinguishes measured reachability from end-to-end verification. EPC, S1, MongoDB, Nokia management, SSH, DNS, site Internet, routing, UE data, and the optional communications gateway each have their own state. **Not verified** means the app does not have enough evidence; it does not mean the service is working or failed.

The subscriber data pulse adds four gauges: current EPC/radio/S1/registry reachability, readiness of the seven managed routing checks, bidirectional traffic evidence from cumulative EPC firewall counters, and the percentage of subscriber profiles assigned both a device role and vineyard zone. Routing and traffic gauges use the last successful EPC routing check and show their age. They are operational evidence—not bandwidth, data-usage, billing, or per-device session measurements.

Network Care includes allowlisted tools for known service ports, container routes, DNS/uplink checks, inventory readiness, and incident history. With trusted EPC SSH access it also provides read-only core-process, interface, firewall, traffic-counter, S1/session, time-sync, and journal views. Arbitrary shell commands are not accepted. Activity can be searched by type and downloaded; support bundles and exports exclude subscriber authentication secrets and communications tokens.

## Optional outbound voice and text

The app can send a confirmed outbound request to a separately operated PBX gateway. Configure these Home Assistant app options and restart:

- `communications_enabled`: enable only after the gateway is ready
- `communications_gateway_url`: HTTP(S) endpoint that accepts JSON fields `kind`, `to`, `message`, and `source`
- `communications_gateway_token`: optional bearer token, stored as a protected app option and never returned to the browser or support bundle
- `sip_gateway_host`, `sip_gateway_port`, `sip_transport`: optional TCP/TLS reachability check for the PBX or SIP proxy

Each dispatch requires typing `SEND`. The activity log records only that the configured gateway accepted a voice or text request; it does not record the recipient or message body. The gateway is responsible for authentication, rate limits, emergency-number blocking, provider rules, and delivery reporting.

This feature is not a native VoLTE/IMS implementation. Native handset dialer calls and carrier-style SMS require an IMS core, IMS-capable SIM/UE provisioning, a supported EPC, and a lawful SIP/PSTN or SMS interconnect. App-based SIP clients can use the LTE data connection without native VoLTE.

Only operate radio equipment on frequencies, power levels, and locations you are authorized to use.
