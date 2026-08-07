# Baiamonte LTE

## Install

1. In Home Assistant, open **Settings → Apps → App store**.
2. Open the menu, choose **Repositories**, and add this GitHub repository URL.
3. Install **Baiamonte LTE** and start it.
4. Enable **Show in sidebar**. Optionally enable **Automatic updates** on the Info page.

The initial values already point to EPC `192.168.1.151` and Nokia eNodeB `192.168.1.100`. Both devices and Home Assistant must have a route to Baiamonte’s internal `192.168.1.0/24` LTE network.

## Nokia commissioning

Connect the MAIN antenna to MAIN and the diversity antenna to DIV before enabling RF. Connect the GPS antenna and confirm a valid GPS lock in licensed Nokia BTS Site Manager. Import the supplied commissioning backup on the BTS page; the app stores it privately with mode `0600` but does not impersonate or automate Nokia Site Manager.

In Site Manager, verify:

- eNodeB management address: `192.168.1.100`
- MME/S1 target: `192.168.1.151`, SCTP port `36412`
- MCC, MNC, TAC, and LTE band match the EPC, SIMs, license, and authorized spectrum
- GPS is locked and alarms are clear before enabling RF

## UEs and SIMs

The UE page writes subscribers to NextEPC/Open5GS MongoDB and keeps a local index for the dashboard. Assign each device to a vineyard zone for filtering and operations. K and OPc are sensitive; keep Baiamonte LTE and Home Assistant access private.

The SIM page supports USB CCID readers through PC/SC, validates a profile, reports the detected reader name, and generates a reviewable pySim worksheet. Physical writing remains disabled by default. Enable it only when a compatible USB reader and programmable test SIM are attached. The exact administrative key and command sequence depend on the SIM vendor. A non-CCID programmer may require its vendor driver.

## Subscriber Internet access

Set `ue_subnet` to the address pool configured on the NextEPC PGW and set `epc_uplink_interface` to the EPC server's Internet-facing interface. Network Care then shows the expected UE → APN → PGW → NAT → Internet path and includes these checks in diagnostics.

On the EPC host, an administrator must:

1. Confirm the APN address pool matches `ue_subnet`.
2. Enable IPv4 forwarding.
3. Masquerade the UE subnet out `epc_uplink_interface` and allow established return traffic.
4. Persist those settings using the EPC operating system's supported firewall method.
5. Attach a subscriber and open a public HTTPS site from that UE. This is the required end-to-end proof that subscriber Internet routing works.

The Home Assistant app deliberately does not rewrite the firewall on the separate EPC server. Apply these changes directly on `192.168.1.151`, after confirming the correct subnet and uplink interface.

## Availability alerts

The app samples EPC and radio reachability every minute and retains 30 days of connection history. On the Overview page, choose which offline conditions should notify Home Assistant, how many failed checks trigger an alert, and the minimum repeat interval. A recovery notification replaces the offline notification when service returns.

Only operate radio equipment on frequencies, power levels, and locations you are authorized to use.
