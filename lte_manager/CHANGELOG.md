# Changelog

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
