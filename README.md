##==============================================================================
## Sig-Net Protocol Framework - Wireshark Lua Dissector
##==============================================================================

## Copyright (c) 2026 Singularity (UK) Ltd.

## Sig-Net Wireshark Lua Dissector

This repository contains a Wireshark Lua post-dissector for Sig-Net. 

## Files

- `sig-net.lua`: Sig-Net dissector plugin.

## What it does

- Activates on CoAP packets whose Uri-Path contains `sig-net`.
- Reparses the CoAP packet to extract Sig-Net custom options defined in Section 8.
- Decodes Sig-Net TLVs with detailed field-level output.
- Attempts to hand `TID_RDM_COMMAND` and `TID_RDM_RESPONSE` payloads to Wireshark's built-in RDM dissector.
- Does not verify or calculate the HMAC.

## Install

Copy `sig-net.lua` into one of Wireshark's Lua plugin directories, for example:

- `%APPDATA%\Wireshark\plugins`
- typically C:\Users\[Username]\AppData\Roaming\Wireshark\plugins
- Wireshark's global `plugins` directory inside the installation tree

- You may need to create the Plugins folder.

Then restart Wireshark. (Not sure if this is required)

## Run

Use `signet` (no hyphen) in the display filter.

- Display filter name: `signet`
- Sig-Net URI path value: `sig-net`

These are different on purpose. The display filter is derived from the Lua protocol registration name, while the URI path is the on-wire protocol path.

## Versioning

- Plugin versioning uses semantic versioning (MAJOR.MINOR.PATCH).
- Protocol version is tracked separately as Sig-Net v1.04 and SNOW v0.7.

## Version History

- 1.2.1 (2026-06-14)
	- Fixed TLV field-to-frame mapping for Wireshark column usage by adding `signet.tlv.tid`, `signet.tlv.length`, and `signet.tlv.value` using absolute offsets from the top-level packet buffer.
	- Added packet-level summary field `signet.tids_present` (`TIDs Present`) with a comma-separated list of decoded TIDs to support reliable "Apply as Column" for multi-TLV packets.
	- Added `TID_PREVIEW` (0x0103) name and decoder coverage for Sig-Net v1.04 completeness.

- 1.2.0 (2026-06-13)
	- Refactored to align with Sig-Net v1.04 and SNOW v0.7.
	- Changed dissector protocol abbreviation to `signet` and converted all ProtoField filter IDs to lowercase for reliable "Apply as Column" behavior.
	- Added explicit protocol column setter and preserved field-backed tree population for all key decode paths.
	- Updated Sig-Net security mode enums: added `0x01` Open Mode and changed `0xFF` label to Offboarded Device Beacon.
	- Added and updated Sig-Net TIDs and decoders including `TID_UNIVERSE` (0x0203), `TID_OSC` (0x0204), `TID_RDM_EP_CONFIG` (0x0305), `TID_RT_OFFBOARD` (0x0401), `TID_RT_OTW_CAPABILITY` (0x060D), `TID_EP_PROTOCOL` (0x090B), and `TID_EP_IDENTIFY` (0x090C).
	- Updated bitfield/value decoders for `TID_RT_IDENTIFY`, `TID_RT_STATUS`, `TID_RT_ROLE_CAPABILITY` (now 4-byte), `TID_EP_CAPABILITY` (now 4-byte), `TID_EP_DIRECTION`, `TID_EP_STATUS`, and `TID_EP_FAILOVER`.
	- Expanded `TID_DG_SECURITY_EVENT` event code enum coverage (0x0005, 0x0006, 0x0007).
	- Added SNOW TOTW namespace decode support for `0x7001` through `0x700C`.
	- Added payload fallback handling to decode Sig-Net/SNOW TLVs from UDP/TCP/data payloads when CoAP URI metadata is unavailable, preserving compatibility with stream-layer transport paths.

- 1.1.0 (2026-04-06)
	- Updated dissector target to Sig-Net v0.15.
	- Added TID decode coverage for `TID_RDM_FLOW_CONTROL` (0x0306).
	- Added TID decode coverage for `TID_RT_REBOOT` (0x060A) and `TID_RT_MODEL_NAME` (0x060B).
	- Added TID decode coverage for `TID_EP_FAILOVER` (0x0908), `TID_EP_DMX_TIMING` (0x0909), and `TID_EP_REFRESH_CAPABILITY` (0x090A).
	- Updated `TID_RT_IDENTIFY` decode options to v0.15 states: Off, Identify Subtle, Identify Full, and Mute indicators/backlights.
	- Updated `TID_EP_CAPABILITY` (0x0904) decode and renamed display from legacy `TID_EP_DIRECTION_CAPABILITY`.
	- Renamed displayed `TID_RT_MULT` (0x0606) to `TID_RT_MULT_OVERRIDE` for v0.15 naming alignment.

- 1.0.1 (2026-03-31)
	- Blind fix of reported +1 offset on RDM payload.
	- Fix for zero length `TID_RDM_TOD_DATA`.

- 1.0.0 (2026-03-30)
	- Initial public Wireshark Lua post-dissector release.
	- CoAP Sig-Net custom option decoding and TLV decode support.
	- RDM TLV handoff path included.

## Notes

- This is implemented as a post-dissector so the normal CoAP dissection remains visible.
- Wireshark may show yellow CoAP expert warnings such as `Unknown Option Number 2076` for Sig-Net private CoAP options (2076, 2108, 2140, 2172, 2204, 2236). This is expected in Lua post-dissector mode and does not mean Sig-Net decoding failed.
- The plugin is defensive about malformed CoAP options and malformed TLV lengths.
- Validated to load in the local Wireshark 4.6 installation via TShark.
- This should handoff TID_RDM to the 'rdm`, dissector - not yet tested.
