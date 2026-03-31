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
- Protocol version is tracked separately as Sig-Net v0.12.

## Version History

- 1.0.1 (2026-03-31)
	- Blind fix of reported +1 offset on RDM payload.
	- Fix for zero length TID_LEVEL.

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
