V1.0

![](media/image1.png){width="3.9850371828521434in" height="1.0176727909011374in"}

Copyright Singularity (UK) Ltd 2026

# Table of Contents {#table-of-contents .TOC-Heading}

[Acknowledgements [5](#acknowledgements)](#acknowledgements)

[1 Introduction [6](#introduction)](#introduction)

[1.1 Overview [6](#overview)](#overview)

[1.2 Goals [6](#goals)](#goals)

[1.3 Conditions of Use [6](#conditions-of-use)](#conditions-of-use)

[1.4 Compliance Notice & Disclaimer [6](#compliance-notice-disclaimer)](#compliance-notice-disclaimer)

[1.5 Vulnerability Disclosure [7](#vulnerability-disclosure)](#vulnerability-disclosure)

[2 References to other Documents [7](#references-to-other-documents)](#references-to-other-documents)

[2.1 Normative References [7](#normative-references)](#normative-references)

[2.2 Informative References [8](#informative-references)](#informative-references)

[3 Definitions [8](#definitions)](#definitions)

[3.1 Document Conventions [8](#document-conventions)](#document-conventions)

[3.2 Byte Order [8](#byte-order)](#byte-order)

[3.3 Octet and Byte [8](#octet-and-byte)](#octet-and-byte)

[4 Cryptographic Concepts [8](#cryptographic-concepts)](#cryptographic-concepts)

[4.1 Asymmetric Provisioning [8](#asymmetric-provisioning)](#asymmetric-provisioning)

[4.2 TLV Type Namespace [9](#tlv-type-namespace)](#tlv-type-namespace)

[4.3 Proof of Management [9](#proof-of-management)](#proof-of-management)

[5 Sig-Net Recovery Protocol (SNRP) [9](#sig-net-recovery-protocol-snrp)](#sig-net-recovery-protocol-snrp)

[5.1 IP Rescue (COME_HOME) [9](#ip-rescue-come_home)](#ip-rescue-come_home)

[5.2 Authenticated Rescue (POM Wipe) [9](#authenticated-rescue-pom-wipe)](#authenticated-rescue-pom-wipe)

[5.3 Rotation Trigger (OTW Reopen) [9](#rotation-trigger-otw-reopen)](#rotation-trigger-otw-reopen)

[5.4 Operational Restrictions [10](#operational-restrictions)](#operational-restrictions)

[5.5 User-Initiated Force Beaconing [10](#user-initiated-force-beaconing)](#user-initiated-force-beaconing)

[6 Secure Tunnel Mechanics [10](#secure-tunnel-mechanics)](#secure-tunnel-mechanics)

[6.1 The Universal Rendezvous Scope [10](#the-universal-rendezvous-scope)](#the-universal-rendezvous-scope)

[6.2 Offboarded Discovery and Port Announcement [11](#offboarded-discovery-and-port-announcement)](#offboarded-discovery-and-port-announcement)

[6.3 The Secure Handshake [11](#the-secure-handshake)](#the-secure-handshake)

[6.4 Authentication [11](#authentication)](#authentication)

[6.4.1 Optical PIN Verification (QR Code) [12](#optical-pin-verification-qr-code)](#optical-pin-verification-qr-code)

[6.5 Key Delivery & Privilege [12](#key-delivery-privilege)](#key-delivery-privilege)

[6.6 Pre-Authenticated Onboarding (Manifest Files) [13](#pre-authenticated-onboarding-manifest-files)](#pre-authenticated-onboarding-manifest-files)

[6.7 Tunnel Teardown and Handoff [13](#tunnel-teardown-and-handoff)](#tunnel-teardown-and-handoff)

[7 Ongoing Security Management [13](#ongoing-security-management)](#ongoing-security-management)

[7.1 Key Rotation [13](#key-rotation)](#key-rotation)

[7.1.1 Symmetric Key Rotation Lifecycle [14](#symmetric-key-rotation-lifecycle)](#symmetric-key-rotation-lifecycle)

[7.2 Revocation [14](#revocation)](#revocation)

[7.3 Limitations [14](#limitations)](#limitations)

[8 Packet Structure and Transport [14](#packet-structure-and-transport)](#packet-structure-and-transport)

[8.1 CoAP Encapsulation [14](#coap-encapsulation)](#coap-encapsulation)

[8.2 Security Options and HMAC [14](#security-options-and-hmac)](#security-options-and-hmac)

[8.3 Payload Syntax (TOTW) [15](#payload-syntax-totw)](#payload-syntax-totw)

[9 TOTW Payload Definitions [15](#totw-payload-definitions)](#totw-payload-definitions)

[9.1 TOTW_RT_COME_HOME [15](#totw_rt_come_home)](#totw_rt_come_home)

[9.2 TOTW_RT_PUBLIC_KEY [16](#totw_rt_public_key)](#totw_rt_public_key)

[9.3 TOTW_RT_IDENTIFY [16](#totw_rt_identify)](#totw_rt_identify)

[9.4 TOTW_RT_KEY_KS [18](#totw_rt_key_ks)](#totw_rt_key_ks)

[9.5 TOTW_RT_KEY_KC [19](#totw_rt_key_kc)](#totw_rt_key_kc)

[9.6 TOTW_RT_KEY_KM_GLOBAL [20](#totw_rt_key_km_global)](#totw_rt_key_km_global)

[9.7 TOTW_RT_KEY_KM_LOCAL [21](#totw_rt_key_km_local)](#totw_rt_key_km_local)

[9.8 TOTW_RT_KEY_K0 [21](#totw_rt_key_k0)](#totw_rt_key_k0)

[9.9 TOTW_RT_POM_PUBLIC_KEY [22](#totw_rt_pom_public_key)](#totw_rt_pom_public_key)

[9.10 TOTW_RT_POM_WIPE [23](#totw_rt_pom_wipe)](#totw_rt_pom_wipe)

[9.11 TOTW_RT_OTW_REOPEN [23](#totw_rt_otw_reopen)](#totw_rt_otw_reopen)

[9.12 TOTW_RT_UPDATE_POM [24](#totw_rt_update_pom)](#totw_rt_update_pom)

[9.13 TOTW_RT_SCOPE [24](#totw_rt_scope)](#totw_rt_scope)

[10 Example Operational Workflows (Informative) [24](#example-operational-workflows-informative)](#example-operational-workflows-informative)

[10.1 The Touring Manifest Workflow [24](#the-touring-manifest-workflow)](#the-touring-manifest-workflow)

[10.2 The \"Hostage Fixture\" Rescue [24](#the-hostage-fixture-rescue)](#the-hostage-fixture-rescue)

[10.3 Routine Key Rotation [25](#routine-key-rotation)](#routine-key-rotation)

[11 Appendix G Document Revisions (Informative) [27](#appendix-g-document-revisions-informative)](#appendix-g-document-revisions-informative)

# Acknowledgements 

Singularity (UK) Ltd would like to thank for following individuals for their assistance in the evolution of SNOW:

> Chris Kennedy
>
> Tracy Fitch
>
> Peter Newman
>
> Lars Wernlund
>
> Richard Thompson
>
> Christian Reese
>
> Shep Dick

# Introduction 

## Overview 

The core Sig-Net protocol mandates physical, out-of-band onboarding to transfer the Root Key (K0). This approach guarantees that physical proximity remains the absolute root of trust, protecting the network from remote interception during setup.

However, in large-scale environments, physically accessing hundreds of suspended fixtures to manually input passcodes is operationally prohibitive.

The Sig-Net Over Wire (SNOW) Onboarding Framework provides a secure over-the-wire option. It defines a Public Key Infrastructure (PKI) and an ephemeral TLS/DTLS tunnel mechanism, allowing a Manager to remotely and securely distribute derived cryptographic keys to unprovisioned devices.

## Goals

- Secure Distribution: Provide a cryptographically sound method to transfer derived role keys across an untrusted network.

- Key Lifecycle Management: Define a Manager-owned Public Key directory to facilitate remote, zero-touch Key Rotation and Revocation.

- V1 Interoperability: Ensure maximum interoperability on the same network between manually onboarded devices and OTW-onboarded devices.

## Conditions of Use 

SNOW™ is a proprietary protocol designed and owned by Singularity (UK) Ltd.

Singularity (UK) Ltd hereby grants a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to any person or entity (\"Licensee\") to develop, manufacture, and distribute software or hardware that implements the SNOW protocol, subject to the following conditions:

1.  Attribution: The Licensee shall include the following credit in the product\'s user manual, digital \'About\' screen, or accompanying technical documentation: \"SNOW™ Designed by and Copyright Singularity (UK) Ltd.\"

2.  Product Identification: The Licensee shall assign a unique product identifier (SoemCode) for each product or product variant, and report it accurately during a SNOW transaction.

3.  Trademarks: The Licensee acknowledges that SNOW, Sig-Net™ and Multicast Folding™ are trademarks of Singularity (UK) Ltd. When using these trademarks in product marketing or user interfaces, the Licensee agrees to adhere to the branding guidelines available at www.Sig-Net.info.

By implementing SNOW in any product or system, the Licensee agrees to be bound by these conditions. This licence is governed by the laws of England and Wales. Any disputes arising under or in connection with this licence shall be subject to the exclusive jurisdiction of the courts of England and Wales.

## Compliance Notice & Disclaimer 

Compliance with this protocol specification is the sole and exclusive responsibility of the manufacturer or provider and is entirely within their control and discretion. Any markings, identification or other claims of compliance do not constitute certification or approval of any type or nature whatsoever by Singularity (UK) Ltd (SUL).

SUL neither guarantees nor warrants the accuracy or completeness of any information published herein and disclaims liability for any personal injury, property or other damage or injury of any nature whatsoever, whether special, indirect, consequential or compensatory, directly or indirectly resulting from the publication, use of, or reliance on this document.

SNOW is provided by SUL \"AS IS\", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability or fitness for a particular regulatory purpose.

Singularity (UK) Ltd does not warrant that implementations of SNOW™ will not infringe upon the intellectual property rights or patents of third parties.

While SNOW incorporates security concepts designed to assist manufacturers in securing their network interfaces, use of this protocol does not guarantee compliance with the EU Cyber Resilience Act (CRA), the UK Product Security and Telecommunications Infrastructure (PSTI) Act, California SB-327, Oregon HB-2395, or any other cybersecurity legislation.

Secure operation of a SNOW network is a shared responsibility, requiring proper product implementation by the manufacturer and diligent lifecycle management by the system integrator and end user.

Regulatory compliance is evaluated on the final manufactured product (including hardware design, key storage mechanisms, firmware implementation, and lifecycle management). Compliance is the sole and exclusive responsibility of the manufacturer implementing the protocol. SUL shall not be held liable for any regulatory fines, product recalls, compliance failures, or damages of any nature directly or indirectly resulting from the implementation of this document.

## Vulnerability Disclosure

SUL maintains a vulnerability disclosure policy for this specification. Security vulnerabilities discovered in the SNOW protocol design should be reported to: office@singularity-uk.com.

Manufacturers implementing SNOW are independently responsible for establishing and publishing their own vulnerability handling processes as required by Article 13(6) of the EU Cyber Resilience Act.

# References to other Documents 

## Normative References 

This section details external documents and standards that are referenced by this specification.

- \[CoAP\] RFC 7252 The Constrained Application Protocol (CoAP)

> This standard is maintained by the IETF.

- \[HMAC\] RFC 2104 HMAC: Keyed-Hashing for Message Authentication

> This standard is maintained by the IETF.

- \[HKDF\] RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

> This standard is maintained by the IETF

- \[RFC 5705\] RFC 5705 Keying Material Exporters for Transport Layer Security (TLS).

> This standard is maintained by the IETF.

- \[SHA\] FIPS PUB 180-4 Secure Hash Standard (SHS)

> This standard is maintained by the NIST.

- \[Shannon\] C. E. Shannon, \"A Mathematical Theory of Communication,\" in The Bell System Technical Journal, vol. 27, no. 3, pp. 379-423, July 1948.

> This paper defines the foundational mathematics of information entropy.

- \[CSPRNG\] NIST Special Publication 800-90A Revision 1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators.

> This standard is maintained by the National Institute of Standards and Technology (NIST).

- \[URI\] RFC 3986 Uniform Resource Identifier (URI): Generic Syntax.

> This standard is maintained by the IETF.

## Informative References

This section details external legal frameworks, guidelines, and regulatory texts that inform the secure design rationale of this specification but do not dictate protocol mechanics.

- \[CRA\] Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024 on horizontal cybersecurity requirements for products with digital elements and amending Regulations (EU) No 168/2013 and (EU) No 2019/1020 and Directive (EU) 2020/1828 (Cyber Resilience Act). <https://eur-lex.europa.eu/eli/reg/2024/2847/oj>

- \[ENISA\] European Union Agency for Cybersecurity (ENISA), Security by Design and Default Playbook, 2026.

- \[PSTI\] United Kingdom Product Security and Telecommunications Infrastructure Act 2022.

# Definitions 

## Document Conventions 

A name enclosed in square brackets (e.g. \[CoAP\]) refers to an external document (Section [2.1](#normative-references)) .

A name enclosed in angle brackets (e.g. \<mult_poll\>) is a symbolic name whose value is defined in Section [**Error! Reference source not found.**](#_Ref226796638).

## Byte Order 

All multi-byte data shall be transmitted in network byte order (Big-Endian).

## Octet and Byte 

Octet is an eight-bit byte. Octet and byte are used interchangeably in this document.

# Cryptographic Concepts

## Asymmetric Provisioning

All devices supporting OTW onboarding require an asymmetric Public/Private key-pair (e.g. ECDSA or RSA). This key-pair may be injected as a one-time factory provisioning event, or the device may self-generate the key-pair upon first boot. The Private Key must never leave the device\'s secure hardware storage.

## TLV Type Namespace

To prevent parser collisions with native Sig-Net Type Identifiers (TID\_), all payloads used within the SNOW onboarding tunnel and the Sig-Net Recovery Protocol (SNRP) use the TOTW\_ (Type Over-The-Wire) namespace.

## Proof of Management

SNOW-compliant devices shall support a single administrative \"Owner Identity Key\" known as the Proof of Management (POM) Public Key. This 64-byte key (secp256r1) represents the device\'s \"Owner.\" Possession of the corresponding Private Key allows a Manager to remotely offboard a device via the network if the primary Sig-Net keys are lost.

# Sig-Net Recovery Protocol (SNRP)

The Sig-Net Recovery Protocol (SNRP) serves as the out-of-band administrative channel for SNOW-compliant devices. It uses the standard discovery multicast group (\<mult_node_beacon\>) to rescue unreachable devices, execute remote factory resets, and trigger secure re-keying sessions.

## IP Rescue (COME_HOME)

If an offboarded device boots with an invalid, conflicting, or unreachable IP address (e.g. a DHCP failure resulting in an Auto-IP), the Manager cannot establish a TLS handshake with it.

To resolve this, the Manager may use the Sig-Net Recovery Protocol (SNRP). The Manager multicasts a TOTW_RT_COME_HOME command to the \<mult_node_beacon\> address. This unauthenticated command targets the device\'s TUID, providing it with a valid, routable IP Address, Subnet Mask, and Gateway. Upon receiving a matching TOTW_RT_COME_HOME command, the offboarded device applies the new IP configuration, tears down its old sockets, and resumes beaconing on the correct subnet, allowing the secure handshake to proceed.

## Authenticated Rescue (POM Wipe)

To rescue a \"Hostage Fixture\" (an onboarded device with lost keys), a Manager may transmit a TOTW_RT_POM_WIPE command via UDP Multicast to the \<mult_node_beacon\> group.

The payload shall contain the target TUID and a 64-bit Nonce.

The payload shall be cryptographically signed by the POM Private Key.

An onboarded device receiving this command shall verify the signature against its stored POM Public Key. If the signature is valid, the device shall execute a full WIPE and return to Beacon Mode.

## Rotation Trigger (OTW Reopen)

To initiate a secure key rotation on an onboarded device, the Manager transmits a TOTW_RT_OTW_REOPEN command via the SNRP protocol.

This command may be signed using either the device\'s active symmetric Km_local key (using an HMAC signature) or the owner\'s POM Private Key (using an asymmetric signature), as specified by the Signature Type flag in the payload.

Upon successful verification of the signature, the device shall:

1.  Temporarily open its ephemeral TLS port for the duration specified by the Timeout parameter in the payload (defaulting to 60 seconds if the parameter is set to 0).

2.  Proactively multicast its current TID_RT_OTW_CAPABILITY state (as defined in Sig-Net v1.0 Section 11.6.10) to the \<mult_node_send\> group, signed with its Citizen Key (Kc). This informs the initiating Manager that the TLS listener is active and identifies the specific port to target.

## Operational Restrictions

Onboarded devices shall explicitly ignore unauthenticated SNRP commands (such as TOTW_RT_COME_HOME). However, all SNOW-compliant devices, regardless of onboarding state, shall continue to listen to the SNRP multicast group for the cryptographically signed TOTW_RT_POM_WIPE and TOTW_RT_OTW_REOPEN commands.

## User-Initiated Force Beaconing 

An onboarded Manager operates silently with its TLS Server port closed.

In order to allow an onboarded manager to be onboarded by another manager it must send Beacons (e.g. a touring console that needs to be onboarded to a house console).\
Managers shall support a user-initiated 'Force Beaconing' mechanism. When Force Beaconing is activated, the Manager shall the Device shall immediately multicast three consecutive unauthenticated discovery beacons (Security-Mode 0xFF) to \<mult_node_beacon\> spaced \<on_demand_beacon_interval\> milliseconds apart.

# Secure Tunnel Mechanics

The Sig-Net Over-the-Wire (OTW) onboarding process isolates the asymmetric cryptographic handshake from the real-time lighting plane. The following diagram provides an overview of the handover from discovery/recovery to the secure tunnel.

![](media/image2.png){width="6.268055555555556in" height="4.324305555555555in"}

## The Universal Rendezvous Scope

All SNOW transactions shall operate exclusively on the \"local\" scope as defined in \[Sig-Net\].

This remains true regardless of whether the participating Managers or Nodes are currently onboarded and active on custom operational scopes. The \"local\" path serves as the single, universal rendezvous channel for the network, ensuring that secure pairing and emergency recovery can always be executed without pre-existing knowledge of the target\'s active show keys or scope strings.

## Offboarded Discovery and Port Announcement

An offboarded device broadcasts its presence to the \<mult_node_beacon\> multicast group. If the device supports SNOW, it includes the TID_RT_OTW_CAPABILITY payload in its beacon. This informs the discovering Manager of the specific ephemeral TLS port the device has opened.

## The Secure Handshake

Once a routable IP is established, the Manager initiates a standard TLS handshake via Unicast to the device\'s announced ephemeral OTW port. The Manager and the Device establish an anonymous, encrypted tunnel with forward secrecy (e.g. via ECDHE).

To ensure SNOW can be implemented on memory-constrained embedded microcontrollers without requiring advanced TLS extensions, the maximum size of any single TLS record transmitted during a SNOW session shall be constrained. A Manager shall not transmit a TLS ciphertext record exceeding 2,048 bytes. Device implementations may safely allocate TLS receive buffers based on this maximum payload limit.

## Authentication

To prevent Man-in-the-Middle (MITM) attacks during the anonymous over-the-wire key exchange, the tunnel must be authenticated to prove the initiating Manager is speaking to the genuine, physical target hardware. To facilitate rapid, zero-touch onboarding in touring or high-density environments, the manual authentication methods below (Method A/B) may be bypassed if the Manager possesses a Manifest File (Section 6.5) containing the target device\'s Public Key.

SNOW supports two authentication mechanisms, selected based on the target device\'s role and user interface capabilities:

- Method A: Visual TOFU (Trust On First Use)

  - Applicability: Permitted for Nodes and Senders. Prohibited for Equal Managers.

  - The Manager and the target Device establish an anonymous, encrypted TLS/DTLS tunnel. The Device transmits its Public Key within its self-signed certificate during the standard TLS handshake. The Manager holds this Public Key in a temporary, \"untrusted\" state.

  - The Manager transmits a TOTW_RT_IDENTIFY command down the encrypted tunnel. To generate the payload, both devices use the TLS Exporter interface (RFC 5705) to export 32 bytes of keying material using the label string \"EXPORTER-Sig-Net-SNOW-Identify\". This cryptographically binds the identify command to this specific tunnel.

  - The target Device verifies the fingerprint, and physically actuates or flashes its indicators.

  - The operator visually confirms the location of the identifying physical device on the rig and clicks \"Confirm\" in the Manager UI.

  - Upon confirmation, the Manager commits the Device\'s Public Key to its trusted directory, binding it permanently to the visually confirmed location.

- Method B: Cryptographic PIN Verification

  - Applicability: Optional for Senders/Nodes with display capabilities. MANDATORY for Equal Manager-to-Manager onboarding.

  - The Manager and the target Device establish an anonymous, encrypted TLS/DTLS tunnel. The Device transmits its Public Key during the handshake.

  - Both devices use the TLS Exporter interface (RFC 5705) to export 4 bytes of keying material using the label string \"EXPORTER-Sig-Net-SNOW-PIN\". To ensure cross-vendor interoperability, both devices shall treat these 4 bytes as a Network Byte Order (Big-Endian) 32-bit unsigned integer, and perform a modulo 1,000,000 operation to derive an identical, cryptographically secure 6-digit numeric PIN (000000 to 999999).

  - The target Device displays this 6-digit PIN (leading zero padded) on its physical user interface.

  - The operator physically reads the PIN on the target device and manually inputs it into the initiating Manager\'s UI.

  - Because the PIN is derived directly from the TLS session exporter, successful validation guarantees that no MITM attacker has intercepted the tunnel. The Manager immediately promotes the target\'s Public Key to \"Trusted\".

### Optical PIN Verification (QR Code)

The target Device may optionally render a QR Code on its physical user interface alongside the plain text PIN.

The QR specification shall be:

- QR Code Type: Standard QR Code, Version 1.

- Error Correction: Level M.

- Encoding Mode: Alphanumeric Mode.

- Payload Format: The ASCII string \"SNOW:\" followed immediately by the 6-digit PIN, left-padded with leading zeros (e.g. \"SNOW:001234\").

- Quiet Zone: The graphical display shall maintain a minimum quiet zone of 4 modules around the QR Code to ensure reliable.

## Key Delivery & Privilege

The cryptographic material delivered over the authenticated tunnel determines the operational authority of the receiving device on the network. The initiating Manager evaluates the Device\'s reported TID_RT_ROLE_CAPABILITY and executes one of the following key delivery scenarios:

- Nodes and Senders: To enforce the principle of Least Privilege, the Root Key (K0) is never transmitted to these devices. The Manager locally derives only the specific symmetric role keys required by the Device (e.g. Ks and Kc for a Sender; Km_global and Km_local for a Node) and transfers them down the tunnel.

<!-- -->

- Guest Managers (e.g. Touring Consoles): If an operator wishes to grant a visiting console the ability to discover the network and transmit real-time control data, without granting permission to permanently alter the venue\'s infrastructure, the initiating Manager generates and transmits only the global derived keys (Km_global, Ks, and Kc). The Root Key (K0) and the array of Node-specific management keys (Km_local) are withheld. Because the Guest Manager lacks K0, any configuration SET or OFFBOARD commands it attempts to transmit will fail HMAC verification on the Nodes.

- Equal Managers (e.g. Backup Consoles): If the receiving device requires total administrative parity with the primary Manager, the initiating Manager shall transmit the Master Root Key (K0) securely across the tunnel. To prevent unauthorised administrative cloning, this transaction shall be authenticated via Method B (Cryptographic PIN Verification).

In all scenarios, the initiating Manager packs each required key into a dedicated TOTW payload (e.g., TOTW_RT_KEY_KS, TOTW_RT_KEY_K0), and transfers the resulting TLV payload block over the TLS tunnel. During any successful OTW onboarding sequence, the Manager shall also transmit its POM Public Key (TOTW_RT_POM_PUBLIC_KEY) to the device. The device shall store this key in non-volatile memory. This key shall persist across offboarding and manual onboarding and is cleared via a factory reset.

## Pre-Authenticated Onboarding (Manifest Files)

To facilitate rapid, zero-touch onboarding, SNOW supports Pre-Authenticated Manifest Files. An operator can extract the asymmetric Public Keys from a batch of unprovisioned devices and compile them into a JSON Manifest File. When this Manifest File is loaded into a Manager via an out-of-band transfer, the Manager registers the listed Public Keys as \"Trusted.\"

When the unprovisioned fixtures are subsequently connected to the show network and announce their OTW ports, the Manager connects via TLS. Because the target device\'s Public Key matches a trusted entry in the imported Manifest, the Manager shall bypass the manual authentication step (Section 6.3) and proceed immediately to Key Delivery (Section 6.4).

A Manifest File is a JSON object used by Managers to pre-authorize devices. It is never processed by the Node.

{

\"sig-net_snow_manifest\": {

\"pom_public_key\": \"Base64_Encoded_Key\",

\"devices\": \[

{ \"tuid\": \"7A7000000001\", \"public_key\": \"Base64_Encoded_Key\" }

\]

}

}

Security Limitations: A Manifest File can only be used to onboard devices that are currently in an Offboarded state (Beacon Mode). If a device arrives at a venue still onboarded to a previous network\'s Root Key (K0), it will reject all SNOW connections. The device must be physically offboarded (as defined in Sig-Net v1.0 Section 7.7.2) or rescued via the POM framework (Section 5.2) before it can be managed by the new network.

## Tunnel Teardown and Handoff

Once the required key TLVs are successfully delivered, stored, and acknowledged, the Device immediately closes the TLS listener and tears down the connection. The Device commits the symmetric role keys to secure non-volatile storage and transitions to normal Sig-Net communication on UDP Port 5683.

# Ongoing Security Management

## Key Rotation

The Manager maintains a directory of all OTW Devices' Public Keys. This allows the Manager to re-key all devices remotely. During key rotation, the Manager derives new symmetric keys and establishes a new TLS tunnel with the device. The Manager verifies the identity of the device by matching the Public Key presented during the TLS handshake against its trusted directory. Once authenticated, the Manager pushes the new keys down the encrypted tunnel. As the Public Keys were definitively trusted during the initial onboarding phase, re-keying occurs securely in the background without the need for visual identification or PIN verification.\
Informative Note: The \"trusted directory\" is simply an internal database or list maintained by the Manager application, stored in non-volatile memory, which securely maps the TUID of each onboarded device to its validated asymmetric Public Key.

### Symmetric Key Rotation Lifecycle

During key rotation, Devices shall adhere to a Node-First transition sequence:

- Node Update Phase: The Manager shall first connect to all Nodes and deliver the new symmetric key.

- Dual-Key Transition Mode: Upon receiving a new symmetric key while an old key is still active, the Node shall enter Dual-Key Transition Mode for a maximum of \<key_rotation_overlap\> seconds.

- During this window, the Node shall maintain both the old and new keys in volatile memory.

> For every incoming packet on that stream, the Node shall first attempt to verify the HMAC using the new key. If verification fails, it shall fall back to verify using the old key. If both checks fail, the packet is discarded. The Node shall immediately discard the old key and exit this mode upon successfully verifying its first packet signed with the new key.

- Manager Update Phase: Once the Manager receives successful TLS confirmations from all Nodes, the Manager shall connect to the Senders (Transmitters) over TLS and deliver the new key. The Senders shall immediately switch to transmitting and signing packets using the new key only.

- Transition Expiry: Upon the expiration of the local \<key_rotation_overlap\> second timer, the Node shall permanently discard the old key from volatile memory and return to standard single-key verification.

## Revocation

The Manager\'s Public Key directory also facilitates device revocation. A list of active devices can be presented to the user. Devices that are no longer valid (e.g. a touring fixture that has been removed from the venue) can be revoked by the operator. The Manager effectuates this revocation simply by excluding the revoked device\'s Public Key from the next network-wide Key Rotation cycle.

## Limitations

While OTW-onboarded devices can coexist seamlessly on the same network with manually onboarded devices, the latter cannot be key-rotated or revoked via the network, as they do not possess an asymmetric Public Key registered with the Manager. This is an accepted operational limitation that can be mitigated by using the \<scope\> variable in the URI to logically subdivide mixed-capability networks.

# Packet Structure and Transport

The Sig-Net Over-The-Wire (OTW) Framework strictly reuses the packet architecture and Type-Length-Value (TLV) payload syntax defined in the core Sig-Net Protocol Framework.

## CoAP Encapsulation

All OTW and SNRP payloads shall be encapsulated within standard CoAP Non-Confirmable (NON) POST messages, adhering exactly to the CoAP Base Header and URI syntax rules defined in Sig-Net Section 8.

## Security Options and HMAC

The inclusion of the 6 mandatory Sig-Net Security Options and the Sig-Net-Auth HMAC (defined in Sig-Net V1.0 Section 8.3) depends entirely on the transport phase:

- SNRP Transport (Unauthenticated UDP): Packets transmitting TOTW_RT_COME_HOME to the \<mult_node_beacon\> multicast group are, by definition, unauthenticated. They shall set the Sig-Net-Security-Mode option to 0xFF (Offboarded). The Sig-Net-Auth (HMAC) option (Option 2236) shall be included with a Length of 0, and the responder shall bypass cryptographic verification (as defined in Sig-Net V1.0 Section 8.6, Step 1b).

- TLS Transport (The Secure Tunnel): Once the ephemeral TLS tunnel is established, the underlying transport is cryptographically secured by the TLS stack. To maintain parser consistency, CoAP payloads transmitted within the tunnel (e.g. TOTW_RT_IDENTIFY, TOTW_RT_KEY_KS) shall still include the 6 mandatory Sig-Net Security Options. The Sig-Net-Security-Mode shall be set to 0xFF (Offboarded), and the Sig-Net-Auth option shall be included with a Length of 0, as the TLS tunnel provides the requisite integrity and confidentiality. To ensure payloads are executed, a Sig-Net Device receiving CoAP packets via a secure TLS/TCP stream socket shall deliberately bypass the payload-drop restriction associated with Security-Mode 0xFF (defined in Sig-Net V1.0 Section 8.6, Step 1b) and fully process the TOTW TLVs.

- SNRP Authenticated UDP: Packets transmitting TOTW_RT_OTW_REOPEN shall set the Sig-Net-Security-Mode to 0x00 (Plaintext with HMAC). The Sig-Net-Auth (HMAC) option shall contain a valid signature generated using the current symmetric Km_local key.

> Note: TOTW_RT_POM_WIPE may utilize Mode 0xFF as it carries its own asymmetric signature within the TLV payload.

## Payload Syntax (TOTW)

The application payload following the CoAP 0xFF marker shall use the identical 4-byte TLV syntax (2-byte Identifier + 2-byte Length) defined in Sig-Net Section 10.1.

To prevent parser collisions with native control traffic, all OTW and SNRP payloads reside in a distinct namespace, using Type Over-The-Wire (TOTW) identifiers (defined in Section [9](#totw-payload-definitions)). Standard Sig-Net TIDs shall not be parsed or transmitted within the ephemeral TLS tunnel.

# TOTW Payload Definitions

The following Type Over-The-Wire (TOTW) identifiers are used exclusively during the SNRP and OTW TLS tunnel phases.

## TOTW_RT_COME_HOME

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Multicast SNRP command to rescue an unreachable offboarded device.                                                                                                                                                     |
+=================================================+=================================================+=================================================+===============================================================================+
| Sent by \| to URI                               | Enum                                            | Length                                          | Value                                                                         |
+-------------------------------------------------+-------------------------------------------------+-------------------------------------------------+-------------------------------------------------------------------------------+
| Manager                                         | 0x7001                                          | 18                                              | \[0-5\] Target TUID: The unique hardware identifier of the offboarded device. |
|                                                 |                                                 |                                                 |                                                                               |
| /sig-net/\<version\>/local/snrp                 |                                                 |                                                 | \[6-9\] New IPv4 Address.                                                     |
|                                                 |                                                 |                                                 |                                                                               |
|                                                 |                                                 |                                                 | \[10-13\] New IPv4 Subnet Mask.                                               |
|                                                 |                                                 |                                                 |                                                                               |
|                                                 |                                                 |                                                 | \[14-17\] New IPv4 Default Gateway.                                           |
+-------------------------------------------------+-------------------------------------------------+-------------------------------------------------+-------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                               | Queryable: No                                                                 |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------+
| Notes: Sent via UDP Multicast to \<mult_node_beacon\>. Unauthenticated, offboarded devices shall apply these settings immediately. Onboarded devices shall silently discard this payload.                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                                                                            | Node Mandated: Yes, if SNOW supported                                         |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------+
| Sender Mandated: Yes, if SNOW supported                                                                                                             | Visualiser Mandated: Yes, if SNOW supported                                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------+

## TOTW_RT_PUBLIC_KEY

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits the device\'s asymmetric Public Key to the Manager to facilitate the encrypted TLS tunnel and key rotation.                                                                                                                                                    |
+=====================================================================+=====================================================================+=====================================================================+=====================================================================+
| Sent by \| to URI                                                   | Enum                                                                | Length                                                              | Value                                                               |
+---------------------------------------------------------------------+---------------------------------------------------------------------+---------------------------------------------------------------------+---------------------------------------------------------------------+
| Node                                                                | 0x7002                                                              | Variable                                                            | The raw or DER-encoded Public Key of the device.                    |
|                                                                     |                                                                     |                                                                     |                                                                     |
| /sig-net/\<version\>/local/node/{tuid}/0                            |                                                                     |                                                                     |                                                                     |
+---------------------------------------------------------------------+---------------------------------------------------------------------+---------------------------------------------------------------------+---------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                                                           | Queryable: No                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| Notes: Sent by the device down the secure TLS tunnel immediately following the handshake. This provides the Manager\'s application layer with the raw key for directory storage, avoiding the need to extract it programmatically from the underlying TLS certificate stack.          |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                                                                                                                                        | Node Mandated: Yes, if SNOW supported                               |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| Sender Mandated: Yes, if SNOW supported                                                                                                                                                                         | Visualiser Mandated: Yes, if SNOW supported                         |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+

## TOTW_RT_IDENTIFY

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands the device to visually identify itself during TOFU.                                                                                                                                                                                                                                                                      |
+=============================================+=====================+=====================+======================================================================================================================================================================================================================================================+
| Sent by \| to URI                           | Enum                | Length              | Value                                                                                                                                                                                                                                                |
+---------------------------------------------+---------------------+---------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                     | 0x7003              | 32                  | \[0-31\] TLS Session Fingerprint: 32 bytes of keying material derived via RFC 5705 using the label \"EXPORTER-Sig-Net-SNOW-Identify\" to cryptographically bind the visual identification to the specific tunnel, preventing session replay attacks. |
|                                             |                     |                     |                                                                                                                                                                                                                                                      |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                     |                     |                                                                                                                                                                                                                                                      |
+---------------------------------------------+---------------------+---------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                   | Queryable: No                                                                                                                                                                                                                                        |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                                                                                                         |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                | Node Mandated: Yes, if SNOW supported                                                                                                                                                                                                                |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes, if SNOW supported                                                 | Visualiser Mandated: Yes, if SNOW supported                                                                                                                                                                                                          |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

## TOTW_RT_KEY_KS 

+-------------------------------------------------------------------------------------------------------------------------------------+
| Description: The 32-byte derived Sender Key (Ks).                                                                                   |
+=============================================+====================+====================+=============================================+
| Sent by \| to URI                           | Enum               | Length             | Value                                       |
+---------------------------------------------+--------------------+--------------------+---------------------------------------------+
| Manager                                     | 0x7004             | 32                 | \[0-31\] Ks                                 |
|                                             |                    |                    |                                             |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                    |                    |                                             |
+---------------------------------------------+--------------------+--------------------+---------------------------------------------+
| Target Endpoint: Root                                                                 | Queryable: No                               |
+---------------------------------------------------------------------------------------+---------------------------------------------+
| Notes:                                                                                                                              |
+---------------------------------------------------------------------------------------+---------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                              | Node Mandated: Yes, if SNOW supported       |
+---------------------------------------------------------------------------------------+---------------------------------------------+
| Sender Mandated: Yes, if SNOW supported                                               | Visualiser Mandated: Yes, if SNOW supported |
+---------------------------------------------------------------------------------------+---------------------------------------------+

## TOTW_RT_KEY_KC 

+-------------------------------------------------------------------------------------------------------------------------------------+
| Description: The 32-byte derived Citizen Key (Kc).                                                                                  |
+=============================================+====================+====================+=============================================+
| Sent by \| to URI                           | Enum               | Length             | Value                                       |
+---------------------------------------------+--------------------+--------------------+---------------------------------------------+
| Manager                                     | 0x7005             | 32                 | \[0-31\] Kc                                 |
|                                             |                    |                    |                                             |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                    |                    |                                             |
+---------------------------------------------+--------------------+--------------------+---------------------------------------------+
| Target Endpoint: Root                                                                 | Queryable: No                               |
+---------------------------------------------------------------------------------------+---------------------------------------------+
| Notes:                                                                                                                              |
+---------------------------------------------------------------------------------------+---------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                              | Node Mandated: Yes, if SNOW supported       |
+---------------------------------------------------------------------------------------+---------------------------------------------+
| Sender Mandated: Yes, if SNOW supported                                               | Visualiser Mandated: Yes, if SNOW supported |
+---------------------------------------------------------------------------------------+---------------------------------------------+

## TOTW_RT_KEY_KM_GLOBAL 

+-------------------------------------------------------------------------------------------------------------------------------+
| Description: The 32-byte derived Global Manager Key (Km_global).                                                              |
+=============================================+====================+====================+=======================================+
| Sent by \| to URI                           | Enum               | Length             | Value                                 |
+---------------------------------------------+--------------------+--------------------+---------------------------------------+
| Manager                                     | 0x7006             | 32                 | \[0-31\] Km_global                    |
|                                             |                    |                    |                                       |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                    |                    |                                       |
+---------------------------------------------+--------------------+--------------------+---------------------------------------+
| Target Endpoint: Root                                                                 | Queryable: No                         |
+---------------------------------------------------------------------------------------+---------------------------------------+
| Notes:                                                                                                                        |
+---------------------------------------------------------------------------------------+---------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                              | Node Mandated: Yes, if SNOW supported |
+---------------------------------------------------------------------------------------+---------------------------------------+
| Sender Mandated: No                                                                   | Visualiser Mandated: No               |
+---------------------------------------------------------------------------------------+---------------------------------------+

## TOTW_RT_KEY_KM_LOCAL 

+---------------------------------------------------------------------------------------------------------------------------------+
| Description: The 32-byte derived Node-Specific Manager Key (Km_local).                                                          |
+=============================================+=====================+=====================+=======================================+
| Sent by \| to URI                           | Enum                | Length              | Value                                 |
+---------------------------------------------+---------------------+---------------------+---------------------------------------+
| Manager                                     | 0x7007              | 32                  | \[0-31\] Km_local                     |
|                                             |                     |                     |                                       |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                     |                     |                                       |
+---------------------------------------------+---------------------+---------------------+---------------------------------------+
| Target Endpoint: Root                                                                   | Queryable: No                         |
+-----------------------------------------------------------------------------------------+---------------------------------------+
| Notes:                                                                                                                          |
+-----------------------------------------------------------------------------------------+---------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                | Node Mandated: Yes, if SNOW supported |
+-----------------------------------------------------------------------------------------+---------------------------------------+
| Sender Mandated: No                                                                     | Visualiser Mandated: No               |
+-----------------------------------------------------------------------------------------+---------------------------------------+

## TOTW_RT_KEY_K0 

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: The 32-byte Root Key.                                                                                                                                                                                                                    |
+=============================================================+=============================================================+=============================================================+=============================================================+
| Sent by \| to URI                                           | Enum                                                        | Length                                                      | Value                                                       |
+-------------------------------------------------------------+-------------------------------------------------------------+-------------------------------------------------------------+-------------------------------------------------------------+
| Manager                                                     | 0x7008                                                      | 32                                                          | \[0-31\] K0                                                 |
|                                                             |                                                             |                                                             |                                                             |
| /sig-net/\<version\>/local/manager/{tuid}/0                 |                                                             |                                                             |                                                             |
+-------------------------------------------------------------+-------------------------------------------------------------+-------------------------------------------------------------+-------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                                   | Queryable: No                                               |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------+
| Notes: This payload shall only be transmitted during an Equal Manager onboarding sequence, authenticated via Method B (Cryptographic PIN Verification). It shall never be transmitted to a Node, Sender, Visualiser, or Guest Manager.                |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                                                                                                                | Node Mandated: No                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------+
| Sender Mandated: No                                                                                                                                                                     | Visualiser Mandated: No                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------+

## TOTW_RT_POM_PUBLIC_KEY 

+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits the Manager\'s Master Public Key to the device.                                                                                         |
+=============================================+=====================+=================================================================+==========================+
| Sent by \| to URI                           | Enum                | Length                                                          | Value                    |
+---------------------------------------------+---------------------+-----------------------------------------------------------------+--------------------------+
| Manager                                     | 0x7009              | 65 bytes (Raw uncompressed with 0x04 prefix) or Variable (DER). | DER-encoded Public Key   |
|                                             |                     |                                                                 |                          |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                     |                                                                 |                          |
+---------------------------------------------+---------------------+-----------------------------------------------------------------+--------------------------+
| Target Endpoint: Root                                                                                                               | Queryable: No            |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------+
| Notes: Sent only during initial TLS onboarding.                                                                                                                |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------+
| Manager Mandated: Yes, if SNOW supported                                                                                            | Node Mandated: No        |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------+
| Sender Mandated: No                                                                                                                 | Visualiser Mandated: No  |
+-------------------------------------------------------------------------------------------------------------------------------------+--------------------------+

## TOTW_RT_POM_WIPE 

+----------------------------------------------------------------------------------------------------------------------------+
| Description: Command to force a device reset.                                                                              |
+================================+====================+====================+=================================================+
| Sent by \| to URI              | Enum               | Length             | Value                                           |
+--------------------------------+--------------------+--------------------+-------------------------------------------------+
| Manager                        | 0x700A             | 78 bytes.          | \[TUID(6)\] + \[Nonce(8)\] + \[Signature(64)\]. |
|                                |                    |                    |                                                 |
| sig-net/\<version\>/local/snrp |                    |                    |                                                 |
+--------------------------------+--------------------+--------------------+-------------------------------------------------+
| Target Endpoint: Root                                                    | Queryable: No                                   |
+--------------------------------------------------------------------------+-------------------------------------------------+
| Notes: Sent via SNRP (Multicast UDP) to the beacon address.                                                                |
+--------------------------------------------------------------------------+-------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                 | Node Mandated: No                               |
+--------------------------------------------------------------------------+-------------------------------------------------+
| Sender Mandated: No                                                      | Visualiser Mandated: No                         |
+--------------------------------------------------------------------------+-------------------------------------------------+

## TOTW_RT_OTW_REOPEN 

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands an onboarded device to temporarily open its TLS port for a re-keying session.                                                                                                                           |
+=================================+=============================+=============================+=================================================================================================================================+
| Sent by \| to URI               | Enum                        | Length                      | Value                                                                                                                           |
+---------------------------------+-----------------------------+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Manager                         | 0x700B                      | 48 or 80 bytes.             | \[0-5\] Target TUID: The hardware identifier of the device.                                                                     |
|                                 |                             |                             |                                                                                                                                 |
| /sig-net/\<version\>/local/snrp |                             |                             | \[6\] Signature Type:                                                                                                           |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | - 0x00: HMAC-SHA256 (signed using the active Km_local).                                                                         |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | - 0x01: Asymmetric ECDSA (signed using the POM Private Key).                                                                    |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | \[7\] Timeout: Ephemeral port window in seconds (1--255). A value of 0x00 defaults the timeout window to 60 seconds.            |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | \[8-15\] Nonce: An 8-byte random initialization value intended to ensure signature entropy and prevent pre-computation attacks. |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | \[16-n\] Signature Block:                                                                                                       |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | - If Type is 0x00: 32-byte HMAC (Total TLV Length = 48).                                                                        |
|                                 |                             |                             |                                                                                                                                 |
|                                 |                             |                             | - If Type is 0x01: 64-byte Raw R/S Signature (Total TLV Length = 80).                                                           |
+---------------------------------+-----------------------------+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                       | Queryable: No                                                                                                                   |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                        |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                    | Node Mandated: No                                                                                                               |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No                                                                         | Visualiser Mandated: No                                                                                                         |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+

## TOTW_RT_UPDATE_POM 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Rotates or updates the stored Proof of Management (POM) Public Key on the device.                                                                                           |
+=============================================+===========================================+===========================================+====================================================+
| Sent by \| to URI                           | Enum                                      | Length                                    | Value                                              |
+---------------------------------------------+-------------------------------------------+-------------------------------------------+----------------------------------------------------+
| Manager                                     | 0x700C                                    | 64 or variable bytes.                     | DER-encoded or 64-byte raw (secp256r1) Public Key. |
|                                             |                                           |                                           |                                                    |
| /sig-net/\<version\>/local/manager/{tuid}/0 |                                           |                                           |                                                    |
+---------------------------------------------+-------------------------------------------+-------------------------------------------+----------------------------------------------------+
| Target Endpoint: Root                                                                                                               | Queryable: No                                      |
+-------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Notes: To prevent unauthorised administrative takeovers, this payload is restricted to the OTW TLS session and shall be ignored if received over unencrypted UDP.                        |
+-------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                                                            | Node Mandated: No                                  |
+-------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Sender Mandated: No                                                                                                                 | Visualiser Mandated: No                            |
+-------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+

## TOTW_RT_SCOPE 

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits the active destination Scope Name string to the target device.                                                                                                                                                                                                                                                 |
+======================================================================+======================================================================+======================================================================+==================================================================================================================+
| Sent by \| to URI                                                    | Enum                                                                 | Length                                                               | Value                                                                                                            |
+----------------------------------------------------------------------+----------------------------------------------------------------------+----------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+
| Manager                                                              | 0x700D                                                               | 1-32 bytes.                                                          | UTF-8 encoded string containing the destination Scope Name (e.g., \"theatre\" or \"tour\"). Not null-terminated. |
|                                                                      |                                                                      |                                                                      |                                                                                                                  |
| /sig-net/\<version\>/local/manager/{tuid}/0                          |                                                                      |                                                                      |                                                                                                                  |
+----------------------------------------------------------------------+----------------------------------------------------------------------+----------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                                                              | Queryable: No                                                                                                    |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+
| Notes: Sent by the Manager inside the secure TLS tunnel. This payload defines the Scope Name to which the accompanying symmetric keys (TOTW_RT_KEY\_\*) are bound. The target device shall associate the received keys with this Scope Name string in its persistent storage.                                                         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes, if SNOW supported                                                                                                                                                                           | Node Mandated: Yes, if SNOW supported                                                                            |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes, if SNOW supported                                                                                                                                                                            | Visualiser Mandated: Yes, if SNOW supported                                                                      |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------+

# Example Operational Workflows (Informative)

This section describes how the various components of SNOW are utilised during common production scenarios.

## The Touring Manifest Workflow

This scenario demonstrates rapid onboarding for a high-density festival rig.

- At the rental shop, a technician generates a Manifest File (Section 6.5) containing the Public Keys of all 200 fixtures.

- The rig is hung and powered on. The fixtures begin transmitting Beacons (Section 6.1) on the \<mult_node_beacon\> address.

- The console operator imports the JSON Manifest into the Manager.

- The Manager detects the beacons. Because the Public Keys match the Manifest, the Manager establishes TLS tunnels and pushes the Show Keys and POM Public Key to all fixtures automatically. No PIN codes or visual identification are required.

## The \"Hostage Fixture\" Rescue

This scenario describes how to recover control of a rig when the original console is lost or has crashed.

- A touring rig is already onboarded to \"Console A,\" but Console A has been destroyed. The technician has \"Console B,\" but it does not possess the Km_local keys required to manage the rig.

- The technician loads the venue\'s POM Private Key (Section 4.3) into Console B.

- Console B multicasts a TOTW_RT_POM_WIPE (Section 9.10) to the network.

- Every fixture on the truss verifies the signature using its stored POM Public Key. Finding it valid, the fixtures execute a factory reset and return to Beacon Mode.

Recovery: Console B now discovers the offboarded fixtures and onboards them to a new session.

## Routine Key Rotation

This scenario describes how a Manager updates security without interrupting a long-term installation.

- The Manager decides to rotate the Ks (Sender) key. It multicasts a TOTW_RT_OTW_REOPEN (Section 9.11) signed with the current Km_local.

- The fixtures verify the HMAC and temporarily open their TLS Ports.

- The Manager establishes new TLS tunnels and pushes the updated Ks key to each fixture one by one.

- Once the new keys are acknowledged, the TLS tunnels are torn down. The entire rig is now secured with fresh keys without the operator ever leaving their seat.

# Appendix G Document Revisions (Informative)

V0.1-0.3 (16/4/2026)

- Discussion document at Lille PlugFest

V0.4 (23/4/2026)

- Initial concept draft, limited release for discussion.

V0.5 (9/5/2026)

- Updated for the Equal/Guest concept in Sig-Net v1.0

- All Discord threads to this date resolved and incorporated.

V0.6 (20/5/2026)

- Added POM

- Added Manifest

- Added 3 x TIDs

- Restructured document.

- Added section 10 -- informative.

V0.7 (1/6/2026)

- Section 9.11 (TOTW_RT_OTW_REOPEN): Added 1-byte timeout and 1-byte Signature Type flag (HMAC vs. Asymmetric).

- Section 9.12 (TOTW_RT_UPDATE_POM): Added new in-tunnel payload for secure POM key rotation.

- Section 5.3 (Rotation Trigger): Mandated proactive multicast of TID_RT_OTW_CAPABILITY.

- Section 5.5 (User Initiated Force Beaconing): Added this section to deal with manager -- manager discovery for multi-scoped onboarding

V0.8 (22/6/2026)

- New Section 6.1 inserted to clarify the significance of scope local.

- New Section 9.13 added to define TOTW_RT_SCOPE. This new TID resolves the problem that we cannot use the URI scope to define the target scope that we are onboarding.

- Section 7.1 updated for overlap.

- Section 9.3 corrected.

V0.9 (22/6/2026)

- Section 5.2 Defined NONCE operation.

- Section 7.1.1 Mandate old key discard on new key verify.

- Section 8.2. Typo corrected.

- Section 9.9 Payload error corrected.

- Section 8.3 updated to clarify allowed TIDs.

- Section 6.5 POM persistence defined.

V1.0 (11/7/2026)

- Section 6.3. Updated to add QR.

Copyright © Singularity (UK) Ltd 2026. All rights reserved.\
Sig-Net®, Multicast Folding™, SNACtest™, SNOW™ and SNOWman™ are trademarks of Singularity (UK) Ltd.
