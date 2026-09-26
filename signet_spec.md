V1.11

![](media/image1.png){width="3.9850371828521434in" height="1.0176727909011374in"}

Copyright Singularity (UK) Ltd 2026

# Table of Contents {#table-of-contents .TOC-Heading}

[Table of Figures [10](#table-of-figures)](#table-of-figures)

[Preface [11](#preface)](#preface)

[Acknowledgements [12](#acknowledgements)](#acknowledgements)

[1 Introduction [13](#introduction)](#introduction)

[1.1 Overview [13](#overview)](#overview)

[1.2 Conditions of Use [13](#conditions-of-use)](#conditions-of-use)

[1.3 Compliance Notice & Disclaimer [13](#compliance-notice-disclaimer)](#compliance-notice-disclaimer)

[1.4 Vulnerability Disclosure [14](#vulnerability-disclosure)](#vulnerability-disclosure)

[2 References to other Documents [14](#references-to-other-documents)](#references-to-other-documents)

[2.1 Normative References [14](#normative-references)](#normative-references)

[2.2 Informative References [15](#informative-references)](#informative-references)

[3 Definitions [15](#definitions)](#definitions)

[3.1 Document Conventions [16](#document-conventions)](#document-conventions)

[3.2 Byte Order [16](#byte-order)](#byte-order)

[3.3 Octet and Byte [16](#octet-and-byte)](#octet-and-byte)

[3.4 Bit Numbering [16](#bit-numbering)](#bit-numbering)

[4 Security Concepts [16](#security-concepts)](#security-concepts)

[4.1 Introduction [16](#introduction-1)](#introduction-1)

[4.2 Secure Design Rationale [16](#secure-design-rationale)](#secure-design-rationale)

[4.3 Provenance and Attestation [17](#provenance-and-attestation)](#provenance-and-attestation)

[4.4 Encryption [17](#encryption)](#encryption)

[4.5 Authentication [18](#authentication)](#authentication)

[4.6 Integrity [18](#integrity)](#integrity)

[4.7 Authorisation [18](#authorisation)](#authorisation)

[4.8 Freshness [18](#freshness)](#freshness)

[4.9 Security Lifecycle & Extensibility (Informative) [18](#security-lifecycle-extensibility-informative)](#security-lifecycle-extensibility-informative)

[4.9.1 Firmware Updates [18](#firmware-updates)](#firmware-updates)

[4.9.2 Key Rotation [19](#key-rotation)](#key-rotation)

[4.9.3 Future Encryption: [19](#future-encryption)](#future-encryption)

[5 Threat Vectors [19](#threat-vectors)](#threat-vectors)

[5.1 Introduction [19](#introduction-2)](#introduction-2)

[5.2 Man-in-the-Middle [19](#man-in-the-middle)](#man-in-the-middle)

[5.3 Masquerading and Spoofing [19](#masquerading-and-spoofing)](#masquerading-and-spoofing)

[5.4 Replay Attack [19](#replay-attack)](#replay-attack)

[5.5 Rogue Device [19](#rogue-device)](#rogue-device)

[5.6 Eavesdropping & Sniffing [19](#eavesdropping-sniffing)](#eavesdropping-sniffing)

[5.7 Compromised Node or Sender [20](#compromised-node-or-sender)](#compromised-node-or-sender)

[5.8 Compromised Manager [20](#compromised-manager)](#compromised-manager)

[5.9 Offboarded Beacon Spoofing [20](#offboarded-beacon-spoofing)](#offboarded-beacon-spoofing)

[6 System Architecture [20](#system-architecture)](#system-architecture)

[6.1 Structure [20](#structure)](#structure)

[6.2 Functional Roles [20](#functional-roles)](#functional-roles)

[6.3 Trust [21](#trust)](#trust)

[6.4 Air-Gap [21](#air-gap)](#air-gap)

[6.5 SoemCode [22](#soemcode)](#soemcode)

[6.6 Transport Unique Identifier (TUID) [22](#transport-unique-identifier-tuid)](#transport-unique-identifier-tuid)

[6.7 TUID and E1.20 UID Relationship [23](#tuid-and-e1.20-uid-relationship)](#tuid-and-e1.20-uid-relationship)

[6.8 Endpoints [23](#endpoints)](#endpoints)

[6.8.1 Root Endpoint [23](#root-endpoint)](#root-endpoint)

[6.8.2 Data Endpoints [23](#data-endpoints)](#data-endpoints)

[6.8.3 Reserved Endpoints [23](#reserved-endpoints)](#reserved-endpoints)

[6.8.4 Broadcast Endpoint [24](#broadcast-endpoint)](#broadcast-endpoint)

[6.8.5 Endpoint Examples [24](#endpoint-examples)](#endpoint-examples)

[7 Root Key and Key Derivation [24](#root-key-and-key-derivation)](#root-key-and-key-derivation)

[7.1 Introduction [24](#introduction-3)](#introduction-3)

[7.2 Root Key (K0) Specification [24](#root-key-k0-specification)](#root-key-k0-specification)

[7.2.1 Entropy Validation [25](#entropy-validation)](#entropy-validation)

[7.2.2 Offboarded Operation (Beacon Mode) [25](#offboarded-operation-beacon-mode)](#offboarded-operation-beacon-mode)

[7.2.3 Input and Transfer Formats [25](#input-and-transfer-formats)](#input-and-transfer-formats)

[7.2.4 Open Mode (Unauthenticated Operation) [27](#open-mode-unauthenticated-operation)](#open-mode-unauthenticated-operation)

[7.3 Key Derivation Function (KDF) [27](#key-derivation-function-kdf)](#key-derivation-function-kdf)

[7.3.1 **Key Usage Summary** [28](#key-usage-summary)](#key-usage-summary)

[7.3.2 Key Lifecycle and Erasure [30](#key-lifecycle-and-erasure)](#key-lifecycle-and-erasure)

[7.4 Human Readable Format (Display and Verification) [31](#human-readable-format-display-and-verification)](#human-readable-format-display-and-verification)

[7.5 Machine Readable Format (Out-of-Band Transfer) [31](#machine-readable-format-out-of-band-transfer)](#machine-readable-format-out-of-band-transfer)

[7.5.1 Restricted Key Export (Guest Access) [31](#restricted-key-export-guest-access)](#restricted-key-export-guest-access)

[7.6 Storage and Security [32](#storage-and-security)](#storage-and-security)

[7.7 Offboarding and Erasure [33](#offboarding-and-erasure)](#offboarding-and-erasure)

[7.7.1 Authenticated Network Offboarding [33](#authenticated-network-offboarding)](#authenticated-network-offboarding)

[7.7.2 Physical Out-of-Band Offboarding [33](#physical-out-of-band-offboarding)](#physical-out-of-band-offboarding)

[8 Packet Structure [33](#packet-structure)](#packet-structure)

[8.1 CoAP Summary (Informative) [33](#coap-summary-informative)](#coap-summary-informative)

[8.2 URI Syntax Overview [34](#uri-syntax-overview)](#uri-syntax-overview)

[8.3 Security Options [34](#security-options)](#security-options)

[8.4 Packet Structure [36](#packet-structure-1)](#packet-structure-1)

[8.5 HMAC Calculations [37](#hmac-calculations)](#hmac-calculations)

[8.6 Packet Processing and Replay Attack Prevention [38](#packet-processing-and-replay-attack-prevention)](#packet-processing-and-replay-attack-prevention)

[8.6.1 Manager Processing of Replies [40](#manager-processing-of-replies)](#manager-processing-of-replies)

[8.6.2 Freshness Architecture (The Lane Model) [40](#freshness-architecture-the-lane-model)](#freshness-architecture-the-lane-model)

[8.6.3 First-Packet Bootstrapping [41](#first-packet-bootstrapping)](#first-packet-bootstrapping)

[8.6.4 Post-Reboot Replay Protection [42](#post-reboot-replay-protection)](#post-reboot-replay-protection)

[9 Transport [42](#transport)](#transport)

[9.1 Multicast Use [42](#multicast-use)](#multicast-use)

[9.2 Multicast Address Mapping [42](#multicast-address-mapping)](#multicast-address-mapping)

[9.2.1 URI to Multicast Determinism [42](#uri-to-multicast-determinism)](#uri-to-multicast-determinism)

[9.2.2 Discovery and Management Subscriptions [43](#discovery-and-management-subscriptions)](#discovery-and-management-subscriptions)

[9.2.3 Default Multicast Folding™ (Universe Mapping) [43](#default-multicast-folding-universe-mapping)](#default-multicast-folding-universe-mapping)

[9.2.4 Multicast Folding™ Configuration and Overrides [44](#multicast-folding-configuration-and-overrides)](#multicast-folding-configuration-and-overrides)

[9.2.5 Multicast Interoperability and Safety Reset [45](#multicast-interoperability-and-safety-reset)](#multicast-interoperability-and-safety-reset)

[9.2.6 Sync and Timecode Address [45](#sync-and-timecode-address)](#sync-and-timecode-address)

[9.3 Port Assignment [45](#port-assignment)](#port-assignment)

[9.4 CoAP Message Type and Method [45](#coap-message-type-and-method)](#coap-message-type-and-method)

[9.5 Network Infrastructure Requirements [45](#network-infrastructure-requirements)](#network-infrastructure-requirements)

[9.6 Multicast TTL [46](#multicast-ttl)](#multicast-ttl)

[10 Payload Syntax [46](#payload-syntax)](#payload-syntax)

[10.1 Introduction [46](#introduction-4)](#introduction-4)

[10.1.1 TID Allocation and Namespaces [46](#tid-allocation-and-namespaces)](#tid-allocation-and-namespaces)

[10.1.2 Proprietary TID Resolution [46](#proprietary-tid-resolution)](#proprietary-tid-resolution)

[10.1.3 TLV Validation [47](#tlv-validation)](#tlv-validation)

[10.2 Device Discovery and Polling [47](#device-discovery-and-polling)](#device-discovery-and-polling)

[10.2.1 Offboarded Operation (Beacon Mode) [47](#offboarded-operation-beacon-mode-1)](#offboarded-operation-beacon-mode-1)

[10.2.2 Manager Operation [48](#manager-operation)](#manager-operation)

[10.2.3 Device Response Logic [49](#device-response-logic)](#device-response-logic)

[10.2.4 Fragmentation [50](#fragmentation)](#fragmentation)

[10.2.5 On-Boot Notification [50](#on-boot-notification)](#on-boot-notification)

[10.2.6 Device Loss Detection (Lost Mode) [51](#device-loss-detection-lost-mode)](#device-loss-detection-lost-mode)

[10.3 Targeted Device Routing [51](#targeted-device-routing)](#targeted-device-routing)

[10.3.1 Targeted URIs [52](#targeted-uris)](#targeted-uris)

[10.3.2 Unicast vs. Multicast Command Routing: [52](#unicast-vs.-multicast-command-routing)](#unicast-vs.-multicast-command-routing)

[10.3.3 Auxiliary URI [52](#auxiliary-uri)](#auxiliary-uri)

[10.4 Node Configuration and State Synchronisation [53](#node-configuration-and-state-synchronisation)](#node-configuration-and-state-synchronisation)

[10.4.1 Directional URI Mapping [53](#directional-uri-mapping)](#directional-uri-mapping)

[10.4.2 Parameter Updates (SET) [53](#parameter-updates-set)](#parameter-updates-set)

[10.4.3 Parameter Queries (GET) [55](#parameter-queries-get)](#parameter-queries-get)

[10.4.4 Consistency Tracking [56](#consistency-tracking)](#consistency-tracking)

[10.4.5 Implementing Eventual Consistency (Informative) [57](#implementing-eventual-consistency-informative)](#implementing-eventual-consistency-informative)

[10.4.6 Batch State Retrieval (QUERY_LEVEL) [58](#batch-state-retrieval-query_level)](#batch-state-retrieval-query_level)

[10.4.7 Network Interface Configuration (IP Settings) [58](#network-interface-configuration-ip-settings)](#network-interface-configuration-ip-settings)

[10.5 RDM Payload [60](#rdm-payload)](#rdm-payload)

[10.5.1 Transaction Responses [61](#transaction-responses)](#transaction-responses)

[10.5.2 Proactive State Notification [61](#proactive-state-notification)](#proactive-state-notification)

[10.5.3 RDM Boundary Restrictions (Normative) [61](#rdm-boundary-restrictions-normative)](#rdm-boundary-restrictions-normative)

[10.5.4 Node Responsibilities [62](#node-responsibilities)](#node-responsibilities)

[10.5.5 RDM Discovery Commands [63](#rdm-discovery-commands)](#rdm-discovery-commands)

[10.6 Universe Payload [63](#universe-payload)](#universe-payload)

[10.6.1 Example Universe Payload (Informative) [64](#example-universe-payload-informative)](#example-universe-payload-informative)

[10.6.2 Routing & Mixed Security Environments [66](#routing-mixed-security-environments)](#routing-mixed-security-environments)

[10.6.3 Transmission Rates and Keep-Alive [66](#transmission-rates-and-keep-alive)](#transmission-rates-and-keep-alive)

[10.6.4 Stream Loss Timeout: [67](#stream-loss-timeout)](#stream-loss-timeout)

[10.7 Sync Payload [67](#sync-payload)](#sync-payload)

[10.7.1 Transmission Rules [67](#transmission-rules)](#transmission-rules)

[10.7.2 Processing Rules and the SYNC_ACTIVE State [67](#processing-rules-and-the-sync_active-state)](#processing-rules-and-the-sync_active-state)

[10.7.3 Synchronisation Timeout [68](#synchronisation-timeout)](#synchronisation-timeout)

[10.8 Timecode Payload [68](#timecode-payload)](#timecode-payload)

[10.8.1 Transmission Rules [68](#transmission-rules-1)](#transmission-rules-1)

[10.8.2 Timecode Stream Loss [69](#timecode-stream-loss)](#timecode-stream-loss)

[10.9 Security Event Reporting [69](#security-event-reporting)](#security-event-reporting)

[10.9.1 Event Counters [69](#event-counters)](#event-counters)

[10.9.2 Offending Address Capture [69](#offending-address-capture)](#offending-address-capture)

[10.9.3 Transmission and Rate Limiting [69](#transmission-and-rate-limiting)](#transmission-and-rate-limiting)

[11 TID Definitions [70](#tid-definitions)](#tid-definitions)

[11.1 Node-Discovery Type Identifiers [71](#node-discovery-type-identifiers)](#node-discovery-type-identifiers)

[11.1.1 TID_POLL [71](#tid_poll)](#tid_poll)

[11.1.2 TID_POLL_REPLY [71](#tid_poll_reply)](#tid_poll_reply)

[11.1.3 TID_SET_REPLY [71](#tid_set_reply)](#tid_set_reply)

[11.2 Sender Type Identifiers [72](#sender-type-identifiers)](#sender-type-identifiers)

[11.2.1 TID_LEVEL [72](#tid_level)](#tid_level)

[11.2.2 TID_PRIORITY [72](#tid_priority)](#tid_priority)

[11.2.3 TID_PREVIEW [72](#tid_preview)](#tid_preview)

[11.2.4 TID_SYNC [72](#tid_sync)](#tid_sync)

[11.2.5 TID_TIMECODE [73](#tid_timecode)](#tid_timecode)

[11.2.6 TID_UNIVERSE [74](#tid_universe)](#tid_universe)

[11.2.7 TID_OSC [74](#tid_osc)](#tid_osc)

[11.3 RDM Type Identifiers [75](#rdm-type-identifiers)](#rdm-type-identifiers)

[11.3.1 TID_RDM_COMMAND [75](#tid_rdm_command)](#tid_rdm_command)

[11.3.2 TID_RDM_RESPONSE [75](#tid_rdm_response)](#tid_rdm_response)

[11.3.3 TID_RDM_TOD_CONTROL [75](#tid_rdm_tod_control)](#tid_rdm_tod_control)

[11.3.4 TID_RDM_TOD_DATA [76](#tid_rdm_tod_data)](#tid_rdm_tod_data)

[11.3.5 TID_RDM_EP_CONFIG [76](#tid_rdm_ep_config)](#tid_rdm_ep_config)

[11.3.6 TID_RDM_FLOW_CONTROL [77](#tid_rdm_flow_control)](#tid_rdm_flow_control)

[11.4 Offboarding Type Identifiers [77](#offboarding-type-identifiers)](#offboarding-type-identifiers)

[11.4.1 TID_RT_OFFBOARD [77](#tid_rt_offboard)](#tid_rt_offboard)

[11.5 Network Configuration Type Identifiers [78](#network-configuration-type-identifiers)](#network-configuration-type-identifiers)

[11.5.1 TID_NW_MAC_ADDRESS [78](#tid_nw_mac_address)](#tid_nw_mac_address)

[11.5.2 TID_NW_IPV4_MODE [78](#tid_nw_ipv4_mode)](#tid_nw_ipv4_mode)

[11.5.3 TID_NW_IPV4_ADDRESS [78](#tid_nw_ipv4_address)](#tid_nw_ipv4_address)

[11.5.4 TID_NW_IPV4_NETMASK [79](#tid_nw_ipv4_netmask)](#tid_nw_ipv4_netmask)

[11.5.5 TID_NW_IPV4_GATEWAY [79](#tid_nw_ipv4_gateway)](#tid_nw_ipv4_gateway)

[11.5.6 TID_NW_IPV4_CURRENT [79](#tid_nw_ipv4_current)](#tid_nw_ipv4_current)

[11.5.7 TID_NW_IPV6_MODE [80](#tid_nw_ipv6_mode)](#tid_nw_ipv6_mode)

[11.5.8 TID_NW_IPV6_ADDRESS [80](#tid_nw_ipv6_address)](#tid_nw_ipv6_address)

[11.5.9 TID_NW_IPV6_PREFIX [80](#tid_nw_ipv6_prefix)](#tid_nw_ipv6_prefix)

[11.5.10 TID_NW_IPV6_GATEWAY [81](#tid_nw_ipv6_gateway)](#tid_nw_ipv6_gateway)

[11.5.11 TID_NW_IPV6_CURRENT [81](#tid_nw_ipv6_current)](#tid_nw_ipv6_current)

[11.6 Root Endpoint Type Identifiers [81](#root-endpoint-type-identifiers)](#root-endpoint-type-identifiers)

[11.6.1 TID_RT_SUPPORTED_TIDS [81](#tid_rt_supported_tids)](#tid_rt_supported_tids)

[11.6.2 TID_RT_ENDPOINT_COUNT [82](#tid_rt_endpoint_count)](#tid_rt_endpoint_count)

[11.6.3 TID_RT_PROTOCOL_VERSION [82](#tid_rt_protocol_version)](#tid_rt_protocol_version)

[11.6.4 TID_RT_FIRMWARE_VERSION [82](#tid_rt_firmware_version)](#tid_rt_firmware_version)

[11.6.5 TID_RT_DEVICE_LABEL [83](#tid_rt_device_label)](#tid_rt_device_label)

[11.6.6 TID_RT_MULT_OVERRIDE [83](#tid_rt_mult_override)](#tid_rt_mult_override)

[11.6.7 TID_RT_IDENTIFY [84](#tid_rt_identify)](#tid_rt_identify)

[11.6.8 TID_RT_STATUS [84](#tid_rt_status)](#tid_rt_status)

[11.6.9 TID_RT_ROLE_CAPABILITY [85](#tid_rt_role_capability)](#tid_rt_role_capability)

[11.6.10 TID_RT_REBOOT [85](#tid_rt_reboot)](#tid_rt_reboot)

[11.6.11 TID_RT_MODEL_NAME [85](#tid_rt_model_name)](#tid_rt_model_name)

[11.6.12 TID_RT_OTW_CAPABILITY [86](#tid_rt_otw_capability)](#tid_rt_otw_capability)

[11.7 Data Endpoint Type Identifiers [86](#data-endpoint-type-identifiers)](#data-endpoint-type-identifiers)

[11.7.1 TID_EP_UNIVERSE [86](#tid_ep_universe)](#tid_ep_universe)

[11.7.2 TID_EP_LABEL [86](#tid_ep_label)](#tid_ep_label)

[11.7.3 TID_EP_MULT_OVERRIDE [87](#tid_ep_mult_override)](#tid_ep_mult_override)

[11.7.4 TID_EP_CAPABILITY [87](#tid_ep_capability)](#tid_ep_capability)

[11.7.5 TID_EP_DIRECTION [89](#tid_ep_direction)](#tid_ep_direction)

[11.7.6 TID_EP_INPUT_PRIORITY [89](#tid_ep_input_priority)](#tid_ep_input_priority)

[11.7.7 TID_EP_STATUS [90](#tid_ep_status)](#tid_ep_status)

[11.7.8 TID_EP_FAILOVER [90](#tid_ep_failover)](#tid_ep_failover)

[11.7.9 TID_EP_DMX_TIMING [91](#tid_ep_dmx_timing)](#tid_ep_dmx_timing)

[11.7.10 TID_EP_REFRESH_CAPABILITY [91](#tid_ep_refresh_capability)](#tid_ep_refresh_capability)

[11.7.11 TID_EP_PROTOCOL [92](#tid_ep_protocol)](#tid_ep_protocol)

[11.7.12 TID_EP_IDENTIFY [92](#tid_ep_identify)](#tid_ep_identify)

[11.8 Diagnostic Endpoint Type Identifiers [93](#diagnostic-endpoint-type-identifiers)](#diagnostic-endpoint-type-identifiers)

[11.8.1 TID_DG_SECURITY_EVENT [93](#tid_dg_security_event)](#tid_dg_security_event)

[11.8.2 TID_DG_MESSAGE [94](#tid_dg_message)](#tid_dg_message)

[11.8.3 TID_DG_LEVEL_FOLDBACK [94](#tid_dg_level_foldback)](#tid_dg_level_foldback)

[11.9 TID Polling Cross Reference [95](#tid-polling-cross-reference)](#tid-polling-cross-reference)

[11.10 TID Informative Summary [97](#tid-informative-summary)](#tid-informative-summary)

[12 Protocol Versioning and Compatibility [99](#protocol-versioning-and-compatibility)](#protocol-versioning-and-compatibility)

[12.1 Document and URI Relationship [99](#document-and-uri-relationship)](#document-and-uri-relationship)

[12.2 Node Versioning Requirements [99](#node-versioning-requirements)](#node-versioning-requirements)

[12.3 Manager Compatibility Requirements (Normative) [99](#manager-compatibility-requirements-normative)](#manager-compatibility-requirements-normative)

[12.4 Sender Compatibility Requirements [99](#sender-compatibility-requirements)](#sender-compatibility-requirements)

[13 Example Sig-Net Transaction (Informative) [100](#example-sig-net-transaction-informative)](#example-sig-net-transaction-informative)

[13.1 Sig-Net Device Discovery [100](#sig-net-device-discovery)](#sig-net-device-discovery)

[13.2 Example Node Endpoint Configuration [101](#example-node-endpoint-configuration)](#example-node-endpoint-configuration)

[13.3 Example Multi-Manager Environments [102](#example-multi-manager-environments)](#example-multi-manager-environments)

[13.3.1 Equal Managers [102](#equal-managers)](#equal-managers)

[13.3.2 Guest Manager [102](#guest-manager)](#guest-manager)

[14 Implementation Guidelines (Informative) [102](#implementation-guidelines-informative)](#implementation-guidelines-informative)

[14.1 Hardware Considerations [102](#hardware-considerations)](#hardware-considerations)

[14.1.1 Non-Volatile Memory Wear Endurance [102](#non-volatile-memory-wear-endurance)](#non-volatile-memory-wear-endurance)

[14.1.2 Key Storage Hardware [102](#key-storage-hardware)](#key-storage-hardware)

[14.1.3 Multicast Folding™ Load Scaling [103](#multicast-folding-load-scaling)](#multicast-folding-load-scaling)

[14.2 Network Considerations [103](#network-considerations)](#network-considerations)

[14.2.1 CoAP Port Coexistence [103](#coap-port-coexistence)](#coap-port-coexistence)

[14.2.2 Multicast Address Exclusivity [103](#multicast-address-exclusivity)](#multicast-address-exclusivity)

[14.3 Manufacturer Specific Extensions [103](#manufacturer-specific-extensions)](#manufacturer-specific-extensions)

[15 Appendix A Multicast Addresses [105](#appendix-a-multicast-addresses)](#appendix-a-multicast-addresses)

[16 Appendix B Definitions [106](#appendix-b-definitions)](#appendix-b-definitions)

[17 Appendix C Machine-Readable TID Dictionary (Informative) [108](#appendix-c-machine-readable-tid-dictionary-informative)](#appendix-c-machine-readable-tid-dictionary-informative)

[18 Appendix D Glossary [110](#appendix-d-glossary)](#appendix-d-glossary)

[19 Appendix E CRA and ENISA Compliance Reference (Informative) [113](#appendix-e-cra-and-enisa-compliance-reference-informative)](#appendix-e-cra-and-enisa-compliance-reference-informative)

[19.1 CRA Annex 1, Part 1 Mapping [113](#cra-annex-1-part-1-mapping)](#cra-annex-1-part-1-mapping)

[19.2 ENISA Security by Design and Default Playbook Mapping [114](#enisa-security-by-design-and-default-playbook-mapping)](#enisa-security-by-design-and-default-playbook-mapping)

[20 Appendix F Architectural Rationale (Informative) [115](#appendix-f-architectural-rationale-informative)](#appendix-f-architectural-rationale-informative)

[20.1 Why CoAP? [115](#why-coap)](#why-coap)

[20.2 Why Cleartext Routing [116](#why-cleartext-routing)](#why-cleartext-routing)

[20.3 Why Out-of-Band Keying? [116](#why-out-of-band-keying)](#why-out-of-band-keying)

[20.4 Why a Custom HMAC structure instead of OSCORE? [116](#why-a-custom-hmac-structure-instead-of-oscore)](#why-a-custom-hmac-structure-instead-of-oscore)

[20.5 Why a Custom TLV structure instead of CBOR? [116](#why-a-custom-tlv-structure-instead-of-cbor)](#why-a-custom-tlv-structure-instead-of-cbor)

[20.6 Why CoAP NON POST only? [116](#why-coap-non-post-only)](#why-coap-non-post-only)

[20.7 Why multicast RDM responses? [117](#why-multicast-rdm-responses)](#why-multicast-rdm-responses)

[20.8 Future Extensibility [117](#future-extensibility)](#future-extensibility)

[21 Appendix G Cryptographic Test Vectors (Normative) [118](#appendix-g-cryptographic-test-vectors-normative)](#appendix-g-cryptographic-test-vectors-normative)

[21.1 Input Parameters [118](#input-parameters)](#input-parameters)

[21.2 Key Derivation Reference Script (Python 3) [118](#key-derivation-reference-script-python-3)](#key-derivation-reference-script-python-3)

[21.3 Real Calculated Key Outputs [119](#real-calculated-key-outputs)](#real-calculated-key-outputs)

[21.4 HMAC Input Construction and Output Digest [119](#hmac-input-construction-and-output-digest)](#hmac-input-construction-and-output-digest)

[22 Appendix H Document Revisions (Informative) [120](#appendix-h-document-revisions-informative)](#appendix-h-document-revisions-informative)

# Table of Figures

[Figure 1 Summary of Key Derivation [29](#_Toc240901071)](#_Toc240901071)

[Figure 2 Summary of Derived Key Usage [30](#_Toc240901072)](#_Toc240901072)

[Figure 3 The Lane Model [41](#_Toc240901073)](#_Toc240901073)

[Figure 4 Multicast Folding and URI Filtering [44](#_Toc240901074)](#_Toc240901074)

[Figure 5 Summary of SET Processing [55](#_Toc240901075)](#_Toc240901075)

[Figure 6 Manager Eventual Consistency [57](#_Toc240901076)](#_Toc240901076)

[Figure 7 IP Change and Rollback Verification [60](#_Toc240901077)](#_Toc240901077)

[Figure 8 RDM Flow Control [63](#_Toc240901078)](#_Toc240901078)

[Figure 9 Wireshark Example [66](#_Toc240901079)](#_Toc240901079)

[Figure 10 Example TID Polling Cycle [100](#_Toc240901080)](#_Toc240901080)

[Figure 11 Example Endpoint Configuration [101](#_Toc240901081)](#_Toc240901081)

# Preface 

Cybersecurity legislation, notably the EU Cyber Resilience Act (CRA), will imminently impact upon the entertainment technology industry.

Sig-Net aims to provide a CRA-defensible communication framework. It has five primary goals:

- Offer a level of security defensible under the CRA.

- Support DMX, RDM, timecode and firmware upload.

- Re-use existing protocol structures and syntax wherever possible.

- Operate on a lightweight stack that can be implemented in a very short development cycle.

- Be scalable, supporting multiple Senders and very large universe counts.

What does \"CRA Defensible\" mean? This is a highly subjective question, best answered with an example. A simplistic reading of CRA Annex I, Part I, Point 2(e) suggests that encryption is mandated across the board. However, a more nuanced reading suggests that the risk assessment required by Article 13(2) defines the true applicability of the annex. Did the authors of the CRA genuinely intend for DMX lighting levels to be treated with the same cryptographic weight as a financial transaction? Recital (55) of Regulation (EU) 2024/2847 explicitly acknowledges the validity of this reading by stating that manufacturers may be required to \"follow widely recognised interoperability standards even if its security features are no longer considered to be state of the art.\"

One of the core philosophies of Sig-Net is to reuse proven concepts rather than reinventing the wheel. The following list identifies the existing protocol elements that Sig-Net re-uses, either conceptually or physically:

- sACN: The 1:1 universe-to-multicast mapping creates scalability limits on standard network switches (IGMP exhaustion). However, the core concept of basing Sig-Net on multicast is correct and has been retained, albeit with an improved Multicast Folding strategy.

- Art-Net (DMX): There is almost no difference between how sACN and Art-Net handle DMX other than transport routing. Sig-Net uses multicast but fixes the sACN IGMP scalability issue.

- Art-Net (Discovery): The ArtPoll mechanism is universally understood, lightweight and stateless. Sig-Net uses the concept of continuous polling but includes options for segmenting node-discovery to avoid network storms.

- Art-Net (RDM): The flat architecture and streaming approach to RDM in Art-Net have been highly successful. Sig-Net retains that concept but adds native multi-Sender synchronisation.

- Art-Net (Timecode): The simple multi-stream approach to timecode is well-liked and has been retained in Sig-Net.

- RDMnet (RPT): RDMnet has not seen widespread support, primarily because the requirement for a central broker has not been well received. Sig-Net retains a flat streaming approach and allows multi-Sender operation via passive snooping instead of a broker.

- RDMnet (LLRP): LLRP has been well received but, by its design intent, does not fit cleanly into a secured environment. That said, Sig-Net includes robust node recovery and configuration mechanisms.

- IoT: The IoT industry went through a lot of pain and embarrassment dealing with security. They have learnt a lot in recent years and Sig-Net builds on that, reusing protocols such as CoAP.

From these conclusions, the specification below has evolved.

Wayne Howell

February 2026

# Acknowledgements 

Singularity (UK) Ltd would like to thank for following individuals for their assistance in the evolution of Sig-Net:

> Chris Kennedy
>
> Thierry Dupont
>
> Alan Giraudon
>
> Karen Howell
>
> Red Walter
>
> Andrew Berry
>
> Tracy Fitch
>
> Simon Canins
>
> Peter Newman
>
> Ainars Pastars
>
> Lars Wernlund
>
> Shep Dick
>
> Christian Reese
>
> Richard Thompson
>
> Glenn Keates

# Introduction 

## Overview 

This protocol specification describes a method of transferring lighting control and timing data via a network. It introduces a level of network security that may allow users to comply with aspects of cybersecurity standards and legislation such as the EU Cyber Resilience Act (CRA), California SB-327 and Oregon HB-2395.

## Conditions of Use 

Sig-Net® is a proprietary protocol designed and owned by Singularity (UK) Ltd.

Singularity (UK) Ltd hereby grants a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to any person or entity (\"Licensee\") to develop, manufacture and distribute software or hardware that implements the Sig-Net protocol, subject to the following conditions:

1.  Attribution: The Licensee shall include the following credit in the product\'s user manual, digital \'About\' screen, or accompanying technical documentation: \"Sig-Net® Designed by and Copyright Singularity (UK) Ltd.\"

2.  Product Identification: The Licensee shall assign a unique product identifier (SoemCode) for each product or product variant and report it accurately during discovery polling, as defined in Section [6.5](#soemcode).

3.  Trademarks: The Licensee acknowledges that Sig-Net® and Multicast Folding™ are trademarks of Singularity (UK) Ltd. When using these trademarks in product marketing or user interfaces, the Licensee agrees to adhere to the branding guidelines available at www.Sig-Net.net.

By implementing Sig-Net in any product or system, the Licensee agrees to be bound by these conditions. This licence is governed by the laws of England and Wales. Any disputes arising under or in connection with this licence shall be subject to the exclusive jurisdiction of the courts of England and Wales.

## Compliance Notice & Disclaimer 

Compliance with this protocol specification is the sole and exclusive responsibility of the manufacturer or provider and is entirely within their control and discretion. Any markings, identification or other claims of compliance do not constitute certification or approval of any type or nature whatsoever by Singularity (UK) Ltd (SUL).

SUL neither guarantees nor warrants the accuracy or completeness of any information published herein and disclaims liability for any personal injury, property or other damage or injury of any nature whatsoever, whether special, indirect, consequential or compensatory, directly or indirectly resulting from the publication, use of, or reliance on this document.

Sig-Net is provided by SUL \"AS IS\", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability or fitness for a particular regulatory purpose.

Singularity (UK) Ltd does not warrant that implementations of Sig-Net™ will not infringe upon the intellectual property rights or patents of third parties.

While Sig-Net incorporates security concepts designed to assist manufacturers in securing their network interfaces, use of this protocol does not guarantee compliance with the EU Cyber Resilience Act (CRA), the UK Product Security and Telecommunications Infrastructure (PSTI) Act, California SB-327, Oregon HB-2395, or any other cybersecurity legislation.

Secure operation of a Sig-Net network is a shared responsibility, requiring proper product implementation by the manufacturer and diligent lifecycle management by the system integrator and end user.

Regulatory compliance is evaluated on the final manufactured product (including hardware design, key storage mechanisms, firmware implementation and lifecycle management). Compliance is the sole and exclusive responsibility of the manufacturer implementing the protocol. SUL shall not be held liable for any regulatory fines, product recalls, compliance failures, or damages of any nature directly or indirectly resulting from the implementation of this document.

## Vulnerability Disclosure

SUL maintains a vulnerability disclosure policy for this specification. Security vulnerabilities discovered in the Sig-Net protocol design should be reported to: office@singularity-uk.com.

Manufacturers implementing Sig-Net are independently responsible for establishing and publishing their own vulnerability handling processes as required by Article 13(6) of the EU Cyber Resilience Act.

# References to other Documents 

## Normative References 

This section details external documents and standards that are referenced by this specification.

- \[CoAP\] RFC 7252 The Constrained Application Protocol (CoAP)

> This standard is maintained by the IETF.

- \[E1.31\] ANSI E1.31 - 2025 Entertainment Technology - Lightweight streaming protocol for transport of DMX512 using ACN.

This standard is maintained by ESTA.

- \[E1.33\] ANSI E1.33 Entertainment Technology -- Message Transport and Device Management of ANSI E1.20 (RDM) over IP Networks (RDMnet).

> This standard is maintained by ESTA.

- \[E1.37-2\] ANSI E1.37-2 Entertainment Technology -- Additional Message Sets for ANSI E1.20 (RDM) -- Part 2, IPv4 & DNS Configuration Messages.

> This standard is maintained by ESTA.

- \[FTC\] ANSI E1.37-4 Entertainment Technology -- Remote Device Management over DMX512 Networks - File Transfer Control with Firmware Upload capabilities.

> This standard is maintained by ESTA.

- \[E1.37-7\] ANSI E1.37-7 Entertainment Technology -- Additional Message Sets for ANSI E1.20 (RDM) -- Gateway and Splitter Configuration.

> This standard is maintained by ESTA.

- \[HMAC\] RFC 2104 HMAC: Keyed-Hashing for Message Authentication

> This standard is maintained by the IETF.

- \[HKDF\] RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

> This standard is maintained by the IETF

- \[SHA\] FIPS PUB 180-4 Secure Hash Standard (SHS)

> This standard is maintained by the NIST.

- \[Shannon\] C. E. Shannon, \"A Mathematical Theory of Communication,\" in The Bell System Technical Journal, vol. 27, no. 3, pp. 379-423, July 1948.

> This paper defines the foundational mathematics of information entropy.

- \[CSPRNG\] NIST Special Publication 800-90A Revision 1: Recommendation for Random Number Generation Using Deterministic Random Bit Generators.

> This standard is maintained by the National Institute of Standards and Technology (NIST).

- \[DMX512\] ANSI E1.11 - 2024 Entertainment Technology -- USITT DMX512-A Asynchronous Serial Digital Data Transmission Standard for controlling lighting equipment and accessories.

> This standard is maintained by ESTA.

- \[RDM\] ANSI E1.20 - 2025 Entertainment Technology -- Remote Device Management over DMX512 networks.

> This standard is maintained by ESTA.

- \[Group OSCORE\] No RFC yet, in development.

> This document is maintained by the IETF.

- \[OSCORE\] RFC 8613 Object Security for Constrained RESTful Environments (OSCORE).

> This standard is maintained by the IETF.

- \[URI\] RFC 3986 Uniform Resource Identifier (URI): Generic Syntax.

> This standard is maintained by the IETF.

- \[ETC 0xDD\] ETC, Inc 0xDD Alternate START Code Definition

> ETC, Inc (https://www.etcconnect.com)

## Informative References

This section details external legal frameworks, guidelines and regulatory texts that inform the secure design rationale of this specification but do not dictate protocol mechanics.

- \[CRA\] Regulation (EU) 2024/2847 of the European Parliament and of the Council of 23 October 2024 on horizontal cybersecurity requirements for products with digital elements and amending Regulations (EU) No 168/2013 and (EU) No 2019/1020 and Directive (EU) 2020/1828 (Cyber Resilience Act). <https://eur-lex.europa.eu/eli/reg/2024/2847/oj>

- \[ENISA\] European Union Agency for Cybersecurity (ENISA), Security by Design and Default Playbook, 2026.

- \[PSTI\] United Kingdom Product Security and Telecommunications Infrastructure Act 2022.

# Definitions 

## Document Conventions 

A name enclosed in square brackets (e.g. \[CoAP\]) refers to an external document (Section [2.1](#normative-references)) .

A name enclosed in angle brackets (e.g. \<mult_poll\>) is a symbolic name whose value is defined in Section [16](#appendix-b-definitions).

## Byte Order 

All multi-byte data shall be transmitted in network byte order (Big-Endian).

## Octet and Byte 

Octet is an eight-bit byte. Octet and byte are used interchangeably in this document.

## Bit Numbering

All bitfields and flag registers in this specification use Least Significant Bit zero (LSB 0) numbering.

# Security Concepts 

## Introduction 

This section introduces key security concepts and discusses how Sig-Net interacts with them.

## Secure Design Rationale

Security reviewers may note that Sig-Net uses custom CoAP Options to carry cryptographic data rather than adopting the \[OSCORE\] or \[Group OSCORE\] standards. This departure is a deliberate, necessary architectural decision driven by the extreme real-time constraints of live entertainment control:

- Compute Overhead and Multicast State: Standard secure CoAP frameworks rely on Authenticated Encryption with Associated Data (AEAD) ciphers, such as AES-CCM or ChaCha20-Poly1305. Applying these to a live lighting environment introduces two severe barriers for baseline embedded hardware. First, enforcing AES decryption in software on a mid-tier \[DMX512\] Gateway receiving 8 multiplexed universes (processing 352 packets per second) exceeds the real-time frame budget, causing dropped frames. Second, while alternative software-optimised ciphers (like ChaCha20) reduce CPU load, all AEAD ciphers require the strict, synchronised management of unique Initialisation Vectors (Nonces). In a decentralized, multi-Sender UDP multicast environment, guaranteeing global Nonce uniqueness without a central broker introduces unacceptable architectural fragility. Sig-Net's use of symmetric HMACs solves both issues, providing stateless integrity and implicit authentication that remains viable on constrained silicon.

- Cleartext Routing: \[OSCORE\] encrypts the CoAP Uri-Path as an inner option to prevent traffic analysis. However, Sig-Net explicitly relies on the URI (e.g. /sig-net/v1/\<scope\>/level/11) as a hardware-layer routing filter. By keeping the URI in cleartext and appending the HMAC as a trailing CoAP Option, network switches and multi-port Gateways can parse routing targets at line-rate, dropping irrelevant multicast universes without wasting CPU cycles on cryptographic verification. See Section [20.2](#why-cleartext-routing).

- Forward Compatibility: The Sig-Net-Security-Mode (Option 2076) explicitly provides a mechanism to support future payload encryption ciphers should legislative guidance eventually mandate the confidentiality of lighting levels, while currently prioritising the processing speed required by the industry.

## Provenance and Attestation 

Device provenance is the process of proving a Device\'s origin and that it is genuine hardware. Sig-Net does not directly verify cryptographic Device provenance over the network (Attestation). Instead, an operator must physically verify a Device before manually providing it with the Root Key (aka K0).

The Manager, which permanently retains K0, represents the highest-value physical security target on a Sig-Net network. See Section [5.7](#compromised-node-or-sender) for a full threat analysis of a compromised Manager.

## Encryption 

Sig-Net does not encrypt payload data. Data is transmitted as plaintext and is therefore readable by any party with access to the network (see Section [5.6](#eavesdropping-sniffing)).

CRA Consideration (Informative): Annex 1, Part I, Point 2(e) of the EU Cyber Resilience Act references the encryption of transmitted data. Sig-Net\'s position with respect to this point is that compliance is subject to the manufacturer\'s risk assessment as required by Article 13(2).

Furthermore, Recital (55) of Regulation (EU) 2024/2847 explicitly permits manufacturers to deviate from state-of-the-art security requirements when complying with widely recognised interoperability standards, or when a requirement is fundamentally incompatible with the nature of the product. Enforcing payload encryption severely limits the density of universes that baseline, non-hardware-accelerated Gateways can process at 44Hz, rendering it incompatible with the real-time constraints of the entertainment industry.

In the context of live entertainment control, neither lighting levels nor Device management parameters originate as confidential information. The operational state of the system can be derived by a competent observer simply by looking at the physical output (the lighting rig) or reading the local user interface screens on the devices. Therefore, the primary security risk is not whether this operational data can be observed in transit, but whether an unauthorised party can alter the state of the rig.

Sig-Net addresses this risk entirely through cryptographic authentication and integrity (HMAC) rather than payload confidentiality (Encryption). While commands and levels are transmitted as plaintext, they cannot be forged, spoofed, or replayed without possession of the appropriate role-specific derived key (e.g. Ks or Km_local), which is held in protected non-volatile storage.

Furthermore, enforcing payload encryption severely limits the density of universes that baseline, non-hardware-accelerated Gateways can process at 44Hz. Given this reality, the most productive security investment is ensuring that management commands cannot be forged, spoofed, or replayed---which Sig-Net achieves cryptographically via Km_local---rather than mandating payload encryption that traffic analysis would in any case contextualise.

Physical network access is a prerequisite for any passive observation. In deployments where topology confidentiality is a specific identified risk --- shared infrastructure venues, multi-tenant environments, or rental contexts where network access changes between events --- physical network isolation or VLAN segmentation shall be treated as a mandatory compensating control rather than an optional recommendation.

The Security-Mode option (Section [8.3](#security-options), Option 2076) is explicitly designed to provide a forward-compatible migration path should a manufacturer\'s risk assessment, or future regulatory guidance, conclude that payload encryption is required.

Manufacturers should document their assessment of whether the nature of entertainment control data (lighting levels, timecode) and their specific deployment environment justify the conclusion that HMAC-based integrity and authentication, without payload encryption, is proportionate to the identified risk. This formal risk assessment should be included in the product\'s technical documentation, citing the use of role-specific HMACs and physical network isolation as the primary controls for ensuring data integrity and preventing unauthorized access.

## Authentication 

Authentication is the process of proving that a Device is a legitimate member of a trusted network role. Possession of a key derived from K0 serves as cryptographic proof that the sender is an authentic participant in the system.

## Integrity 

Integrity is the process of ensuring that a packet has not been tampered with in transit. This is achieved by sending each packet with an \[HMAC\] (Hash-based Message Authentication Code).

## Authorisation 

Authorisation is the process of determining if a Device has the permission to perform an action. Sig-Net uses an Implicit Authorisation model; possession of a role-specific key (e.g. the Manager Key) provides the mathematical proof required to authorize a command.

## Freshness 

Freshness checking is the ability to ensure that received packets are fresh and not old copies. Sig-Net achieves this with a sequence number and session ID inside the \[HMAC\].

## Security Lifecycle & Extensibility (Informative)

### Firmware Updates

Sig-Net provides a secure, authenticated transport layer that may be used to carry firmware update payloads. This may be achieved using the standard \[FTC\] \[RDM\] extension encapsulated within the TID_RDM_COMMAND structure, or natively via dedicated Sig-Net TIDs (such as manufacturer-proprietary TIDs).

Firmware Routing via Endpoints:

When using \[FTC\] over Sig-Net, the intended target of the firmware update is deterministically defined by the Endpoint specified in the Command URI:

- Root Endpoint (0): If a Device declares Root_Firmware_Support (Bit 6) via TID_RT_ROLE_CAPABILITY, a TID_RDM_COMMAND containing an \[FTC\] payload directed to Endpoint 0 shall be processed by the Sig-Net Node to update its own core network processor, bypassing standard \[RDM\] discovery.

<!-- -->

- Data & Virtual Endpoints (1 to N): A TID_RDM_COMMAND containing an \[FTC\] payload directed to a Physical Data Endpoint shall be routed downstream to update the physical RDM-Responder attached to that port. Alternatively, if directed to a Virtual Endpoint, the payload may be consumed internally by the Node to update specific secondary hardware subsystems associated with that Virtual Endpoint.

- Security Mandate (Sig-Net Devices Only): Because Sig-Net transmits application payloads as plaintext, manufacturers choosing to implement native firmware updates for the Sig-Net Device itself (via the Root Endpoint) shall ensure that the firmware image is cryptographically signed by the manufacturer prior to transmission and that the receiving Sig-Net Device verifies the signature before applying the update. Encryption of the firmware image is additionally recommended to prevent reverse engineering of proprietary code.

> Informative Note: This mandate cannot apply to firmware updates routed to Data Endpoints for downstream legacy RDM-Responders, as those devices operate outside the Sig-Net protocol boundary and receive standard unauthenticated serial \[RDM\]. Manufacturers of downstream RDM-Responders are independently responsible for the security of their own firmware update mechanisms.

### Key Rotation

Because standard Sig-Net control traffic prioritises execution speed via plaintext payloads, a new Root Key (K0) cannot safely be transmitted over the primary network interface. In the event of a compromised Sig-Net Device, K0 must be rotated out-of-band (e.g. via local UI or USB) or via a dedicated, cryptographically authenticated encrypted tunnel extension.

Operators should rotate the Root Key (K0) whenever a production is repurposed or if the physical security of the network has been compromised.

### Future Encryption: 

The Sig-Net-Security-Mode option is specifically reserved to allow future minor-version updates to introduce AES-GCM payload encryption for management commands and over-the-wire key rotation, providing an upgrade path as embedded silicon capabilities advance.

# Threat Vectors 

## Introduction 

This section identifies some key threat vectors and discusses how Sig-Net does or does not handle them.

## Man-in-the-Middle 

A Man-in-the-Middle (MITM) attack involves an attacker intercepting a valid packet, modifying it and retransmitting. For example: changing a channel level from zero to full. Sig-Net protects against this using integrity checking. Each packet is sent with an \[HMAC\] which allows the Device to confirm that the packet has not been tampered with in transit.

## Masquerading and Spoofing 

Masquerading attacks involve an attacker pretending to be a legitimate Device. For example, an attacker pretending to be a lighting console and sending bad data. As with MITM attacks, the \[HMAC\] protects against this.

## Replay Attack 

A replay attack involves an attacker recording part of the show and replaying it at another time, perhaps to force a blackout during the show. Sig-Net uses a sequence number and session ID inside the \[HMAC\] to reject old or duplicate numbers.

## Rogue Device 

The threat is someone plugging a rogue Device into the network. Sig-Net protects against this using authentication. Without the Root Key that authenticates a Device, it cannot generate a valid \[HMAC\] and therefore cannot participate in communication.

## Eavesdropping & Sniffing 

Data is transmitted as plaintext and can therefore be read by any party with access to the network segment. Physical or VLAN-level network isolation is the recommended mitigation where confidentiality is required.

## Compromised Node or Sender 

Sig-Net uses a unique per-Device management key (Km_local), because of this the blast radius of a physically compromised Node is contained. If an attacker successfully compromises a legitimate Node (e.g. physically extracting the memory from a moving light), they only expose that specific Node\'s Km_local, the global Citizen Key (Kc) and the Sender Key (Ks). Because the Node deleted the Root Key (K0) immediately after onboarding, the attacker cannot mathematically derive the management keys for any other Node on the network. They cannot spoof the Manager to reconfigure the rig or alter the state of other devices.

## Compromised Manager

The threat profile of a compromised Manager Device is categorically different to a Node or Sender (Section [5.7](#compromised-node-or-sender)) and should be understood by any operator deploying Sig-Net.

A Manager permanently retains the Root Key (K0). If an attacker successfully extracts K0 from a Manager, the attacker can derive every key in the system (Ks, Kc, Km_global and any Km_local for any Node whose TUID is known). They can forge authenticated packets for any role, spoof any Sender or Manager command and reconfigure or disrupt the entire system.

To mitigate this risk:

- Manager role devices shall use the highest available hardware security for K0 storage (see Section [14.1.2](#key-storage-hardware)). A dedicated secure element is strongly recommended for Manager implementations.

- Operators shall treat Manager role devices with the same physical security discipline as other high-value credentials. Manager devices should not be left unattended and accessible in shared or publicly accessible spaces.

- In the event of a suspected Manager compromise, the Root Key shall be rotated immediately via out-of-band onboarding off all devices on the network (Section [4.9.2](#key-rotation)).

## Offboarded Beacon Spoofing

Because offboarded Device beacons (Security-Mode 0xFF) carry no valid HMAC by design, they cannot be authenticated. An attacker with access to the network can forge a beacon carrying an arbitrary TUID, causing a Sender to display a false \"offboarded Device present\" notification or to incorrectly mark an operational Device as lost or offboarded.

This is an inherent limitation of the offboarded beacon mechanism. It does not compromise the integrity of authenticated Sig-Net traffic --- a forged beacon cannot cause an onboarded Node to change its behaviour or accept commands --- but it may cause operational confusion at the management console level. See Section [10.2.1](#offboarded-operation-beacon-mode-1) for mitigation.

Physical or VLAN-level network isolation (Section [5.6](#eavesdropping-sniffing)) is the primary mitigation. Operators should treat unexpected offboarded beacon notifications during live operation as a potential indicator of network intrusion or misconfiguration.

# System Architecture 

## Structure 

A flat, peer to peer network architecture is used by Sig-Net.

## Functional Roles 

Sig-Net operates on a flat, peer-to-peer multicast architecture. To manage network authorisation without requiring a central server or hierarchical broker, functionality is divided into four logical roles. A single physical Sig-Net Device may implement any combination of these roles depending on its operational purpose. All roles participate in network discovery.

- Manager Role: An administrative entity possessing the capability to perform network configuration, Device discovery and \[RDM\] transactions. Depending on the cryptographic keys provided to it during onboarding, a Manager operates in one of two states:

  - Equal Manager: The Device possesses the Root Key (K0) and can dynamically derive all targeted keys (Km_local) to securely configure other endpoints. Multiple Managers sharing the same K0 operate as Equal Managers with full, redundant network authority (e.g. a Main and Backup Console).

  - Guest Manager: A restricted operational state where the Device is provisioned only with the global derived keys (Km_global, Ks and Kc), but lacks K0 and Km_local. Guest Managers can discover the network topology, monitor Device status and transmit real-time data, but are cryptographically prohibited from altering Device configurations or executing \[RDM\] commands (e.g. a touring console controlling a house rig).

- Sender Role: A control entity authorised to transmit real-time lighting levels and timecode. (e.g. the playback engine within a lighting console or an architectural wall plate).

- Node Role: A consumer entity that receives lighting control data, executes commands and multicasts its state and replies. Devices acting in a Node role hold a unique, cryptographically derived management key (Km_local) to verify inbound configuration commands without needing to trust a central server.

- Visualiser Role: A passive consumer entity (e.g. a 3D rendering suite) that subscribes to lighting control data, preview streams and patch directories. Visualisers do not output physical data or generate configuration commands. They do not have data endpoints.

Informative note: A physical hardware Device will frequently implement multiple roles simultaneously. Examples:

- A DMX512 Gateway that outputs Sig-Net as DMX512, while also receiving DMX512 to transmit onto the network, operates concurrently as both a Node and a Sender.

- A lighting console that streams \[DMX512\] levels while also allowing the user to patch the rig operates concurrently as both a Sender and a Manager.

Informative Note (Manager-less Operation): While a Manager is required to onboard devices, configure IP addresses and assign routing patches, a Sig-Net system can actively operate a live show without a Manager present on the network. If a system consists only of onboarded Senders and Nodes, the Senders will stream level data and the Nodes will output it. Unmanaged Nodes will continuously transmit \<mult_node_lost\> messages (as defined in Section [10.2.6](#device-loss-detection-lost-mode)), but this does not impede the real-time processing of lighting data or timecode.

## Trust 

The Root Key is used to define the trust structure of a Sig-Net network. Sig-Net uses a Human-in-the-Loop trust model; the operator is responsible for verifying the provenance and physical integrity of a Device before supplying it with the Root Key (K0) via a local interface.

## Air-Gap 

Sig-Net is self-contained and is natively capable of operating in air-gapped (non-Internet connected) environments. It does not require external Time Servers (NTP), DNS, or external certificate validation to maintain cryptographic integrity.

## SoemCode

A SoemCode is a 32-bit unsigned integer. To ensure global uniqueness without requiring a central registry, the upper 16 bits shall contain the manufacturer\'s officially assigned ESTA Manufacturer ID and the lower 16 bits shall contain a specific product variant ID managed independently by the manufacturer. SoemCode 0x00000000 is reserved and shall not be used.

Manufacturers that do not hold an ESTA Manufacturer ID shall obtain one prior to implementing Sig-Net. ESTA Manufacturer IDs are available to any organisation manufacturing relevant products and are assigned by the ESTA Technical Standards Manager. Implementing Sig-Net without a valid ESTA Manufacturer ID will result in SoemCode collisions with other manufacturers and is not permitted.

For devices that also support \[RDM\], the 16-bit Product Variant ID should match the Device\'s \[RDM\] Device Model ID to ensure consistent identification across both protocol layers.

## Transport Unique Identifier (TUID)

The TUID is a 48-bit value consisting of a 16-bit Manufacturer ID (assigned by ESTA) in the upper two bytes and a 32-bit Device ID (managed independently by the manufacturer) in the lower four bytes.

To prevent identity collisions between physical hardware devices and software applications (e.g. PC-based consoles or conformance tools) operating on the same network, the 32-bit Device ID shall be partitioned using its Most Significant Bit (MSB):

- 0x00000000 to 0x7FFFFFFF (MSB = 0): Static Assignment. Used for physical hardware devices. This ID must be uniquely assigned by the manufacturer during production and stored in non-volatile memory.

- 0x80000000 to 0xFFFFFFEF (MSB = 1): Dynamic Assignment. Used for software applications that lack a fixed hardware identity. The application shall generate a random Device ID within this range using a \[CSPRNG\]. Permanent installations should save this dynamically generated TUID to non-volatile storage during initial installation and reuse it persistently. Truly transient software (such as diagnostic apps) may generate a new Dynamic TUID upon each execution.

- 0xFFFFFFF0 to 0xFFFFFFFF: Reserved for future administrative or diagnostic use.

Informative Note on Dynamic TUID Generation: To ensure statistical uniqueness when multiple transient software instances operate on the same host machine sharing a single MAC address, applications generating Dynamic TUIDs should seed their \[CSPRNG\] using a combination of the host MAC address, a sub-millisecond timestamp and the application\'s unique Process ID. The application takes the bottom 31 bits of the CSPRNG output and sets the MSB to 1.

Informative Note on Dynamic TUID Collisions: In specialist applications where a single host dynamically generates large numbers of virtual nodes, the originator application is responsible for internal collision avoidance. Originators should monitor the scope's TID_POLL_REPLY communication to verify their randomly generated 31-bit Device ID is unique on the subnet prior to initiating authenticated network communication.

Informative Note on Human Readable Format: The recommended method for representing the TUID in text is a hexadecimal format with a colon separating the Manufacturer ID and the Device ID, identical to the convention defined in \[RDM\].

Example format: mmmm:dddddddd (where mmmm is the 16-bit ESTA Manufacturer ID and dddddddd is the 32-bit Device ID). Devices should use uppercase characters (A-F) for all TUID.

## TUID and E1.20 UID Relationship

A Sig-Net Device that is simultaneously a native IP-connected RDM-Responder possesses both a TUID (identifying it as a Sig-Net network entity) and an E1.20 UID (identifying it as an \[RDM\] Device, as defined in \[RDM\]). These two identifiers exist in separate protocol namespaces and serve distinct purposes.

Such a Device shall assign the same 48-bit value to both its TUID and its E1.20 UID.

## Endpoints

The logical and physical interfaces of a Sig-Net Node are addressed using a 16-bit integer known as an Endpoint.

### Root Endpoint

Endpoint 0 is known as the Root Endpoint and is reserved as the administrative interface for the entire physical product. It is used to report and set global Device parameters (e.g. TID_RT_DEVICE_LABEL or IP network settings). A Sig-Net Node shall implement one Root Endpoint.

Administrative \[RDM\] & Firmware: To maintain architectural separation, the Root Endpoint does not function as a standard RDM-Responder and is strictly prohibited from parsing legacy \[RDM\] configuration or discovery logic (e.g., SUPPORTED_PARAMETERS, IDENTIFY_DEVICE). However, to support Device-level updates, devices declaring Root_Firmware_Support in TID_RT_ROLE_CAPABILITY shall accept encapsulated TID_RDM_COMMAND payloads on the Root Endpoint strictly limited to the \[FTC\] Firmware Update PIDs. In this specific context, the encapsulated \[RDM\] protocol is used purely as a binary file transport mechanism to update the core Device firmware.

### Data Endpoints

Endpoints in the range 0x0001 to 0xFF00 represent logical or physical ports that consume, route, or generate data. Data Endpoints shall be numbered consecutively from 0x0001. Sig-Net Nodes are not required to implement Data Endpoints.

- Physical Endpoints: A Data Endpoint that maps to a physical hardware port (e.g. a 5-pin \[DMX512\] socket on a Gateway). It outputs TID_LEVEL data as physical \[DMX512\] and acts as a transparent proxy for TID_RDM_COMMAND payloads, forwarding them to downstream RDM-Responders.

- Virtual Endpoints: A Data Endpoint that maps to an internal logical block (e.g. the motor control engine of a native IP moving light). It consumes TID_LEVEL data internally. To allow Managers to configure standard fixture properties (such as DMX_START_ADDRESS or DEVICE_MODE), the Node shall expose an internal Virtual RDM-Responder on this Endpoint. The Node terminates and processes TID_RDM_COMMAND payloads directed here as if it were a standalone physical fixture.

Linked Hardware Capabilities: If a Node\'s physical hardware design restricts a specific Data Endpoint parameter (such as TID_EP_FAILOVER or TID_EP_DMX_TIMING) to a global state across multiple ports, the Node may apply a Parameter Update intended for a single endpoint to all its linked endpoints simultaneously.

If a Node applies a configuration change to linked endpoints as a side-effect of a Parameter Update, the Node shall proactively multicast the updated parameter state for every affected endpoint to its Reply URI (as defined in Section [10.4.2](#parameter-updates-set)). This guarantees that all active Managers are informed of the hardware\'s linked behaviour and can maintain accurate interface synchronisation.

### Reserved Endpoints

Endpoints in the range 0xFF01 to 0xFFFE are reserved for future use and shall not be used.

### Broadcast Endpoint 

The Broadcast Endpoint 65535 (0xFFFF) is used exclusively in the URI to target a transaction at all valid endpoints on a Node simultaneously, encompassing both the Root Endpoint (0) and all Data Endpoints (1 to N).

When a Node receives a Parameter Update (SET) or a Parameter Query (GET) addressed to 65535, it shall process the enclosed TIDs against every applicable endpoint. If a Parameter Query (GET) addressed to 65535 requires the Node to generate responses from multiple endpoints, the Node shall sequentially transmit the reply packets subject to the minimum pacing delay (\<endpoint_spacing_delay\>) defined in Section [10.2.3](#device-response-logic).

### Endpoint Examples

- A moving light that consumes a single \[DMX512\] universe has an endpoint count of 1. Endpoint 0 sets the fixture name; Endpoint 1 sets the Universe the fixture listens to.

- A \[DMX512\] Gateway with 10 physical outputs has an endpoint count of 10. Endpoint 0 sets the gateway name; Endpoints 1 through 10 route configuration and \[RDM\] to each respective physical serial port.

# Root Key and Key Derivation 

## Introduction

Sig-Net uses a 256-bit Root Key (K0) to cryptographically derive four role-specific keys: the Global Manager Key (Km_global), the Node-Specific Manager Key (Km_local), the Sender Key (Ks) and the Citizen Key (Kc). Kc serves as the \'Citizen Key\' used by all Sig-Net devices to announce their presence and identity.

## Root Key (K0) Specification

The Root Key (K0) is the sole cryptographic root of trust. K0 shall be 32 bytes in length.

To comply with CRA secure-by-default requirements, devices shall not be shipped with a pre-configured, hardcoded, or default K0 (e.g. a string of zeros). A Sig-Net Device shall refuse to process or transmit secure network control traffic until a cryptographically strong K0 is established. See Section [7.2.1](#entropy-validation).

Establishing K0:

To ensure K0 is established securely and to prevent typographical errors that would compromise network interoperability, devices shall only permit K0 to be established via the following specific methods:

- On a Manager: A Manager shall establish K0 via one of three methods:

  - Internal Generation (Recommended): The Manager generates a high-entropy 256-bit K0 (or a compliant passphrase) using its internal \[CSPRNG\].

  - Passphrase Entry: The operator manually types a compliant passphrase via the Device\'s local user interface.

  - Electronic Transfer: The 64-character K0 hexadecimal string is loaded out-of-band via a machine-readable interface (e.g. USB or NFC) as defined in Section 7.5.

- On a Node or Sender: A Node or Sender shall establish K0 via one of two methods:

  - Passphrase Entry: The operator manually types the passphrase via the Device\'s local user interface.

  - Electronic Transfer: The 64-character K0 hexadecimal string is loaded out-of-band via a machine-readable interface (e.g. USB, NFC or SNOW) as defined in Section 7.5.

Manual Hexadecimal Entry Prohibition: Under no circumstances shall any Sig-Net Device (Manager, Sender, or Node) provide a user interface mechanism that allows an operator to manually type the 64-character hexadecimal K0 string. All manual human entry must utilize the Passphrase method.

Cleartext Network Onboarding Prohibition: To prevent key interception, K0 onboarding shall not be accepted over the standard Sig-Net UDP transport. An offboarded Device shall silently discard any standard Sig-Net network-delivered onboarding attempt. Over-The-Wire (OTW) onboarding via an IP network is only permitted if the Device implements a dedicated, cryptographically authenticated and encrypted onboarding extension (e.g. via a distinct TLS/DTLS tunnel) explicitly designed for secure key exchange.

### Entropy Validation

Managers shall implement algorithmic entropy validation when automatically generating K0 using their internal \[CSPRNG\].

A Manager shall reject any internally generated 64-character hexadecimal K0 string that possesses a character-level \[Shannon\] entropy of less than 3.0 bits per character. This algorithmic check natively prevents the use of repeated characters, simple repeating patterns and highly predictable sequences.

(Note: Entropy validation for human-entered passphrases is handled independently via the strict complexity rules defined in Section [7.2.3](#input-and-transfer-formats)).

### Offboarded Operation (Beacon Mode)

A Device that lacks a Root Key (K0) is referred to as 'offboarded'. An offboarded Sig-Net Device lacks the derived cryptographic key material (Km_local, Ks, Kc) required to generate or verify an HMAC. Therefore, it cannot participate in authenticated network communication and shall silently discard all incoming authenticated Sig-Net packets.

To alert Managers that it requires onboarding, the Device shall operate exclusively in \"Beacon Mode,\" transmitting a periodic, unauthenticated presence beacon (using Security-Mode 0xFF). The complete URI syntax, timing rules and payload structure for Beacon Mode are defined in Section [10.2.1](#offboarded-operation-beacon-mode-1).

### Input and Transfer Formats

A Sig-Net Device shall support the establishment of the Root Key (K0) through one of the following two formats, determined by the Device\'s physical interface:

- Passphrase Mapping (Human Interface): To support manual entry via a local user interface (e.g. a keypad or 4-button display), a Device shall accept an ASCII Passphrase, subject to the character limits defined below. The Device shall derive K0 from this passphrase using the PBKDF2-HMAC-SHA256 algorithm with 100,000 iterations and the fixed salt \'Sig-Net-K0-Salt-v1\' (18 bytes, ASCII).

> When accepting a passphrase for K0 derivation, a Sig-Net Device shall enforce the following minimum requirements:

- Minimum Length: 10 characters .

- Maximum Length: 64 characters .

- Character Class Diversity: The passphrase shall contain characters from at least three of the following four classes:

- Uppercase letters (A-Z)

- Lowercase letters (a-z)

- Digits (0-9)

- Symbols (!@#\$%\^&\*()-\_=+\[\]{}\|;:\',.\<\>?/)

> The passphrase shall not contain:

- More than 2 consecutive identical characters (e.g. \'aaa\' rejected)

- More than 3 consecutive sequential characters (e.g. \'abcd\' or \'1234\' rejected)

> User Feedback: If a passphrase fails validation, the Device shall display a specific error message indicating which requirement was not met, rather than a generic \'weak passphrase\' message.
>
> Enforcement Roles: A Manager shall enforce all of the above complexity rules and length limits when a user inputs a passphrase or when the Manager generates one. A Manager shall refuse to initialise the network if the passphrase fails any rule.
>
> Nodes or Senders should also validate the passphrase locally at the user interface before deriving keys.
>
> Informative Note on Node UX: If a Node does not validate the input and a user makes a typographical error, the Node will derive an incorrect K0 and cease transmitting Offboarded Beacons. Because it possesses the wrong keys, it will silently drop all valid discovery polls from the Manager due to HMAC verification failures. While advanced Managers may detect and flag the Node\'s subsequent node_lost broadcasts as cryptographic anomalies, the Node will fundamentally fail to authenticate and participate in the network, requiring a physical out-of-band factory reset to correct. Local validation prevents this operational failure.
>
> Validation Consistency and Reference Implementation: Singularity (UK) Ltd publishes a normative Reference Implementation of the passphrase validation algorithm (written in C) within the official Sig-Net GitHub repository. Implementers should integrate this reference routine directly and if a manufacture chooses to implement their own they shall ensure it behaves identically to the reference implementation.
>
> Manager Generated Passphrases: A Manager should provide a user interface facility to automatically generate a cryptographically secure, random 10-character passphrase that adheres to the complexity rules above, using a \[CSPRNG\].
>
> Informative Note: These requirements are designed to ensure a minimum entropy of approximately 50 bits, providing adequate resistance to offline brute-force attacks even with the fixed PBKDF2 configuration. Furthermore, Manager user interfaces should advise operators that using passphrases longer than the 10-character minimum and incorporating greater character diversity, significantly increases cryptographic entropy and provides exponentially greater resistance to offline dictionary and brute-force attacks.

- Direct Hexadecimal (Machine Interface): For electronic transfer via an out-of-band interface (e.g. USB, NFC, or OTW / SNOW), K0 shall be accepted as a 64-character hexadecimal string or a 32-byte binary block.

Once K0 is established (either via direct hexadecimal entry or passphrase mapping), the Device shall immediately proceed to the Key Derivation process (Section [7.3](#key-derivation-function-kdf)). Nodes, Senders and Visualisers shall then permanently discard the source entry material and K0 from volatile memory as mandated in Section [7.6](#storage-and-security)).

Interoperability Mandate: To ensure a consistent Root Key across the network, all Sig-Net devices utilizing the Passphrase Mapping method shall employ this specific PBKDF2 configuration. A Device shall not use a simple SHA-256 hash for K0 derivation from a passphrase.

Informative Note on Fixed Salt and Domain Separation:

Cryptographic best practice typically requires a unique, per-installation salt to prevent pre-computation (Rainbow Table) attacks. However, requiring an operator to manually type a high-entropy, 16-byte random salt alongside a passphrase into constrained edge-Device user interfaces (e.g. a 4-button LCD menu) is operationally unfeasible and actively hostile to the user experience in live entertainment environments.

To resolve this, Sig-Net uses a fixed global salt (\"Sig-Net-K0-Salt-v1\"). This acts as a cryptographic Domain Separator. It invalidates all existing, pre-computed rainbow tables derived from standard IT data breaches or common dictionaries, forcing an attacker to compute hashes specifically for the Sig-Net ecosystem. The defence against offline attacks therefore relies entirely on the high Work Factor (100,000 PBKDF2 iterations) combined with strict passphrase complexity and the strong recommendation for Manager-generated random passphrases.

### Open Mode (Unauthenticated Operation)

A Sig-Net Device may operate in an unauthenticated \"Open Mode\". This is designed to support temporary trade show environments and educational use where the risk assessment concludes that cryptographic security is unnecessary.

- Explicit Opt-In: To comply with secure-by-default requirements, devices shall not be shipped with Open Mode enabled. A Device shall only enter Open Mode via a deliberate, physical interaction with the Device\'s local user interface (e.g. a menu selection or physical button press) or via an authenticated out-of-band channel. Open Mode shall not be enabled via standard Sig-Net UDP network commands.

- Key Bypass: When placed in Open Mode, the Device does not require a Root Key (K0). The Device skips the Key Derivation Function (Section [7.3](#key-derivation-function-kdf)) and ceases transmitting Offboarded Beacons (Section [10.2.1](#offboarded-operation-beacon-mode-1)).

- UI Indication: A Device operating in Open Mode should clearly indicate this unsecure state on its local physical display (if equipped).

- Compliance Mandate: A Sig-Net Device shall not be manufactured to operate exclusively in Open Mode. To claim compliance with this specification, all devices shall fully implement the cryptographic framework (Secure Mode) and the K0 onboarding lifecycle. Open Mode shall solely be provided as a temporary bypass mechanism for low-risk environments, not as a substitute for the mandatory security stack.

## Key Derivation Function (KDF)

Role-specific keys shall be derived from K0 using the HKDF-Expand function defined in \[HKDF\] RFC 5869 Section 2.3, using HMAC-SHA256 as the underlying hash function.

K0 serves directly as the Pseudorandom Key (PRK) input. The output length (L) for all derived keys shall be 32 bytes.

Devices shall independently generate their required keys by passing specific ASCII info strings into the HKDF-Expand function:

Global Keys:

- Sender Key (Ks): HKDF-Expand(K0, \"Sig-Net-Sender-v1\", 32)

- Citizen Key (Kc): HKDF-Expand(K0, \"Sig-Net-Citizen-v1\", 32)

- Global Manager Key (Km_global): HKDF-Expand(K0, \"Sig-Net-Manager-v1\", 32)

Km_global is used exclusively by Managers to authenticate network-wide discovery multicasts to the TID_POLL URI.

Per-Device Management Key (Km_local):

Targeted management is cryptographically bound to each individual Node\'s Transport Unique Identifier (TUID). This ensures that a physically compromised Node cannot be used to spoof configuration commands to other devices.

When a Node is onboarded with K0, it shall derive its own unique management key by appending its 12-character uppercase hexadecimal TUID to the derivation string:

- Node-Specific Manager Key (Km_local): HKDF-Expand(K0, \"Sig-Net-Manager-v1-\" \|\| TUID, 32)

(Example info string for TUID 123456789ABC: \"Sig-Net-Manager-v1-123456789ABC\")

### **Key Usage Summary**

The following table summarizes the primary purpose and role expectations for each derived key:

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Key**         **Primary Purpose**                                                                                  **Transmitted By**                  **Verified By**
  --------------- ---------------------------------------------------------------------------------------------------- ----------------------------------- -----------------------------------------------------
  **Ks**          Authenticates high-frequency control data (Levels, Priority, Timecode, Sync) and Aux Triggers.       Sender                              Node, Visualiser

  **Kc**          Authenticates Device identity, discovery replies and proactive state notifications.                  Node, Sender, Visualiser, Manager   Manager *(and Senders if resolving Aux TUIDs)*

  **Km_global**   Authenticates network-wide multicast discovery requests (TID_POLL) directed to the /poll URI.        Manager                             Node, Sender, Visualiser, Manager *(Poll Snooping)*

  **Km_local**    Authenticates targeted configuration updates and \[RDM\] commands routed specifically to a {tuid}.   Manager                             Node
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

![[]{#_Toc240901071 .anchor}Figure 1 Summary of Key Derivation](media/image2.png){width="6.169810804899387in" height="3.998566272965879in"}

Informative Note on Key Independence: Although the Km_global and Km_local derivation strings share a common prefix (\"Sig-Net-Manager-v1\"), the HKDF-Expand outputs are computationally independent. Knowledge of Km_global does not assist in computing any Km_local value and vice versa, because HKDF-Expand is a Pseudorandom Function (PRF): without K0, the output for any info string is computationally indistinguishable from a random value. This independence holds provided K0 has sufficient entropy as required by Section [7.2](#root-key-k0-specification).

Informative Note on Versioning: The -v1 version suffix ensures that derived keys from future protocol versions are cryptographically distinct, preventing cross-version key reuse. HKDF-Expand for a 32-byte output simplifies internally to a single HMAC calculation: HMAC-SHA256(K0, info \|\| 0x01). Any implementation possessing HMAC-SHA256 can implement this without additional cryptographic libraries.

![[]{#_Toc240901072 .anchor}Figure 2 Summary of Derived Key Usage](media/image3.png){width="6.268055555555556in" height="5.365972222222222in"}

### Key Lifecycle and Erasure

Nodes and Senders shall adhere to a strict \"Calculate-then-Discard\" lifecycle. This is critical to limiting the Blast Radius of a physically compromised Device.

- Derivation: Upon onboarding, the Device shall use K0 to derive the required role-specific keys (Ks, Kc, Km_global and Km_local).

- Storage: The derived role-specific keys shall be committed to hardware-secure non-volatile storage.

- Erasure: Immediately following successful derivation, the Device shall permanently erase the ASCII passphrase (if used) and the Root Key (K0) from its internal RAM and any temporary buffers.

- Operation: During live network operation, the Device shall use only the derived role-specific keys for HMAC calculations. The Device shall not retain K0 in memory after the initial onboarding sequence is complete.

## Human Readable Format (Display and Verification)

While manual keyboard entry of a 64-character hexadecimal Root Key (K0) is prohibited to prevent typographical errors (see Section [7.2.3](#input-and-transfer-formats)), devices acting in a Manager role may need to display the raw 256-bit K0 on a screen for visual verification, cryptographic auditing, or out-of-band export.

When visually presented to an operator, the 256-bit K0 shall be represented as a 64-character hexadecimal string. To ensure visual clarity and readability, devices shall standardise to lowercase characters (a-f) for all visual displays.

Furthermore, when a Device parses a 64-character hexadecimal string supplied via a machine-readable out-of-band method (such as a JSON file on a USB drive), the parsing logic shall be case-insensitive.

## Machine Readable Format (Out-of-Band Transfer)

When transferring K0 electronically between systems (e.g. via USB flash drive, NFC, or a mutually authenticated secure channel such as BLE or a dedicated TLS/DTLS onboarding extension), it shall be encoded as a simple JSON object:

{

\"sig-net_equal_keys\":

> {
>
> \"scope\": \"local\",
>
> \"k0\": \"E4D909C290D0FB1CA068FFADDF22CBD0\...\"
>
> }

}

Informative Note: The JSON key name \"k0\" uses lowercase characters. Implementations shall use this key name. The value must be 64 uppercase hexadecimal characters representing the full 256-bit Root Key.

Files of this format should be stored with an extension of ".equalkeys".

### Restricted Key Export (Guest Access)

To facilitate the secure handover of a lighting network to a guest controller without compromising the administrative control of the rig, an Equal Manager may export a subset of the derived network keys to a JSON file. This file shall not contain K0 or any Km_local keys. It shall only contain the global keys required to operate as a Guest Manager.

It shall be encoded as a simple JSON object:

> {
>
> \"sig-net_guest_keys\":
>
> {
>
> \"scope\": \"local\",
>
> \"km_global\": \"A1B2C3D4\...\",
>
> \"ks\": \"E5F6G7H8\...\",
>
> \"kc\": \"I9J0K1L2\...\"
>
> }
>
> }

The derived key values shall be encoded as 64-character uppercase hexadecimal strings, matching the format required for out-of-band K0 transfers.

Files of this format should be stored with an extension of ".guestkeys".

A Manager application loaded with these restricted keys will successfully authenticate TID_POLL and TID_LEVEL traffic on the designated scope, but will fail HMAC verification if it attempts to transmit configuration Parameter Updates, enforcing a Read-Only administrative state.

## Storage and Security

Devices must limit which derived keys they retain after onboarding:

- Managers: A Manager requires permanent access to K0 to derive management keys for the network. Because the PBKDF2 derivation is mathematically irreversible, a Manager shall securely store the plaintext passphrase (or the direct 64-character hex K0 if onboarded out-of-band) in its hardware-secure enclave. This ensures an authorized operator can recall and view the passphrase via the Manager\'s UI when onboarding new Nodes added to the system.

  - Exception: A Manager may optionally offer a high-security \"Stateless\" mode where K0 is derived at runtime and held exclusively in volatile memory (RAM). In Stateless mode, the user accepts that they must re-enter the passphrase upon every power cycle and must manually manage their own secure record of the passphrase.

- Nodes: Shall derive and store Kc, Ks, Km_global and their own unique Km_local. They shall immediately and permanently discard K0 and any source passphrase after successful derivation.

- Senders: Shall derive and store Kc, Ks, Km_global. They shall immediately and permanently discard K0 and any source passphrase after successful derivation.

- Visualisers: Shall derive (or receive via SNOW) and store Kc, Ks, Km_global. They shall immediately and permanently discard K0 and any source passphrase after successful derivation.

All cryptographic keys and passphrases retained by a Device shall be protected by a secure storage mechanism that preserves their confidentiality and integrity at rest.

- Where the Device hardware provides a protected cryptographic peripheral or secure element capable of performing the required operations, key material should be held within that subsystem and shall not be exposed to the general application processor.

- Where baseline hardware is used and keys must be loaded into application-accessible memory (RAM) for cryptographic computations, they shall be present in plaintext only for the minimum duration necessary to complete the operation and shall be securely zeroized immediately afterwards. Keys shall never be written to non-volatile storage (Flash/EEPROM) in plaintext, unless the manufacturer explicitly relies on the legacy hardware physical-security provisions detailed in Section [14.1.2](#key-storage-hardware).

Key Extraction Prohibition: Under no circumstances shall a Sig-Net Device provide a mechanism to export or extract derived cryptographic keys (Km_local, Km_global, Ks, Kc) over the network or via local interfaces. If a Device provides a \"Configuration Backup\" or \"Cloning\" feature (e.g. via a web interface or USB file export), all derived cryptographic keys shall be excluded from the exported data. Keys must remain bound to the physical hardware that derived them.

To maintain cryptographic integrity during out-of-band transfers (e.g. loading K0 via a USB flash drive or NFC token), manufacturers shall mandate strict physical hygiene. Operators must ensure that physical access to the Device UI is restricted and that transfer media (such as USB drives containing K0.json) are securely wiped immediately after onboarding is complete.

## Offboarding and Erasure

To comply with security lifecycle requirements, support key rotation and allow hardware to be safely repurposed, Sig-Net Devices must support a secure return to an offboarded state. Returning to an offboarded state mandates the permanent deletion of the Root Key (K0) and all derived role keys, the reset of the Sig-Net-Session-ID to zero, and the reset of the persistent CHANGE_COUNT to 0x0000. The Sig-Net-Session-ID shall persist unchanged across this procedure, except when offboarding is performed specifically to recover from the Session ID Overflow condition defined in Section 8.3, in which case the Session ID is also reset to zero.

Informative Note: Because the derived keys are permanently destroyed upon offboarding, the Device\'s cryptographic epoch is ended. Therefore, resetting the Session ID to zero is cryptographically safe; any previously recorded packets from prior sessions will automatically fail HMAC authentication against any future onboarding keys.

Informative Note: Recovering a Device from the Session ID exhaustion error state (Section 8.3) uses this same offboarding-and-rekeying procedure. See Section 8.3 Operational Recovery Note for a discussion of peer device impact.

### Authenticated Network Offboarding

A Manager in possession of the current valid cryptographic keys may offboard a Node over the network by unicasting the TID_RT_OFFBOARD command to the Node\'s Root Endpoint.

Operational Safety Lockout: To mitigate the risk of accidental erasure or malicious insider sabotage during live operation, Nodes shall only accept the TID_RT_OFFBOARD command within the first \<offboard_lockout\> seconds after the Node physically powers on.

If the authenticated TID_RT_OFFBOARD command is received after this lockout period has expired, the Node shall silently discard the command. Therefore, to execute a secure network wipe, an operator must intentionally power-cycle the target Node(s) immediately prior to transmitting the command.

Informative Note: To maintain strict physical security, a software-initiated warm reboot (e.g., via TID_RT_REBOOT) does not satisfy the requirement of a physical power cycle and shall not reset the \<offboard_lockout\> timer

### Physical Out-of-Band Offboarding

To prevent a Device from becoming permanently inoperable if the network key is lost, manufacturers shall implement a physical, out-of-band mechanism to force a return to the offboarded state.

This fallback mechanism shall not be accessible via the Sig-Net network port to prevent unauthenticated network attacks. It shall require either physical human proximity or an authenticated out-of-band channel that is independent of the Sig-Net network. Acceptable mechanisms include a local user interface menu, an NFC interaction, a recessed hardware button, a proprietary serial wipe command received via the physical \[DMX512\]/\[RDM\] connector (facilitating external hardware dongles), or a command received over a mutually authenticated out-of-band connection (such as a BLE channel established by a paired management application).

# Packet Structure

## CoAP Summary (Informative)

Sig-Net uses the Constrained Application Protocol \[CoAP\] operating over UDP. A standard CoAP message consists of a compact 4-byte header, followed by a token, zero or more Options (which function like HTTP headers), a payload marker (0xFF) and the payload itself.

0 1 2 3

0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\|Ver\| T \| TKL \| Code \| Message ID \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Token (if any, length is TKL) \... \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Options (if any) \... \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\|1 1 1 1 1 1 1 1\| Payload (if any) \... \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

## URI Syntax Overview 

The destination of the data is defined using the CoAP Uri-Path option. All Sig-Net URI-Paths (Option 11) shall begin with the following prefix:

> /sig-net/\<version\>/\<scope\>

- Where \<version\> is the protocol version (e.g. v1).

<!-- -->

- Where \<scope\> is a 1 to 32-character ASCII string containing only URL-safe unreserved characters (as defined in \[URI\] Section [2.1](#normative-references)). The scope isolates discrete control networks sharing the same physical IT infrastructure (e.g. separating \"Hall_A\" from \"Hall_B\"). The factory configuration for all devices shall be "local".

The remainder of the URI-Path defines the specific resource (e.g. universes, \[RDM\], management) and is fully defined in Section [10](#payload-syntax).

Where a URI-Path component contains a {tuid}, it shall be represented as a 12-character uppercase hexadecimal string with no separators (e.g. 123456789ABC). This canonical form shall be used in all URI-Path options and in the HMAC calculation input defined in Section [8.5](#hmac-calculations).

Where a URI-Path component contains a numerical index---specifically {universe}, {endpoint}, or {stream}---it shall be represented as a Base-10 decimal integer string. To guarantee deterministic HMAC calculations across all implementations, these decimal strings shall not contain leading zeros (e.g. Endpoint 5 shall be represented as /5, not /05 or /005).

Note that the hyphen in "sig-net" is character 0x2d.

The major version number of this specification document (e.g, 1.x) shall correspond directly to the \<version\> string used in the CoAP URI-Path (e.g. /v1/). Sub-point revisions (e.g. 1.1) represent non-breaking changes (such as new TIDs or clarified definitions) and do not trigger a change in the URI-Path.

## Security Options 

To maintain a clean and standardised payload, Sig-Net does not embed security metadata inside the lighting data payload. Instead, Sig-Net uses custom CoAP Option fields to carry the authentication and freshness data.

Implementations shall include the following five options in every Sig-Net packet (Option 6 is mode dependent). As mandated by \[CoAP\] Section 3.1, these options must appear in order of their Option Numbers on the wire (using standard CoAP extended delta encoding). Note: The Option numbers below are selected from the CoAP private use range to be Elective, Safe-to-Forward and NoCacheKey and to guarantee the correct sequential parsing order required for the HMAC calculation.

- Sig-Net-Security-Mode (Option Number: 2076): An opaque 1-byte field, interpreted by the application layer as an unsigned integer, defining the cryptographic mode. The following values are defined:

  - 0x00: Signifying Plaintext Payload with HMAC-SHA256.

  - 0x01: Signifying Open Mode (Unauthenticated).

  - 0xFF: Indicate an Offboarded Device Beacon. Processing is as described in Section 7.2.

- Sig-Net-Sender-ID (Option Number: 2108): An 8-byte string uniquely identifying the specific origin of the packet. The first 6 bytes shall contain the 48-bit Transport Unique Identifier (TUID) of the Device transmitting the packet. The final 2 bytes shall contain the 16-bit Endpoint number originating the payload (or 0x0000 for Root/Manager commands).

- Sig-Net-Mfg-Code (Option Number: 2140): An opaque 2-byte field, interpreted by the application layer as an unsigned integer, used to specify manufacturer-specific proprietary data.  For all standard Sig-Net control messages, this value shall be 0x0000.  For proprietary data the Manufacturer should set it to representing the sender\'s ESTA Manufacturer ID.

- Sig-Net-Session-ID (Option Number: 2172): An opaque 4-byte field, interpreted by the application layer as an unsigned integer, serving as an increasing session identifier to prevent whole-session replay attacks. The value is a global property of the Sig-Net Device and is bound to its TUID.

> During startup or initialisation, before transmitting its first authenticated Sig-Net packet, every Device (Manager, Sender, Node and Visualiser) must increment this Session ID counter by 1 and successfully save the new value to non-volatile storage. This ensures the Session ID increases with each boot cycle or initialisation. Using a random value is not permitted, since random values cannot guarantee that the counter will always be higher than its previous value after a power cycle. The Session ID shall also be incremented by 1 during live operation if the Sig-Net-Seq-Num wraps (see below).
>
> Devices operating exclusively in Open Mode (0x01) or Beacon Mode (0xFF) are exempt from Session ID and Sequence Number tracking and shall transmit 0x00000000 for these option values.

- Session ID Overflow: In the event that the Session ID reaches 0xFFFFFFFF, the Device shall permanently cease transmitting authenticated Sig-Net packets and shall enter an error state. Normal operation can only be restored by executing a full offboarding and rekeying cycle (as defined in Section [7.7](#offboarding-and-erasure)), which securely resets the Session ID to zero under a new cryptographic epoch.

- Informative Note on Session Exhaustion: While 0xFFFFFFFF represents over 4 billion sessions (a number unlikely to be reached in the physical lifespan of most hardware), poorly written firmware could artificially accelerate this counter. Managers should monitor the reported Session IDs of discovered Nodes and proactively warn the operator if a Device\'s Session ID approaches exhaustion (e.g., crossing 0xFFFF0000). This allows the operator to schedule a preventative rekeying cycle outside of live show conditions.

- Operational Recovery Executing the offboarding and rekeying cycle described in Section 7.7 resets the recovered Device\'s own Session ID to zero, but it does not affect the cached Session ID state held by other Devices on the network. Because Session ID and Sequence Number tracking is maintained in volatile RAM by each receiving Device (Section 8.6, Step 10a), any Manager, Node, Sender or Visualiser that previously exchanged authenticated traffic with the recovered Device\'s TUID will retain its prior high-water-mark Session ID in memory. Upon recovery, the freshly onboarded Device\'s initial packets (Session ID starting again from a low value) will therefore be evaluated as a replay per Section 8.6, Step 8a and silently dropped by any such peer that has not itself been rebooted since the recovered Device went offline.

> Operators shall treat this as an expected consequence of the recovery procedure, not a fault: full interoperability with a Session-ID-recovered Device is restored only once every peer Device that had previously tracked its TUID has cleared its RAM-resident tracking table, which occurs on that peer\'s next power cycle. Where continuous, uninterrupted operation of the wider network prevents a convenient reboot of every peer, manufacturers should provide operators with a manual mechanism that discards a specific TUID\'s cached Session ID and Sequence Number state without requiring a full peer reboot.

- Sig-Net-Seq-Num (Option Number: 2204): An opaque 4-byte field, interpreted by the application layer as an unsigned integer. An increasing counter that increments by 1 for every packet sent within a specific Sender-ID data stream. When the counter on any active endpoint reaches 0xFFFFFFFF, the Sender shall increment its non-volatile Session ID by 1, reset the Sequence Number counters for all of its endpoints back to 1, and utilize these new values for all subsequent transmissions, effectively initiating a new global session for that Device.

> Devices operating exclusively in Open Mode (0x01) or Beacon Mode (0xFF) are exempt from Session ID and Sequence Number tracking and shall transmit 0x00000000 for these option values.

- Informative Note: Senders shall maintain independent sequence counters for each of their Endpoints. This ensures that network jitter or packet loss on one universe stream does not cause anti-replay lockouts on other streams originating from the same physical Device.

<!-- -->

- Sig-Net-Auth (Option Number: 2236): A variable-length byte string containing the cryptographic signature or authentication tag for the packet. The length and generation algorithm of this option are defined by the Sig-Net-Security-Mode:

  - Mode 0x00 this shall be a 32-byte HMAC-SHA256 signature.

  - Mode 0x01 this shall be length 0.

  - Mode 0xff this shall be length 0.

> This option shall be the highest-numbered option in the packet so that it appears last before the payload marker.

Informative Note: Whilst standard \[CoAP\] libraries may automatically insert Token bytes (TKL \> 0), Sig-Net does not use them for state tracking. \[CoAP\] option encoding uses a delta scheme; the large numerical gap between the standard Uri-Path option (Option 11) and the first Sig-Net custom option (Option 2076) will result in the 2-byte extended delta encoding prefix being used, as defined in RFC 7252 Section 3.1. Implementations must handle this extended delta correctly.

Informative Note: \[CoAP\] section 3.2 defines the opaque format. Sig-Net uses opaque to mandate that the option fields are transmitted as fixed length fields with zero padding in byte order defined by section 3.2.

## Packet Structure 

The resulting Sig-Net packet encapsulates the CoAP standard, integrating the target URI, the security option and the TLV application payload.

0 1 2 3

0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\|Ver\| T \| TKL \| Code \| Message ID \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Token (if any, length in TKL) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Uri-Path Options (eg \"sig-net\", \"v1\", \"local\", \"level\", \"1\")\|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Sig-Net-Security-Mode Option (1 Byte) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Sig-Net-Sender-ID Option (8 Bytes) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Sig-Net-Mfg-Code Option (2 Bytes) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Sig-Net-Session-ID Option (4 Bytes) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Sig-Net-Seq-Num Option (4 Bytes) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Sig-Net-Auth Option (32 Bytes) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| 0xFF (Payload Marker) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

\| Application Payload (Defined in Section [10](#payload-syntax)) \|

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

If the Application Payload is empty (zero bytes), the Payload Marker (0xFF) shall be omitted from the packet, as required by \[CoAP\] Section 3.

## HMAC Calculations

The HMAC is calculated over a deterministic concatenation of the critical packet values. This guarantees Integrity and Authenticity without requiring complex CoAP byte-stream reconstruction.

The Sender shall calculate the \[HMAC\] using the HMAC-SHA256 algorithm as defined in \[HMAC\] and \[SHA\].

1.  Message: The concatenation of the following byte sequences, in exact order:

<!-- -->

1.  The full constructed URI string as ASCII: Derived from the CoAP Uri-Path and Uri-Query options as defined by \[CoAP\] Section 6.5 (steps 6-8). The URI string shall begin with a forward slash / character (0x2F), shall not include a null terminator and shall not include the scheme or authority components (e.g. coap://host). If Uri-Query options are present in the packet, they shall be appended to the string using the ? and & delimiters as defined in the referenced RFC steps.

> Example byte sequence for /sig-net/v1/local/level/1: 0x2F 0x73 0x69 0x67 0x2D 0x6E 0x65 0x74 0x2F 0x76 0x31 0x2F 0x6C 0x6F 0x63 0x61 0x6C\...

2.  The Sig-Net-Security-Mode option value: (1 byte).

3.  The Sig-Net-Sender-ID option value: (8 bytes).

4.  The Sig-Net-Mfg-Code option value: (2 bytes).

5.  The Sig-Net-Session-ID option value: (4 bytes).

6.  The Sig-Net-Seq-Num option value: (4 bytes).

7.  The Application Payload bytes.

As the Sig-Net-Seq-Num increments for every transmission, each individual CoAP packet produces a unique HMAC even if the application payload remains identical (e.g. streaming static \[DMX512\] levels).

If a Sender needs to retransmit a lost configuration command (e.g. after detecting no change in a Node\'s CHANGE_COUNT), it must treat the retry as a new transmission. It shall increment the Sig-Net-Seq-Num and generate a fresh HMAC. Retransmitting a packet with a previously used Sequence Number will cause the Device\'s anti-replay sequence enforcement (Section [8.6](#packet-processing-and-replay-attack-prevention)) to drop the packet.

Informative Note on Message ID and Token: Hop-by-hop CoAP header fields (such as Message ID and Token) are explicitly excluded from the HMAC calculation. This ensures that standard CoAP proxies can dynamically alter these transport fields for routing purposes without invalidating the Sig-Net security signature.

Informative Note on CoAP Code: The CoAP Code byte (which is always 0x02 for POST in Sig-Net) is also excluded from the HMAC calculation, consistent with the general exclusion of CoAP header fields. Because Sig-Net exclusively uses CoAP NON POST messages, an attacker cannot meaningfully alter the Code byte without rendering the packet invalid to a standard CoAP parser. The URI, which is covered by the HMAC, definitively identifies the resource and operation, providing equivalent protection to explicit Code byte authentication within the Sig-Net operational context.

## Packet Processing and Replay Attack Prevention

Upon receiving a Sig-Net packet, a Device shall process the security option in the following order:

1.  Security-Mode Pre-check: The Device shall inspect the Sig-Net-Security-Mode (Option 2076).

    a.  If the value is not explicitly supported by the Device\'s firmware (e.g. a future cryptographic mode), the Device shall silently discard the packet and perform no further processing or cryptographic verification.

    b.  If the value is 0xFF, the packet is an Offboarded Device Beacon. The Device shall not attempt HMAC verification and shall not act on the payload beyond presenting the Device\'s presence to the operator UI (as defined in Section [10.2.1](#offboarded-operation-beacon-mode-1)). All further security processing steps shall be skipped.

    c.  If the value is 0x00, the packet is a standard authenticated control message. If the Device is currently configured for Open Mode, it lacks the keys to verify the packet and shall silently discard it. Otherwise, the Device shall proceed to Step 2.

    d.  If the value is 0x01, the packet is an Open Mode control message. The Device shall evaluate its own operational state. If the Device is currently onboarded with derived cryptographic keys (Secure Mode), it shall silently discard the packet to definitively prevent cryptographic downgrade attacks. If the Device has been explicitly configured for Open Mode via local opt-in, it shall proceed to Step 2, but shall completely bypass Step 8 (Freshness), Step 9 (Integrity & Authentication) and Step 10 (State Commit).

2.  CoAP Version Check: The Device shall verify that the Ver field in the CoAP header is set to 1 (binary 01), as mandated by \[CoAP\] Section 3. If any other value is present, the Device shall silently discard the packet and perform no further processing.

3.  Token Handling: The Device checks the TKL (Token Length) field in the CoAP Base Header. Sig-Net does not use CoAP Tokens for state tracking. If TKL \> 0, Devices shall skip the Token bytes and proceed to parse the Options. The presence of a Token shall not cause packet rejection.

4.  CoAP Code Check: The Device shall inspect the CoAP Code field in the base header. Sig-Net V1 exclusively utilises POST (0x02). If the Code is any other value, the Device shall silently discard the packet and perform no further processing.

5.  URI Version Check: The Device shall verify the \<version\> string in the URI-Path as defined in Section [12.3](#manager-compatibility-requirements-normative). If the version is unsupported, the packet shall be discarded.

6.  URI Routing Check: The Device parses the CoAP Uri-Path option.

    a.  The Device shall verify the \<scope\> string in the URI-Path. If the scope does not match the Device\'s currently configured scope, the packet shall be silently discarded and perform no further processing or cryptographic verification.

    b.  If the URI contains a targeted {tuid} (such as a /manager/ or /node/ command) and the TUID does not match the Device\'s own TUID, the Device is not the intended recipient. The Device shall silently discard the packet and perform no further processing or cryptographic verification.

7.  Session & Sequence Evaluation: The Device extracts the Sig-Net-Session-ID, Sig-Net-Seq-Num and Sig-Net-Sender-ID option.

    a.  The Sender TUID (the first 6 bytes of the Sender-ID) is the absolute identifier for Session ID tracking.

    b.  The full 8-byte Sender-ID is the absolute identifier for Sequence Number tracking, allowing multi-endpoint gateways to maintain independent sequence threads per physical port.

8.  Freshness: The Device evaluates the freshness of the packet:

    a.  If the received Session ID is less than the stored Session ID for this TUID, the packet is a replay; the Device shall silently drop the packet.

    b.  If the received Session ID equals the stored Session ID, but the Sequence Number is less than or equal to the stored Sequence Number for this Sender-ID, the packet is a replay; the Device shall silently drop the packet.

    c.  For the handling of packets from previously unknown Sender TUIDs where no Session ID record exists, see the First-Packet Bootstrapping rule in Section [8.6.3](#first-packet-bootstrapping).

    d.  If the packet passes these freshness checks, the Device proceeds to Step 9. The Device shall not update its stored sequence state or write to non-volatile memory yet.

> Security Note (Anti-Replay): Because Sig-Net-Session-ID uses an increasing integer, a received Session ID that is lower than the stored value is definitively a replay and is rejected. A received Session ID that is greater is definitively a legitimate reboot or sequence wrap. Therefore, artificial \"hold-off\" delays are not required and should not be implemented, as they would cause unacceptable operational delays. Nodes shall report detected replay anomalies to the network using the TID_DG_SECURITY_EVENT payload.
>
> Security Note (Network Robustness): Because state tracking is cryptographically bound to the Sender TUID and not the IP address, network events such as DHCP IP renewals, or operators manually swapping a backup console into the IP address of a crashed primary console, will not falsely trigger anti-replay lockouts. The backup console will present a new Sender TUID and automatically trigger First-Packet Bootstrapping.

9.  Integrity & Authentication: The Device calculates the expected HMAC using the derived role key designated by the URI as defined in Section [15](#appendix-a-multicast-addresses) and the inputs defined in Section 8.5. It performs a constant-time comparison against the received Sig-Net-Auth option. If the hashes do not match, the packet is forged or corrupted; the Device shall silently drop the packet. Nodes shall report sustained HMAC verification failures to the network using the TID_DG_SECURITY_EVENT payload.

> Security Note (DoS Mitigation): Whilst a failed HMAC drops an unauthorised packet, the packet consumed bandwidth and the cryptographic calculation consumes CPU resources. Nodes shall implement protection to ensure that excessive unwanted traffic does not significantly impact processing of desired network traffic and tasks unrelated to network processing.
>
> When this processing budget is exhausted by a flood of incoming packets, the Node shall simply drop unprocessed packets from its receive buffer. While this will result in the dropping of legitimate traffic, it allows the underlying hardware to remain stable. The Node will resume normal operation when network flood ceases.
>
> Nodes shall not implement automated blocking based on UDP Source IP addresses in an attempt to filter the flood, as attackers can trivially spoof the legitimate Sender\'s IP address to trigger a self-inflicted denial of service. True volumetric DoS mitigation must be handled by physical network isolation or switch-level rate limiting.

10. State Commit: Only after the HMAC is successfully verified shall the Device update its internal security state.

    a.  RAM-Only Tracking: To prevent premature hardware failure through non-volatile memory exhaustion and to accommodate standard \"power-cycle\" troubleshooting, Devices shall store all received Session ID and Sequence Number data in volatile memory (RAM) only.

    b.  Tracking Update: The Device shall update its internal RAM table for the associated Sender TUID and Sender-ID with the newly received values.

    c.  Sig-Net Devices shall support tracking a minimum of 32 unique Sender-ID records. If a packet arrives from a new Sender-ID and the internal table is full, the Device shall evaluate the Least Recently Used (LRU) record. To prevent an attacker from intentionally flushing the table with spoofed identities to facilitate a replay attack, the Device shall only overwrite the LRU record if that Sender has not transmitted a valid packet within the last 3600 seconds (1 hour). If the table is full and the LRU record is newer than 1 hour, the Device shall assume the table is saturated, drop the new unauthenticated packet and immediately multicast a TID_DG_SECURITY_EVENT with Code 0x0005. This 32-entry minimum applies strictly to Node-role implementations; Managers and Visualisers shall scale their tracking tables to accommodate the maximum number of devices expected within their operational scope.

> Informative Note: While received state is stored in RAM, devices acting in a Sender or Manager role must still commit their own transmitted Session ID to non-volatile memory during initialisation as required by Section [8.3](#security-options).

11. Acceptance: The Device executes the Application Payload.

### Manager Processing of Replies

Managers shall implement the full HMAC verification and anti-replay sequence enforcement defined in Section [8.6](#packet-processing-and-replay-attack-prevention) for all received packets, specifically including replies received on the /node and /node_lost URIs, as well as snoop-listened discovery queries on /poll. The 8-byte Sender-ID (Option 2108) contained in the received packet header serves as the unique identifier for tracking sequence freshness. This ensures that data received from different logical endpoints of the same physical Device is tracked in independent sequence windows.

If an incoming authenticated packet fails HMAC verification or violates sequence freshness (e.g. due to Session ID regression), the Manager shall discard the packet. For failures occurring on the /node or /node_lost URIs, the Manager shall additionally log a security anomaly and alert the operator, identifying the transmitting TUID as potentially faulty, compromised, or non-compliant.

### Freshness Architecture (The Lane Model)

Sig-Net employs a tiered freshness model. This architecture separates the global Device state from individual data streams using \"Lanes.\"

![[]{#_Toc240901073 .anchor}Figure 3 The Lane Model](media/image4.png){width="5.302083333333333in" height="3.861134076990376in"}

The freshness of any received packet is evaluated across three tiers:

- Device Tier (Global Session): Every physical Device (TUID) maintains a single Session ID. This counter represents the Device\'s current cryptographic epoch and is stored in non-volatile memory (NVM). All traffic originating from a Device---regardless of the logical endpoint---uses this shared Session ID.

- Stream Tier (Sender Endpoints): Sig-Net isolates independent data streams into Lanes using the Sender Endpoint (contained within Option 2108).

  - Administrative Lane: Discovery polls and management commands originating from a Device shall use Sender Endpoint 0.

  - Data Lanes: Every independent streaming universe (TID_LEVEL), timecode stream (TID_TIMECODE), auxiliary control trigger (TID_OSC via the Auxiliary URI), or any payload originating from a Data Endpoint (Endpoints 1 to N) shall use a unique Sender Endpoint ID (1--63999) to isolate its sequence window from the administrative lane.

- Sequence Tier (Anti-Replay): Anti-replay enforcement occurs at the 8-byte Sender-ID (TUID + Endpoint) level. Each Lane maintains an independent Sequence Number counter in RAM.

Informative Note: This multi-lane isolation ensures that network jitter or out-of-order delivery on one universe (e.g. Universe 1 / EP1) has no impact on the security window of another universe (e.g. Universe 2 / EP2) or management traffic on EP0. If a Device were to use a single global sequence counter for all universes, a minor network delay on one stream could cause a permanent security lockout of all other streams originating from that same TUID.

### First-Packet Bootstrapping

Upon booting and loading its derived keys into memory, Nodes track Sender Session IDs and Sequence Numbers in volatile memory to prevent non-volatile memory exhaustion (see Section [8.6](#packet-processing-and-replay-attack-prevention), Step 9).

When a Node powers on, its internal Sender tracking table is empty. When a Node receives its first packet from a previously unknown Sender TUID (i.e. no Session ID record currently exists in RAM for that Sender), it shall treat the received Session ID and Sequence Number as the initial baseline for that Sender and accept the packet unconditionally, provided all cryptographic HMAC checks pass. Subsequent packets from that Sender shall be subject to strict forward-only enforcement from that new baseline.

Security Note: Because Nodes reset their tracking tables upon power loss, an attacker who recorded a previous session could theoretically replay it immediately after a Node reboots, before the legitimate originator transmits a new packet. However, because a legitimate Sender generates TID_LEVEL keep-alive packets at 1 Hz and a legitimate Manager generates TID_POLL requests every \<poll_time\> seconds, the window for a successful replay attack is bounded to a few seconds. This represents a trivial increase in threat surface in exchange for guaranteed hardware non-volatile memory longevity.

### Post-Reboot Replay Protection

To defend against post-reboot replay attacks (where an attacker records a valid configuration command, forces a Device to power-cycle, and replays the command before the active Manager can assert its state), Devices shall enforce a configuration lockout window upon booting:

12. Link-Up Initialisation: Immediately upon the Devices's network interface transitioning to an active link-state, the Device shall start a non-interruptible timer of \<first_packet_bootstrap_window\> milliseconds.

13. Permitted Traffic: During this window, the Device shall process incoming TID_LEVEL streams and TID_POLL requests normally. This allows legitimate, active Senders and Managers to safely populate the Node\'s volatile tracking table (First-Packet Bootstrapping) with their current Session-ID and Sequence-Number.

14. Prohibited Configuration: During this window, the Device shall reject any high-privilege configuration updates (SET) or commands (such as TID_RT_OFFBOARD or TID_RT_REBOOT) received on /manager URIs. The Device shall treat these forbidden commands as invalid transactions, rejecting them and discarding the packet in accordance with Section 10.1.3.

By the conclusion of the \<first_packet_bootstrap_window\>, the legitimate Manager\'s routine polling will have locked the session baseline and negated and neutralised the window for replaying stale administrative commands.

# Transport

## Multicast Use

Because Sig-Net relies on derived symmetric keys for authentication across the entire network, it natively supports efficient one-to-many communication via UDP Multicast. A Sender signs a packet once using its specific role key and all authorised Sig-Net Devices within the multicast group can verify and process it simultaneously. This is highly advantageous for high-density universe streaming, discovery and global sync commands.

## Multicast Address Mapping

Sig-Net uses a deterministic mapping of CoAP URIs to specific UDP Multicast IP addresses to minimise configuration overhead, prevent network flooding and ensure strict isolation from legacy unauthenticated protocols.

### URI to Multicast Determinism

Sig-Net enforces a strict one-to-one relationship between a CoAP URI and its destination UDP Multicast IP address. Senders and Nodes are not required to maintain complex routing tables; the destination URI deterministically defines the Multicast IP. Where this specification instructs a Device to \"transmit to URI\", the implementation shall automatically resolve that URI to the corresponding multicast address as defined in Section [15](#appendix-a-multicast-addresses).

### Discovery and Management Subscriptions

All onboarded Nodes shall subscribe to \<mult_manager_poll\> and \<mult_manager_send\>.

All Managers shall subscribe to \<mult_node_send\>, \<mult_node_lost\> and \<mult_node_beacon\>.

Senders that only transmit level data, sync, or timecode do not require these subscriptions..

### Default Multicast Folding™ (Universe Mapping)

Sig-Net uses a default pool of 109 Multicast IP addresses (\<mult_u1\> to \<mult_u109\>) to prevent IGMP snooping table exhaustion on network switches. The use of a prime number (109) prevents clustering if an operator patches universes in repeating patterns.

All Sig-Net devices shall, by default, map universes to a Multicast IP using a modulo-109 operation. This ensures that for installations of 109 universes or fewer, each universe is assigned a unique Multicast IP, resulting in zero Discard Load.

The last digit (Index) of the IPv4 multicast address is calculated as follows:

> Index = ((Universe - 1) % 109) + 1

Example mapping:

- Universe 1, 110, 219\... map to \<mult_u1\> (239.254.0.1)

- Universe 109, 218, 327\... map to \<mult_u109\> (239.254.0.109)

Because multiple universes share a single multicast address once the 109-address pool is exceeded, the CoAP URI-Path (e.g. /sig-net/v1/\<scope\>/level/110) serves as the definitive hardware-layer routing filter. Devices shall parse the URI and silently discard packets addressed to universes to which they are not assigned.

![[]{#_Toc240901074 .anchor}Figure 4 Multicast Folding and URI Filtering](media/image5.png){width="4.420437445319335in" height="4.791666666666667in"}

Informative Note. The 109 multicast groups are just defined for default operation. Sig-Net may be configured to operate with any number of multicast groups. However, system operators should ensure that they do not allocate more multicast groups than can be processed by the least capable switch in the network.

### Multicast Folding™ Configuration and Overrides

While the 109-address pool is the mandatory default to guarantee out-of-the-box interoperability, this mapping scheme is configurable via Sig-Net management commands. This provides an option to balance and optimise grouping for complex systems.

A Manager may assign a custom Multicast IP to any specific Data Endpoint using the TID_EP_MULT_OVERRIDE command. When a custom IP is applied, it shall be treated as a non-volatile setting. Support for custom multicast overrides is optional; Nodes that do not support this feature shall silently discard the TID_EP_MULT_OVERRIDE command.

Senders can detect if a Node is using custom routing by inspecting the TID_RT_MULT TLV, which is returned in the Node\'s basic poll reply.

If a Manager updates an endpoint\'s TID_EP_UNIVERSE, the Node shall revert to the default folded multicast address, unless a valid TID_EP_MULT_OVERRIDE TLV is included in the same CoAP packet.

Informative Note: The ability to remap multicast addressing with TID_EP_MULT_OVERRIDE is an advanced feature that is intended to be applied algorithmically rather than from a user configuration menu.

Split Routing Edge Case: TID_EP_MULT_OVERRIDE shall not be used to configure a network such that the same Universe number is expected on multiple different Multicast IP addresses simultaneously. If a Universe is moved to a custom IP address via TID_EP_MULT_OVERRIDE, all Nodes consuming that Universe on the network must be patched to that same custom IP. Senders are only required to transmit a Universe to a single Multicast IP address; split-routing a single universe across multiple IPs is undefined behaviour.

### Multicast Interoperability and Safety Reset

To ensure reliable interoperability in environments where control consoles or Managers are frequently interchanged (e.g. touring or festival environments), a Manager may force the network to abandon any previously configured custom routing plans.

A Manager may transmit a TID_RT_MULT_OVERRIDE command with a value of 0x00 (Default) to target Nodes. This command forces the Node to discard any previous TID_EP_MULT_OVERRIDE settings and return to the standard predictable folding pool. To reset an entire network, the Manager shall transmit this command individually to the TUID of every discovered Node (via Unicast or \<mult_manager_send\>), authenticated with each Node\'s respective Km_local key.

Operational Safety: Because this command immediately alters the network architecture and triggers non-volatile memory writes across all Nodes, Managers shall not transmit this command automatically during their initialisation sequence. This safety reset must only be executed as a deliberate, user-initiated action.

### Sync and Timecode Address

Both synchronisation commands and timecode streams share a single, fixed administrative multicast address (\<mult_time\>).

## Port Assignment

All Sig-Net traffic shall be transmitted to the registered CoAP UDP port \<coap_port\>.

## CoAP Message Type and Method

All Sig-Net packets shall be transmitted as CoAP NON POST messages.

Informative Note: Because Sig-Net uses CoAP NON exclusively, configuration command packets may be silently lost in transit. The CHANGE_COUNT mechanism (Section[10.2.3](#device-response-logic)) provides eventual consistency but does not guarantee immediate delivery.

For critical configuration changes, Managers shall verify the Node\'s replied state by monitoring the CHANGE_COUNT in subsequent TID_POLL_REPLY packets. If the CHANGE_COUNT does not reflect the expected change within \<node_lost_timeout\> consecutive poll cycles, the Manager shall retransmit the configuration command. Each retransmission shall use a new incremented Sig-Net-Seq-Num and freshly calculated HMAC as required by Section [8.5](#hmac-calculations). Managers shall not retransmit more than five times for a single configuration command without presenting an error condition to the operator. Managers should implement an exponential or fixed inter-retransmission delay of at minimum one poll cycle (\<poll_time\>) between retransmission attempts to avoid unnecessary network load

## Network Infrastructure Requirements

Network switches shall support IGMPv2 as a minimum. IGMPv3 is recommended for large installations.

An IGMP querier shall be active on any network or VLAN where IGMP snooping is enabled.

Informative Note: Direct Device-to-Device connections, or networks utilising unmanaged switches without IGMP snooping, do not require an IGMP querier.

When a Data Endpoint\'s universe assignment or custom routing is altered, the Node shall dynamically manage its active network subscriptions. If a configuration change results in the Node no longer requiring an active subscription to a specific Multicast IP address across any of its Endpoints, the Node shall immediately transmit an IGMPv2 Leave Group message for that discarded IP address. Conversely, if a configuration change introduces a requirement for a new Multicast IP address, the Node shall join the new group before transmitting or receiving data on that Endpoint.

## Multicast TTL

All Sig-Net multicast packets shall be transmitted with a default IP Time To Live (TTL) value of \<mult_ttl\>. This value is selected to provide sufficient headroom for routed single-site venue deployments while preventing Sig-Net traffic from propagating beyond the intended network boundary.

Informative Note: In air-gapped deployments, network administrators should additionally configure multicast boundary filters at any edge router to prevent Sig-Net traffic from leaking onto external networks regardless of TTL value. A TTL of \<mult_ttl\> is a defence-in-depth measure, not a substitute for boundary filtering.

# Payload Syntax 

## Introduction

Sig-Net application payloads are structured using Type-Length-Value (TLV) encoding to maximise network efficiency. This allows multiple related data structures to be packed sequentially into a single CoAP payload and allows for variable-length arrays (such as sparse universe updates) to conserve bandwidth.

The basic structure of a Sig-Net TLV is:

- Type Identifier (TID) (2 Bytes): An identifier defining the nature of the data (Section [11.9](#tid-polling-cross-reference)).

- Length (2 Bytes): A 16-bit integer (Network Byte Order) defining the exact size of the Value field in bytes.

- Value (Variable): The actual data payload.

A single Sig-Net CoAP packet may contain one or more TLVs appended sequentially.

Forward Compatibility Rule: If a Device receives a TLV containing a Type Identifier (TID) that it does not recognise or support, it shall use the Length field to silently skip over the Value payload and continue parsing the next TLV in the sequence. Unknown TIDs shall not cause the packet to be rejected.

### TID Allocation and Namespaces

The 16-bit Type Identifier (TID) is divided into two namespaces:

- Standard TIDs (0x0000 to 0x7FFF and 0xff01 to 0xffff): Reserved for identifiers defined within this specification and its official future extensions.

- Manufacturer TIDs (0x8000 to 0xFF00): Reserved for manufacturer-proprietary data.

### Proprietary TID Resolution

Multiple manufacturers may use the same TID in the 0x8000+ range. A Manufacturer TID shall only be interpreted in the context of the Sig-Net-Mfg-Code (Option 2140) provided in the CoAP header.

1.  A Node receiving a TID in the proprietary range (\>= 0x8000) shall first inspect the Sig-Net-Mfg-Code option.

2.  If the Mfg-Code does not match the Node\'s own ESTA Manufacturer ID, the Node shall silently discard the TLV and use the Length field to skip to the next item in the payload.

3.  If the Mfg-Code matches, the Node may process the TID according to the manufacturer's internal specification.

### TLV Validation

For any TID supported by the Device, the TLV Length must strictly match its defined fixed length or fall within its specified variable-length range.

If any TLV within a packet is structurally malformed, truncated, or carries an invalid length that compromises the packet\'s parser boundaries, the Device shall silently discard the entire packet immediately, make no state changes, write nothing to non-volatile memory, and generate no reply. This structural parser validation applies universally to all incoming packets.

If a TLV is structurally valid but the TID is logically unsupported or inapplicable on the targeted endpoint, the behaviour depends on the transaction type:

- For Parameter Queries (GET, Length = 0x0000): The Device shall silently ignore the TLV and continue parsing subsequent TLVs (Section 10.4.3).

- For Parameter Updates or Commands (SET, Length \> 0): The transaction is invalid. To preserve configuration atomicity, the Device shall reject the entire transaction, discard the packet immediately, apply no state changes, write nothing to non-volatile memory, and generate no reply (Section 10.4.2).

## Device Discovery and Polling

Sig-Net uses a polling mechanism to handle Device discovery and network-level configuration without requiring a central broker.

### Offboarded Operation (Beacon Mode)

An offboarded Sig-Net Device is one that has not yet been physically supplied with a Root Key (K0) and therefore lacks the derived cryptographic keys (Km_local, Kc, Ks) required to generate or verify an HMAC.

An offboarded Device cannot participate in authenticated network communication. It shall silently discard all incoming Sig-Net packets.

To ensure unauthenticated traffic does not congest the primary discovery network, offboarded devices in Beacon Mode shall periodically announce their presence exclusively to the \<mult_node_beacon\> multicast group using the URI /sig-net/\<version\>/local/node_beacon/{tuid}/0.

Beacons shall always be transmitted on the local scope, ensuring they remain discoverable to newly connected Managers regardless of the Manager\'s operational scope configuration.

This presence beacon shall be transmitted periodically at the \<beacon_min_interval\> rate. To facilitate identification by a Manager, the CoAP Options and payload for a beacon shall be populated with the following static values:

CoAP Security Options:

- Sig-Net-Security-Mode (2076): 0xFF (Offboarded).

- Sig-Net-Sender-ID (2108): The TUID of the offboarded Device, with the Endpoint bytes set to 0x0000.

- Sig-Net-Mfg-Code (2140): 0.

- Sig-Net-Session-ID (2172): 0.

- Sig-Net-Seq-Num (2204): 0.

- Sig-Net-Auth (2236): Omitted (not present in the packet).

- Application Payload shall consist of (in this order)

  - TID_POLL_REPLY (with CHANGE_COUNT set to 0x0000)

  - TID_RT_DEVICE_LABEL

  - TID_RT_ROLE_CAPABILITY

  - TID_RT_ENDPOINT_COUNT

  - TID_RT_OTW_CAPABILITY (If the Device supports OTW onboarding)

To minimise the discovery-layer attack surface and prevent offboarded devices from congesting the network, devices operating in Beacon Mode shall adhere to the following:

- Transmission Rate: A Device shall not transmit beacons more frequently than once every \<beacon_min_interval\> seconds.

- Internal Failure Handling: If a firmware or hardware error causes a Device to lose its timing baseline, it should cease beacon transmissions until the next physical power cycle rather than risk flooding the discovery network.

- Logging: Managers should provide a mechanism for local or network-based logging of beacon activity if supported by the hardware.

- Multicast Isolation: All unauthenticated Security-Mode 0xFF beacons shall be transmitted exclusively to the \<mult_node_beacon\> address.

When displaying offboarded Device beacons to an operator, A Manager shall implement the following safeguards:

- Source Display: Display the source IP address of each beacon alongside the reported TUID and Device Label.

- Anomaly Detection: If multiple beacons are received claiming the same TUID from different source IP addresses within a \<beacon_timeout\> window, the Manager shall flag this entry as a potential spoofing anomaly and alert the operator.

- Stale Entry Removal: Automatically remove beacon entries that have not been refreshed within \<beacon_timeout\> seconds.

- Onboarded Device Exclusion: The Manager should not display beacon entries for TUIDs that are already present in the authenticated Device table.

On-Demand Beaconing: An onboarded Manager may temporarily initiate on-demand beaconing, during which the Manager shall multicast three consecutive unauthenticated discovery beacons spaced \<on_demand_beacon_interval\> milliseconds apart to the \<mult_node_beacon\> address.

Informative Note: The isolation of beacons to a dedicated multicast address is the primary defence against unauthenticated Denial of Service. This allows network administrators to configure switches to heavily rate-limit or entirely drop traffic destined for \<mult_node_beacon\> during live show operation, ensuring that discovery-layer traffic cannot impact show-critical authenticated control data.

### Manager Operation

A Manager initiates discovery by sending a Sig-Net packet with a payload containing a TID_POLL TLV to the URI /sig-net/\<version\>/\<scope\>/poll at an interval \<poll_time\>. This packet shall be authenticated using Km_global. During this routine background discovery process, the Manager shall multicast a single global poll (TUID_LO=0, TUID_HI=MAX) with the QUERY_LEVEL set to QUERY_HEARTBEAT (0x00).

Managers shall implement poll snooping to prevent multicast storms in multi-Manager environments and to establish a stable \"Discovery Master.\" A Manager shall monitor the \<mult_manager_poll\> multicast group for TID_POLL requests originating from other Managers.

To prevent a single dropped UDP packet from causing rapid switching of the Discovery Master role, Managers shall use a multi-cycle expiration rule:

- Initial Startup: Upon booting or connecting to a network, a Manager shall silently monitor \<mult_manager_poll\> for a minimum duration of 3 \* (\<poll_time\> + \<manager_poll_jitter\>). If a valid TID_POLL from another Manager is received during this window, the new Manager shall suspend its own routine polling cycle.

- Active Operation: If a Manager is currently suspended (acting as a passive listener), it shall restart its own routine \<poll_time\> transmission cycle only if it fails to receive a valid TID_POLL from the active Discovery Master for three consecutive expected \<poll_time\> intervals.

- Collision Avoidance: To prevent simultaneous transmissions if multiple suspended Managers detect a timeout concurrently, a Manager preparing to transmit shall calculate a randomised delay window by adding a jitter value, uniformly distributed between 0 and \<manager_poll_jitter\> milliseconds, to its transmission timer. If a valid TID_POLL is received from another Manager during this jitter window, the Manager shall immediately cancel its pending transmission, reset its 3-cycle timeout counter and remain suspended.

Requests for configuration or diagnostic state (QUERY_LEVEL\>0) must be controlled to prevent severe burst-traffic packet loss on the management subnet. A Manager shall not transmit global QUERY_LEVEL\>QUERY_HEARTBEAT polls as part of its continuous, routine background discovery process. During routine operation, a Manager shall only transmit a targeted QUERY_LEVEL\>0 poll (matching TUID_LO and TUID_HI to a specific Device) in response to detecting a CHANGE_COUNT increment from that Node.

Initialisation Exception: A Manager is permitted to transmit a network-wide global QUERY_LEVEL=QUERY_FULL (TUID_LO=0, TUID_HI=MAX) exclusively upon its initial boot sequence, connection to a new network, or operator-initiated manual \'Full Refresh\' command, in order to populate its initial internal state tables.

Open Mode Discovery: To discover devices operating in Open Mode (Section [7.2.4](#open-mode-unauthenticated-operation)), a Manager may optionally interleave unauthenticated discovery requests by multicasting a TID_POLL with the Sig-Net-Security-Mode set to 0x01.

### Device Response Logic

Upon receipt of a TID_POLL, a Sig-Net Device (regardless of role) shall check that its TUID is in range. If in range, the Device evaluates the QUERY_LEVEL byte (Value \[24\]):

Query Enumerations:

- 0x00 (QUERY_HEARTBEAT): The Device returns the TID_POLL_REPLY and all TIDs marked as HEARTBEAT in Section [11.9](#tid-polling-cross-reference). This is used for discovery and presence detection.

- 0x01 (QUERY_CONFIG): The Device returns the Heartbeat set plus those marked as CONFIG (e.g. Labels, Universes, Directions).

- 0x02 (QUERY_FULL): The Device returns the Config set plus those marked as FULL (e.g. Firmware, IP Settings, MAC, Supported TIDs).

- 0x03 (QUERY_EXTENDED): The Device returns the Full set plus those marked as EXTENDED (e.g. Security Events, Diagnostic Messages).

The Device shall generate a reply for the requested endpoint(s). Every reply packet payload shall begin with a TID_POLL_REPLY. This shall be followed by the supported TIDs relevant to the requested endpoint(s) whose Poll Category (Section [11.9](#tid-polling-cross-reference)) is less than or equal to the requested QUERY_LEVEL.

If the resulting collection of TLVs exceeds the 1,400-byte UDP payload limit, the Device shall split the data into multiple sequential packets as defined in Section [10.2.4](#fragmentation).

Before transmitting any reply, a Device shall evaluate the poll scope.

- If TUID_HI == TUID_LO (indicating a poll targeted at this specific Device only), the Device should reply within \<node_processing_max\> milliseconds. This is a performance target for the application; the Manager uses this value as its timeout threshold before initiating a retransmission.

- If TUID_HI != TUID_LO (indicating a range or broadcast poll), the Device shall delay for a random period uniformly distributed between 0 and \<poll_backoff_max\> milliseconds. The Device shall then transmit its reply within \<node_processing_max\> milliseconds of the conclusion of this random delay.

- All-Endpoints: If the TID_POLL requests data for All Endpoints (END_POINT = 0xFFFF), a Device with multiple Data Endpoints shall not transmit all of its endpoint replies as a simultaneous, back-to-back burst. The Device shall introduce a minimum pacing delay of \<endpoint_spacing_delay\> milliseconds between transmitting the UDP packet for Endpoint 1, the UDP packet for Endpoint 2 and so forth. This prevents high-density Device from overflowing the receive buffers of the Manager.

Reply Supersession:

If a Node receives a new command while it is transmitting a reply, the Node shall:

- Immediately abort the transmission of the previous reply sequence.

- Permanently discard any unsent packets from that previous sequence.

- Process the new command and initiate its corresponding reply sequence immediately.

The initiating Manager\'s standard timeout and retry logic will handle any data recovery if the aborted reply sequence contained packets the Manager still required.

Informative Note on Backoff Duration: In range and broadcast polls, the random delay serves to prevent simultaneous reply storms from large numbers of Device. The value of \<poll_backoff_max\> defines the upper bound of this delay window and is specified in Section [16](#appendix-b-definitions). The actual delay should be uniformly distributed between 0 and \<poll_backoff_max\>.

### Fragmentation

A Device shall ensure that no single CoAP message (the UDP payload, spanning from the CoAP Base Header to the end of the application payload) exceeds 1,400 bytes. To ensure the complete IP datagram safely fits within a standard 1,500-byte Ethernet MTU without IP-layer fragmentation (even when operating over IPv6 or VLANs), the total application payload following the 0xFF marker (including all TLV headers) shall not exceed 1,200 bytes.

If the total collection of TLVs required to satisfy a QUERY_FULL poll exceeds this limit, the Device shall sequentially transmit multiple independent CoAP packets to the same Reply URI. Each packet shall be a mathematically valid Sig-Net payload in its own right, allowing the Manager to process them as independent state updates regardless of UDP delivery order.

### On-Boot Notification

Every Sig-Net Device (Manager, Sender, Visualiser and Node) shall proactively announce its presence upon completing its boot sequence and establishing a network connection.

After a random delay (uniformly distributed between 0 and \<poll_backoff_max\> milliseconds), the Device shall transmit a single CoAP packet to the Reply URI (/sig-net/\<version\>/\<scope\>/node/{tuid}/0) signed with the Citizen Key (Kc).

To ensure traceability for regulatory compliance and automated conformance testing (SNACtest), the application payload shall comprise the following TLVs appended in exact order:

- TID_POLL_REPLY

- TID_RT_PROTOCOL_VERSION

- TID_RT_ROLE_CAPABILITY

- TID_RT_ENDPOINT_COUNT

- TID_RT_MULT_OVERRIDE

- TID_RT_OTW_CAPABILITY (If OTW onboarding supported).

The transmission of this packet shall be completed within \<node_processing_max\> milliseconds of the conclusion of the random delay.

### Device Loss Detection (Lost Mode)

A Manager shall consider a Device lost if no TID_POLL_REPLY has been received from that Device within \<node_lost_timeout\> consecutive poll cycles.

Nodes are Manager-agnostic and do not track individual Manager identities for discovery purposes. If an onboarded Node has not received a valid TID_POLL request from any Manager within \<node_lost_timeout\> consecutive expected poll intervals, the Node shall assume the entire management network has gone offline and shall enter Lost Mode. In Lost Mode, the Node shall:

- Continue to process and output data from active Senders normally (Stream Loss is evaluated independently as defined in Section [10.6.4](#stream-loss-timeout)).

- Transmit a periodic packet to the URI /sig-net/\<version\>/\<scope\>/node_lost/{tuid}/0 at the standard poll interval, signed with its global Citizen Key (Kc), to signal its continued presence to any Manager that comes online.

The payload of this periodic node_lost transmission shall comprise the following TLVs appended in exact order:

- TID_POLL_REPLY

- TID_RT_PROTOCOL_VERSION

- TID_RT_ROLE_CAPABILITY

- TID_RT_ENDPOINT_COUNT

- TID_RT_MULT_OVERRIDE

- TID_RT_OTW_CAPABILITY (If OTW onboarding supported).

This allows any newly connected Manager to identify the orphaned Node and its routing state.

Informative Note for Managers: If an active Manager receives a packet on the /node_lost/ URI from a Node it is already tracking as \"Online,\" the Manager should assume its own outbound TID_POLL multicasts are failing to reach that specific Node, indicating a one-way network routing failure.

## Targeted Device Routing

To send data directly to a specific Device or read its state (such as Configuration changes or \[RDM\] transactions), Sig-Net uses a targeted routing model. Data is routed using the target Devices\'s TUID and Endpoint.

### Targeted URIs

Three specific URIs are defined to separate discovery, commands and replies. TIDs are strictly bound to these URIs as defined in Section [15](#appendix-a-multicast-addresses); receivers shall ignore any TID received on an incorrect URI:

- Discovery URI (/sig-net/\<version\>/\<scope\>/poll): Used exclusively by Managers to multicast discovery requests (TID_POLL) to all Devices on the network. Packets sent to this URI shall be sent via Multicast UDP to \<mult_manager_poll\> and shall be authenticated using the Global Manager Key (Km_global).

- Command URI (/sig-net/\<version\>/\<scope\>/manager/{tuid}/{endpoint}): Used by Managers to send Native Configuration changes (TIDs) or \[RDM\] commands to a specific Device. Packets addressed to this URI may be sent via Unicast UDP or Multicast UDP (\<mult_manager_send\>) and shall be authenticated using the target Node\'s unique Km_local key.

- Reply URI (/sig-net/\<version\>/\<scope\>/node/{tuid}/{endpoint}): Used by Devices to multicast their current configuration state or \[RDM\] Push Notifications. Packets sent to this URI shall be signed using the global Citizen Key (Kc).

Informative Note on URI Naming: The URI path segment /node/ is used to represent the Responder/Citizen plane. All Sig-Net Devices, regardless of whether they implement the Node, Sender, Visualiser, or Manager role, use the /node/{tuid}/0 reply URI to report discovery replies, on-boot notifications, and root diagnostic status.

### Unicast vs. Multicast Command Routing:

To minimise unnecessary network traffic on Nodes, Managers should default to transmitting all Parameter Updates (SET), Parameter Queries (GET) and TID_RDM_COMMAND via Unicast.

However, to allow management in environments where a newly connected Node resides on an unreachable or misconfigured IP subnet, Managers may transmit targeted commands via Multicast UDP to the \<mult_manager_send\> group.

- Security and Processing: Regardless of whether the command is Unicast or Multicast, the packet shall target a specific {tuid} in the URI and shall be authenticated using that Node\'s unique Km_local key. Nodes receiving traffic on \<mult_manager_send\> shall parse the cleartext URI and silently discard any packets that do not match their own TUID, as required by Section [8.6](#packet-processing-and-replay-attack-prevention) (Step 6). This guarantees that multicast configuration routing cannot be used to execute network-wide configuration changes or elevate privileges.

### Auxiliary URI

The Auxiliary URI provides a secure transport path for operational triggers such as OSC macros using TID_OSC. This is a Targeted URI addressed to a specific Device identity.

- Syntax: The URI shall follow the format: /sig-net/\<version\>/\<scope\>/aux/{tuid}/{endpoint}.

<!-- -->

- Authentication: Packets addressed to this URI shall be authenticated using the global Sender Key (Ks). This allows remote control surfaces to trigger fixture functions without requiring access to the higher-privilege Management Plane (Km_local).

- Targeting: Senders shall resolve the target {tuid} by monitoring the TID_POLL_REPLY traffic on the network. If a Sender does not possess the TUID of a target Device, it cannot initiate an auxiliary transaction.

- Security Boundary: Implementers shall ensure that the Auxiliary Lane is strictly limited to operational triggers. Management, security and network configuration functions shall not be exposed via this URI.

## Node Configuration and State Synchronisation

Sig-Net uses a Directional Data Flow model to manage Device configuration. The nature of a transaction (whether it is an update, a query, or a report) is determined by the Destination URI and the TLV Length field, rather than explicit command bytes within the payload.

### Directional URI Mapping

The Destination URI defines the role and intent of every configuration packet:

- Command URI (/sig-net/\<version\>/\<scope\>/manager/{tuid}/{endpoint}): Used by a Manager to send instructions to a Node. The Node interprets packets on this URI as either a Parameter Update or a Parameter Query.

- Reply URI (/sig-net/\<version\>/\<scope\>/node/{tuid}/{endpoint}): Used by a Node to multicast its current state. The Node sends packets to this URI in response to a Parameter Query, as a confirmation of an update, or as a Proactive Change Notification.

### Parameter Updates (SET)

To change a configuration parameter, a Manager transmits the corresponding TID with a Length \> 0 directly to the Node\'s Command URI.

1.  Batching: A Manager may pack multiple Parameter Updates (SET) into a single CoAP packet to improve network efficiency, provided the total payload does not exceed the 1,400-byte UDP limit defined in Section [10.2.4](#fragmentation).

2.  HMAC Verification: The Node shall verify the inbound HMAC and parse the TLVs as defined in Section [8.6](#packet-processing-and-replay-attack-prevention).

Upon successful HMAC verification, the Node shall parse each TID in the packet and evaluate the proposed values. The Node shall initialise an internal counter, nv_count, to 0, and evaluate each proposed parameter according to one of three paths:

1.  Invalid SET (Malformed, Bad HMAC, or Out-of-Bounds Payload)

> If an incoming packet fails HMAC verification, is structurally malformed, or if any single contained TID contains a parameter value that is out-of-bounds, unsupported, or invalid, the Node shall:

- Reject the entire transaction.

- Take no operational action (reverting any RAM states temporarily modified during the processing of this packet) and bypass writing to NVM.

- Leave its global CHANGE_COUNT unchanged.

- Silently discard the packet and generate no multicast reply. This silent-discard rule is a mandatory security boundary designed to prevent multicast traffic amplification Denial-of-Service (DoS) attacks on the network scope.

2.  Valid SET and State Change:

- Apply the new value to its active operational state in RAM.

- Add the parameter TLV to the response packet.

- If the Parameter is flagged as 'Persistent: Yes' in Section [11](#tid-definitions), Increment nv_count by 1.

3.  Valid SET with no State Change:

- Add the parameter TLV to the response packet.

At the conclusion of processing the entire transaction packet and having encountered no invalid TLVs, the Node shall execute the following steps:

If nv_count \> 0:

- Increment the active CHANGE_COUNT in RAM by 1.

- Append a trailing TID_SET_REPLY (carrying the newly incremented CHANGE_COUNT) to the response packet.

- Within \<node_processing_max\> milliseconds, transmit the response packet to its Reply URI.

- Asynchronously commit the updated parameter values and the new CHANGE_COUNT to non-volatile memory.

If nv_count == 0:

- Append a trailing TID_SET_REPLY (carrying the unchanged CHANGE_COUNT) to the response packet.

- Within \<node_processing_max\> milliseconds, transmit the response packet to its Reply URI.

![[]{#_Toc240901075 .anchor}Figure 5 Summary of SET Processing](media/image6.png){width="6.734747375328084in" height="4.385416666666667in"}

### Parameter Queries (GET)

To retrieve the current value of one or more parameters, a Manager transmits the corresponding TID with a Length = 0x0000 to the Node's Command URI.

- Batching: A Manager may pack multiple Query TIDs into a single CoAP packet.

- Queryable TIDs: Any TID marked as \"Queryable: Yes\" in Section [11](#tid-definitions) shall be interpreted as a request for the Node\'s current state.

- Response Packing: To minimise network overhead, the Node should pack all requested responses into as few CoAP packets as possible, subject to the 1,400-byte UDP limit defined in Section [10.2.4](#fragmentation).

- Error Handling: If a requested TID is not supported or not Queryable on that endpoint, the Node shall silently ignore the request and continue parsing any subsequent TLVs in the packet.

A TLV Length of 0x0000 shall be used exclusively to indicate a Parameter Query (GET) request. Nodes transmitting state reports or Get-Responses shall never use a Length of 0x0000.

Informative Note on Guest Manager Query Mechanics: Because the Command URI /manager/{tuid}/{endpoint} requires the Node-Specific Manager Key (Km_local) for authentication, a Device operating in the Guest Manager state (which only possesses Km_global) is blocked from issuing targeted Parameter Queries (GETs). To retrieve specific parameter values or \[RDM\] Tables of Devices, a Guest Manager instead uses the TID_POLL mechanism (Section [10.2.2](#manager-operation)). The Guest Manager sends a targeted TID_POLL (matching TUID_LO and TUID_HI to the specific fixture) to the Discovery URI, authenticated with Km_global and requests the appropriate QUERY_LEVEL. The Node will return the requested data blocks to the \<mult_node_send\> reply group. This allows Read-Only network discovery without requiring Km_local.

### Consistency Tracking

Both TID_POLL_REPLY and TID_SET_REPLY include a 16-bit wrap-around CHANGE_COUNT variable that is designed to guarantee eventual consistency across multiple Managers without requiring reliable transport. The CHANGE_COUNT is processed as a transaction version stamp representing the active configuration state of the Node. A single network packet containing multiple SET commands is treated as one atomic transaction and shall increment the global CHANGE_COUNT by 1 at the end of processing if at least one persistent configuration change occurred. If no persistent changes occurred, the CHANGE_COUNT is not incremented, though a proactive confirmation is still generated and transmitted.

The CHANGE_COUNT shall increment by 1 whenever any native parameter flagged as Persistent = True in Section [11](#tid-definitions) undergoes a valid state change, whether triggered by a network command, a local user interface interaction, or as a side-effect of an encapsulated RDM transaction.

The CHANGE_COUNT shall not increment when parameters flagged as Persistent = False in Section [11](#tid-definitions) change state (which includes volatile statuses, diagnostic events, and transient operational triggers like identify or reboot commands), nor shall it increment when encapsulated \[RDM\] parameter states change (these are handled independently via Section [10.5.2](#proactive-state-notification)).

Proactive Notification:

When a Device\'s configuration or internal status changes, it shall immediately transmit a proactive state update to the URI /sig-net/\<version\>/\<scope\>/node/{tuid}/{endpoint}, where {endpoint} represents the specific port that was altered (or 0 for a global change).

The payload of this proactive notification shall consist of the specific configuration parameter TLV(s) that were altered on that endpoint, followed immediately by a trailing TID_SET_REPLY as the final TLV in the packet payload. (Note: If the proactive transmission was triggered by a Status TID change or a change where Persistent = False, the CHANGE_COUNT reported in the TID_SET_REPLY will be identical to the previously reported value, as Status changes do not increment the counter).

Rate Limit:

Rate Limit & Deferral: To prevent high-frequency status changes (e.g. \[DMX512\] data activity bits flipping) from generating continuous multicast storms, Devices shall rate-limit proactive state notifications for Status TIDs (such as TID_RT_STATUS and TID_EP_STATUS). A Node shall not proactively multicast status updates for the same endpoint more frequently than once every \<status_publish_rate\> seconds.

To prevent data loss during high-frequency bursts, Nodes shall implement a defer-and-coalesce scheduling strategy:

- If a status change occurs while the \<status_publish_rate\> window is closed (i.e. less than \<status_publish_rate\> seconds have elapsed since the last transmission on that endpoint), the Node shall defer the notification and set an internal \"dirty\" flag for that status block. No packets shall be queued in a FIFO buffer.

- Once the \<status_publish_rate\> timer expires and the window opens, the Node shall inspect the \"dirty\" flag.

- If the flag is set, the Node shall re-fetch the current, freshest state of the parameters, transmit a single consolidated proactive notification containing these current values, and clear the \"dirty\" flag.

Consistency Tracking:

A Manager shall actively track the CHANGE_COUNT of every discovered Device. If a Manager receives a routine TID_POLL_REPLY (QUERY_LEVEL=QUERY_HEARTBEAT) during background discovery, or a proactive TID_SET_REPLY, and detects that the CHANGE_COUNT is greater than its internally cached value for that Node, the Manager knows it missed a proactive configuration update.

Upon detecting a CHANGE_COUNT discrepancy, the Manager shall immediately transmit a targeted TID_POLL (matching TUID_LO and TUID_HI to the specific Device) with QUERY_LEVEL\>QUERY_HEARTBEAT to fetch the updated configuration state.

IP Address Resolution:

Because a CHANGE_COUNT increment may indicate that the Node\'s physical IP address was altered by another Manager, the polling Manager shall update its internal routing table using the Source IP address of the received UDP TID_POLL_REPLY or TID_SET_REPLY packet before transmitting the targeted Unicast TID_POLL. This ensures the follow-up query is correctly routed to the Device\'s current network location.

### Implementing Eventual Consistency (Informative)

This section describes a simple method of Manager side parsing designed to achieve eventual consistency. The process involves parsing two TIDs as follows:

- On receiving a TID_SET_REPLY (Write Confirmations): The Manager expects the received counter to either match its cache (a No-Op) or be exactly +1 (a sequential change). If the counter matches neither condition, data has been lost. The manager can remedy this by triggering a targeted poll.

- On receiving a TID_POLL_REPLY (Queries / Heartbeats): The Manager expects the CHANGE_COUNT to match its local copy. Again, any mismatch triggers a targeted pull.

![[]{#_Toc240901076 .anchor}Figure 6 Manager Eventual Consistency](media/image7.png){width="4.96875in" height="6.423826552930883in"}

### Batch State Retrieval (QUERY_LEVEL)

To retrieve a Node\'s configuration in bulk (e.g. during discovery), a Manager uses the TID_POLL mechanism (Section [10.2](#device-discovery-and-polling)). The QUERY_LEVEL byte within the TID_POLL determines the density of information returned by the Node, as defined by the Poll Categories in Section [11.9](#tid-polling-cross-reference).

### Network Interface Configuration (IP Settings)

A Manager may configure a Node\'s IP address settings by transmitting Network Configuration TIDs (Section [11.5](#network-configuration-type-identifiers)) to the Node\'s Root Endpoint.

In order to reduce the risk of accidental configuration change severing communication, atomic execution and rollback rules apply:

Atomicity: A Manager shall pack all required IPv4 or IPv6 parameters for the intended change into a single CoAP POST payload. The Node shall evaluate all network configuration TIDs within the packet simultaneously.

Because applying new IP settings inherently disrupts active network connectivity, the Node shall successfully transmit the confirmation response (containing the updated Parameter TIDs, as required by Section [10.4.2](#parameter-updates-set)) using its existing, working IP configuration prior to applying the new settings to the hardware network stack. This guarantees the Manager receives cryptographic confirmation that the command was accepted before the Node temporarily drops offline to execute the change.

Rollback Verification: Upon successfully applying a new IP network configuration, the Node shall start a rollback timer of \<ip_rollback_timer\> seconds. To prove that the newly assigned IP address is fully routable and valid on the network, the configuring Manager shall immediately transmit a targeted, Unicast TID_POLL (matching TUID_LO and TUID_HI to the specific Node) directly to the Node\'s new IP address.

![[]{#_Toc240901077 .anchor}Figure 7 IP Change and Rollback Verification](media/image8.png){width="5.124291338582677in" height="4.95in"}

If the Node does not successfully receive and cryptographically verify a targeted Unicast TID_POLL directed to its specific TUID within the rollback window, it shall ignore any background Multicast TID_POLL traffic, assume the new network configuration is unreachable and immediately discard the new settings. It shall revert to its previously working IP configuration and multicast its restored state to the network on the standard Reply URI via the \<mult_node_send\> group.

## RDM Payload

Sig-Net encapsulates standard \[E1.20\] \[RDM\] packets inside TLVs. \[RDM\] transactions use the Targeted Node Routing architecture defined in Section [10.3](#targeted-device-routing).

The following Type Identifiers (TID) are defined:

- TID_RDM_COMMAND (Manager Command): Contains the raw E1.20 request packet generated by a Manager.

- TID_RDM_RESPONSE (RDM-Responder Response): Contains the raw E1.20 response packet generated by an RDM-Responder.

The payload shall be a fully formatted \[RDM\] packet starting with the Start_Code and ending with the RDM_Checksum.

### Transaction Responses 

Regardless of whether a TID_RDM_COMMAND was received via Unicast or Multicast, the Node shall multicast its corresponding TID_RDM_RESPONSE reply within \<node_processing_max\> milliseconds of completing the physical \[RDM\] transaction.

### Proactive State Notification

Sig-Net supports multi-Manager synchronisation without requiring a central broker. This is achieved by mandating proactive multicast notifications whenever a Node\'s parameter state changes.

When a Node\'s \[RDM\] parameter state is altered, the Node shall proactively transmit a multicast TID_RDM_RESPONSE containing an \[RDM\] GET_COMMAND_RESPONSE reflecting the new state. This rule applies for any cause of state change including user interface.

The Node shall delay for a random period (between 0 and \<rdm_backoff_max\> before transmitting the proactive response. The response shall then be transmitted within \<node_processing_max\> milliseconds of the conclusion of this delay window.

Node behaviour on receipt of a GET command is defined in Section [10.5.1](#transaction-responses). Where the altered \[RDM\] parameter does not have a corresponding GET command defined in \[RDM\], the Node is not required to transmit a proactive TID_RDM_RESPONSE for that parameter change.

Sig-Net relies on UDP multicast to transport proactive \[RDM\] state notifications. Because UDP is a non-reliable transport, Sig-Net accepts the possibility that a proactive TID_RDM_RESPONSE may occasionally be dropped. Manager applications may wish to implement a low-frequency, background polling loop (issuing targeted TID_RDM_COMMAND GET requests for critical PIDs) to ensure their internal fixture state caches remain accurate over time.

To prevent devices from being overrun with redundant background GET requests in multi-Manager environments, only the Manager that is currently actively transmitting discovery requests (i.e. the Manager that has not suspended its polling cycle under the poll snooping rules defined in Section [10.2.2](#manager-operation)) shall execute this background \[RDM\] polling loop. All other Managers shall passively synchronise their state caches by snooping the resulting multicast TID_RDM_RESPONSE packets.

Informative Note for Gateways: The proactive notification requirement does not mandate that a Gateway cache the entire \[RDM\] parameter state of every downstream physical RDM-Responder in its internal memory. Instead, Gateways should rely on the native \"Queued Message\" mechanism defined in the \[RDM\] standard. When a downstream physical RDM-Responder locally alters a parameter or executes a Broadcast SET command, it queues a message. The Gateway simply retrieves the queued GET_COMMAND_RESPONSE during its routine background \[RDM\] polling, encapsulates the raw \[RDM\] packet within a TID_RDM_RESPONSE and multicasts it to the Sig-Net network.

### RDM Boundary Restrictions (Normative)

Sig-Net Native Configuration TIDs (Section [11](#tid-definitions)) are the absolute authority for the Device\'s physical network interface and routing topology.

To prevent state-machine conflicts and guarantee the enforcement of the Sig-Net IP Rollback Verification mechanism (Section [10.4.7](#network-interface-configuration-ip-settings)), Virtual Endpoints shall reject any encapsulated TID_RDM_COMMAND SET requests that attempt to alter the Device\'s fundamental IP network settings or alternate network routing topologies.

Specifically, Virtual Endpoints shall return an \[RDM\] NR_UNSUPPORTED_COMMAND_CLASS or NR_WRITE_PROTECT response to any SET command targeting PIDs defined within:

- \[E1.33\], \[E1.37-2\] and any possible future replacement for \[E1.37-2\].

Managers requiring to configure the IP address, Subnet Mask, Gateway, or MAC address of a Sig-Net Device shall utilise the authenticated Sig-Net Network Configuration TIDs directed to the Root Endpoint.

Informative Note: Virtual Endpoints may legitimately process read-only \[RDM\] queries (GET) for these network parameters to populate legacy console patching screens, provided the returned values accurately reflect the current Sig-Net native state.

### Node Responsibilities

These rules apply to Nodes irrespective of whether they have physical Data Endpoints that connect to DMX512 links or Virtual Endpoints that terminate \[RDM\] transactions internally in software. For Virtual Endpoints, physical serial bus timings, serial line-pumping, and background wire-polling are omitted, while the Node is required to preserve the logical \[RDM\] transaction state-machine and standard response formatting to ensure consistent behaviour on the IP network. A Node with a physical Data Endpoint or virtual Data Endpoint shall adhere to the following rules:

- Background Queue Polling: The Node shall act as the sole E1.20 master on its downstream RS485 link for the purpose of retrieving queued messages. The Node shall run a continuous, autonomous background polling loop, transmitting GET QUEUED_MESSAGE to all discovered downstream RDM-Responders. When the Node retrieves a queued GET_COMMAND_RESPONSE, it shall encapsulate it within a TID_RDM_RESPONSE and proactively multicast it to the Sig-Net network.

- ACK_OVERFLOW Handling: The Node shall autonomously handle E1.20 ACK_OVERFLOW responses occurring on the downstream RS485 link. The Node shall internally generate the subsequent GET commands required to pump the remaining data. The Node shall not wait for the entire overflow sequence to complete before transmitting to the network; it shall encapsulate and multicast the TID_RDM_RESPONSE blocks as they arrive. The Node may perform short-term buffering to efficiently pack multiple \[RDM\] responses into a single CoAP TLV payload, provided it does not significantly delay transmission. Manager applications on the IP network shall not attempt to manually pump an ACK_OVERFLOW sequence through a Node Endpoint.

> The Available RDM FiFO Buffers count reported via TID_RDM_FLOW_CONTROL shall dynamically reflect the Node\'s actual remaining capacity to accept and queue new RDM transactions for that endpoint. While a Node is actively executing an RDM transaction on a physical port (including performing an autonomous ACK_OVERFLOW pump), the transaction shall consume one slot in that endpoint\'s buffer queue. The Node remains free to advertise its remaining empty queue slots (e.g. reporting 9 out of 10 available) and continue accepting new commands from the network. However, to prevent interleaving collisions on the wire, the Node must temporarily pause the serial transmission and execution of any queued commands for that specific port until the active transaction is fully resolved (i.e. the final ACK is received from the downstream responder or the transaction times out).
>
> During an autonomous ACK_OVERFLOW pumping sequence, the Node shall continue to update and report its network-facing flow control (TID_RDM_FLOW_CONTROL) based on its remaining buffer memory. However, the Node shall gate its FIFO output. The Node must buffer and hold any newly received RDM commands in its queue, pausing their physical transmission on that endpoint until the pumping sequence is completed. This guarantees that no incoming commands are interleaved on the physical wire, and prevents multi-manager interleaving from aborting the downstream RDM-Responder\'s sequence.
>
> Informative Note: \[RDM\] requires that an RDM-Responder abort its ACK_OVERFLOW sequence if another PID is interleaved. Designers should ensure that other network traffic does not accidentally trigger this condition.

- ACK_TIMER Handling: If a downstream RDM-Responder replies with an ACK_TIMER, the Node shall encapsulate and multicast this response to the Sig-Net network. Manager applications shall treat this network ACK_TIMER purely as an informative \"transaction pending\" status; they should use it to extend their internal retry timeouts, but shall not transmit follow-up IP requests to resolve the timer. The Node shall autonomously handle the physical RS485 timer delay and the subsequent data retrieval, multicasting the final data response to the network once the transaction completes on the serial link.

> []{#_Toc240901078 .anchor}Figure 8 RDM Flow Control

![](media/image9.png){width="6.268055555555556in" height="4.509722222222222in"}

### RDM Discovery Commands

Sig-Net Nodes are responsible for autonomously discovering and maintaining the local Table of Devices on their respective endpoints (Section 10.5.4). Devices are prohibited from transmitting RDM Discovery class commands over the network.

A TID_RDM_COMMAND payload shall not encapsulate an E1.20 RDM packet with a Command Class (CC) of DISCOVERY_COMMAND (0x10) or target any of the standard discovery Parameter Identifiers (PIDs): DISC_UNIQUE_BRANCH (0x0001), DISC_MUTE (0x0002), or DISC_UN_MUTE (0x0003).

Nodes receiving a TID_RDM_COMMAND that violates this rule shall reject the TLV based on the rules defined in Section 10.1.3.

## Universe Payload

The {universe} variable in the URI shall be a decimal integer in the range of 1 to 63999.

The following Type Identifiers (TID) are reserved for Universe data sent to the URI: /sig-net/\<version\>/\<scope\>/level/{universe}

- TID_LEVEL (Zero Start Code \[DMX512\]): The Value field contains up to 512 bytes of slot data.

- TID_PRIORITY (Priority Data): The Value field contains 1 to 512 bytes of priority values (0-200).

  - Universe Priority: If the payload length is 1, the single byte value shall be applied uniformly to all 512 slots.

  - Per-Slot Priority: If the length is greater than 1, the bytes map sequentially to the priority slots starting at Slot 1. Any remaining unaddressed priority slots (up to 512) shall be set to 0.

  - Constrained Node Fallback: Nodes that support Data Endpoints should support the full 1 to 512-byte range for TID_PRIORITY. If a Node is memory-constrained and cannot store a 512-byte per-slot priority buffer, it shall use the first byte of any received TID_PRIORITY payload as a global Universe Priority, applying that value to all slots in its merge calculation. It shall then silently discard the remaining bytes. The Node shall accurately declare whether it supports full Per-Slot Priority Merging or is utilizing this Constrained Node Fallback by setting or clearing Bit 5 of the TID_EP_CAPABILITY bit field respectively.

A Sender shall send priority data subject to the rules defined in \[ETC 0xDD\] . A Sender may pack a TID_PRIORITY and a TID_LEVEL into the same packet.

Sig-Net uses the 8-byte Sig-Net-Sender-ID CoAP option to identify sources. When a Node applies the per-slot merge rules defined in \[ETC 0xDD\], it shall use the full 8-byte Sig-Net-Sender-ID to uniquely identify the source of the TID_LEVEL stream. This guarantees that multi-port gateways routing separate physical \[DMX512\] inputs to the same Sig-Net universe are correctly processed as distinct, mergeable sources.

If a Node receives a TID_LEVEL packet on a universe with no accompanying TID_PRIORITY data (either in the same packet or from any prior packet in the current session), it shall treat all slots in that packet as having a priority value of 100, consistent with the default priority defined in \[ETC 0xDD\].

Once TID_PRIORITY data has been received for a universe, the Node shall use the received priority values for merge calculations until priority data is updated or the Sender\'s session expires.

When a Node receives TID_LEVEL data from multiple Senders on the same universe, it shall merge the sources based on the priority mode declared in Bit 5 of TID_EP_CAPABILITY:

- Per-Slot Priority Mode (Bit 5 = 1): The Node shall apply the per-slot merge rules defined in \[ETC 0xDD\], evaluating the individual priority assigned to each slot.

- Universe Priority Fallback (Bit 5 = 0): The Node shall treat the first byte of TID_PRIORITY (or default priority 100) as a global priority applied uniformly across all 512 slots of that source.

In both modes, if multiple Senders provide data for the same slot with an identical effective priority, the Node shall apply a Highest Takes Precedence (HTP) merge between those sources.

A Node supporting Data Endpoints that consume TID_LEVEL shall support merging a minimum of 4 simultaneous sources per patched universe, and shall report its maximum merge capacity via bytes \[4--5\] of TID_EP_CAPABILITY.

When a Sender packs both TID_PRIORITY and TID_LEVEL into a single CoAP payload, TID_PRIORITY shall be placed before TID_LEVEL in the TLV sequence. This allows Nodes to apply the priority context before processing level data, avoiding the need to buffer and reprocess TLVs.

### Example Universe Payload (Informative)

The example below shows a universe payload with a single TID_LEVEL TLV.

[]{#_Toc240901079 .anchor}Figure 9 Wireshark Example

![](media/image10.png){width="5.792474846894138in" height="5.677876202974629in"}

### Routing & Mixed Security Environments

Senders are permitted to transmit TID_LEVEL, TID_PREVIEW and TID_PRIORITY payloads via Unicast UDP directly to the IP address of a specific Node. Nodes shall accept properly authenticated universe payloads regardless of whether they arrive via Unicast or Multicast.

Operating in Unicast is discouraged. Unicast universe delivery prevents passive snooping by other Devices, creates asymmetric behaviour in multi-Sender merge scenarios (other Senders cannot detect that a universe is actively being driven) and eliminates the bandwidth efficiency advantage of multicast for multi-Node deployments sharing a universe.

### Transmission Rates and Keep-Alive

Senders shall adhere to the following transmission rate rules for TID_LEVEL & TID_PRIORITY payloads:

- Maximum Rate: A Sender shall default to transmitting TID_LEVEL & TID_PRIORITY payloads at a maximum rate of 44 frames per second. Senders may be configured by an operator to transmit at higher framerates (e.g. 60Hz or 120Hz for high-speed SPI pixel mapping).

  - Informative Note on Speed Governance: Because pure Senders do not perform Node discovery, they cannot natively query the TID_EP_REFRESH_CAPABILITY of the receiving Nodes. If a Sender transmits a universe faster than a subscribed Node can physically process it, the Node will silently drop the excess frames. Management software should ideally warn operators if a Sender\'s output rate exceeds the capabilities of the slowest Node patched to that universe.

- Dynamic Data: When slot values are actively changing, the Sender shall transmit packets as the changes occur, subject to the maximum rate.

- Transition to Idle: When data stops changing, the Sender shall transmit three identical packets containing the final state at the active frame rate before reducing its transmission speed. (Note: Per Section [8.5](#hmac-calculations), the CoAP Sig-Net-Seq-Num and resulting HMAC will still increment uniquely for each of these three packets).

- Idle Data: While data remains unchanged, the Sender shall transmit a keep-alive packet at a minimum refresh rate of 1 Hz. This keep-alive shall be a standard TID_LEVEL packet containing the full current slot data for the universe. This ensures that Nodes joining the network or recovering from a reboot can synchronise to the current lighting state during idle periods.

Informative note: Sig-Net is intended to be easily integrated with sACN and Art-Net code bases. In the absence of normative instruction, Sig-Net equivalent packets can be sent and received with the same timings and expiration logic as sACN and Art-Net.

### Stream Loss Timeout:

If a Node does not receive a valid TID_LEVEL packet for a patched universe from an active Sender within \<universe_lost_timeout\> consecutive seconds, the Node shall assume the stream is lost. The Node shall then execute its configured data-loss behaviour.

If the endpoint is configured via TID_EP_PROTOCOL to consume level data from an alternative protocol (e.g. Art-Net), the Node shall evaluate Stream Loss based on the expiration logic defined by that specific protocol.

## Sync Payload

Sig-Net implements a global synchronisation mechanism that allows multiple universe to be output in synchronism and so eliminate 'tearing' problems in visual effects.

The sync command uses the TID_SYNC Type Identifier which contains no payload bytes.

### Transmission Rules

A Sender generating synchronised data shall transmit all necessary TID_LEVEL and TID_PRIORITY packets to their respective universe URIs.

The Sender shall introduce a minimum delay of 5 milliseconds after transmitting the final TID_LEVEL packet of the frame to allow receiving Nodes sufficient time to process network buffers. After this delay, the Sender shall transmit a single TID_SYNC packet to the global sync URI (/sig-net/\<version\>/\<scope\>/sync).

This packet shall be authenticated using the Sender Key (Ks).

### Processing Rules and the SYNC_ACTIVE State

A Node shall maintain a SYNC_ACTIVE boolean state flag for each of its data endpoints. Upon boot, the SYNC_ACTIVE flag for all endpoints shall default to False.

When SYNC_ACTIVE is False (Asynchronous Mode):

1.  When a Node receives a valid TID_LEVEL packet, it shall immediately apply the new data to the active output of the corresponding endpoint.

2.  If the Node receives a TID_SYNC packet, it shall extract the 8-byte Sig-Net-Sender-ID from the CoAP header. The Node shall evaluate all active data endpoints. If an endpoint is currently receiving its active TID_LEVEL data from a Sender matching that Sig-Net-Sender-ID (as determined by the priority merge rules in Section [10.6](#universe-payload)), the Node shall transition the SYNC_ACTIVE flag for that specific endpoint to True and reset its internal Sync Timeout timer. Endpoints receiving active data from other Senders shall ignore the TID_SYNC packet.

When SYNC_ACTIVE is True (Synchronised Mode):

1.  When a Node receives a valid TID_LEVEL packet from the active Sender, it shall store the level data in an internal holding buffer for that endpoint. It shall not immediately apply this new data to the active output.

2.  When the Node receives a TID_SYNC packet matching the Sig-Net-Sender-ID of the active Sender currently driving the endpoint, it shall immediately transfer the contents of the holding buffer to the active output, executing the new levels simultaneously. The Node shall then reset its internal Sync Timeout timer for that endpoint.

### Synchronisation Timeout 

When an endpoint is in the SYNC_ACTIVE state, the Node shall continuously monitor the time elapsed since the last valid TID_SYNC packet was received.

If a TID_SYNC packet is not received within \<sync_lost_timeout\> milliseconds of the previous TID_SYNC packet, the Node shall assume the synchronised Sender has gone offline or dropped the stream. The Node shall:

1.  Immediately transition the SYNC_ACTIVE flag for that endpoint back to False.

2.  Automatically flush any data currently held in the holding buffer to the active output.

## Timecode Payload

Sig-Net provides a lightweight payload for transmitting timecode to support show synchronisation. The data structure is based on the MIDI Timecode (MTC) format.

Timecode data shall be transmitted to the following URI:

/sig-net/\<version\>/\<scope\>/timecode/{stream}

The {stream} variable allows multiple independent timecode tracks to coexist on the network and shall be an integer in the range of 1 to 255.

The Type Identifier (TID) TID_TIMECODE shall be used for timecode transmission:

### Transmission Rules

A Sender generating timecode shall transmit a TID_TIMECODE block once per frame to maintain synchronisation across the network. Because timecode is a continuous, high-frequency stream, Devices shall use the Sig-Net-Seq-Num option (Section [8.3](#security-options)) to ignore any out-of-order or delayed packets

Idle/Paused Transmission: If the timecode source is paused or stopped, the Sender shall continue to transmit the frozen, non-advancing timecode value as a keep-alive at a rate of 1 Hz. This prevents receiving devices from prematurely declaring a stream loss.

Duplicate Frame Handling: Implementations consuming TID_TIMECODE shall be robust against receiving identical timecode values in rapid succession (e.g. due to Sender software stutter or idle keep-alive) and shall process them gracefully.

### Timecode Stream Loss

A Device consuming timecode shall consider a stream lost if no TID_TIMECODE packet has been received for the relevant {stream} within \<timecode_lost_timeout\> seconds. Upon stream loss, the consuming Device shall:

- Hold the last received timecode position and cease advancing.

- Resume normal synchronisation immediately upon receipt of the next valid TID_TIMECODE packet for that stream, without requiring a restart or re-synchronisation procedure.

Implementations shall not assume that timecode resumes from the position at which the stream was lost. The frame value in the next received packet shall be treated as the authoritative current position regardless of the elapsed gap.

## Security Event Reporting

This section defines the behaviour of TID_DG_SECURITY_EVENT for diagnostic security monitoring. Sig-Net Nodes shall implement security event tracking using TID_DG_SECURITY_EVENT.

### Event Counters

Nodes shall maintain a 32-bit unsigned integer counter for each security Event Code defined in Section [11.8.1](#tid_dg_security_event). These counters should be stored in volatile memory (RAM) only.

### Offending Address Capture

For each event code, the Node shall capture the IP address of the most recent packet that triggered the event. Nodes are not required to maintain a history or list of offending addresses; capturing the single most recent address is sufficient to minimise memory overhead.

### Transmission and Rate Limiting

A Node shall unilaterally multicast a TID_DG_SECURITY_EVENT to the Reply URI upon detecting a qualifying security event.

Rate Limit: To prevent network flooding during a sustained attack, transmission of this TID shall be rate-limited to a maximum of one packet per second per Event Code.

Accuracy: The \"Event Counter\" in the payload shall reflect the actual total number of events detected, allowing a Manager to observe the full rate of an attack even when the network reports are being suppressed by the rate-limiter.

# TID Definitions 

The following section defines the Type Identifiers and parameters used in all Sig-Net TLVs.

- Length Column: Defines the length of the Value field. The total TLV size on the wire is Length + 4 bytes (2-byte TID + 2-byte Length field).

- Mandated Column: Specifies whether a Node is legally required to support the TID. If a TID is marked \"Mandated: Yes,\" the Node shall accurately report its state when queried. However, if the Node\'s physical hardware does not support altering that specific parameter (e.g. a hardwired \[DMX512\] Output port receiving a TID_EP_DIRECTION SET command), the Node shall silently ignore the invalid parameter update while continuing to accurately report its fixed state.

- Proprietary Range: TIDs 0x8000 to 0xFFFF are reserved for Manufacturer-specific use (See Section [10.1.2](#proprietary-tid-resolution)).

- URI Routing: All URIs listed in the \'Sent by \| to URI\' columns are relative to the /sig-net/\<version\>/\<scope\> prefix defined in Section [8.2](#uri-syntax-overview).

- Cryptographic Verification: In Sig-Net, the required cryptographic key is determined by the Target URI, not the specific TID payload. Implementers shall reference the table in Appendix A (Multicast Addresses) to determine which derived key (Km_global, Km_local, Ks, or Kc) must be loaded into the HMAC engine to verify a packet arriving at a specific URI.

## Node-Discovery Type Identifiers

### TID_POLL

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Requests Device-discovery replies or specific configuration state updates from nodes on the network.                                                                   |
+===============================+===============================+===============================+=====================================================================================+
| Sent by \| to URI             | Enum                          | Length                        | Value                                                                               |
+-------------------------------+-------------------------------+-------------------------------+-------------------------------------------------------------------------------------+
| Manager                       | 0x0001                        | 25                            | \[0-5\] MANAGER_TUID: The 48-bit TUID of the Manager originating the poll.          |
|                               |                               |                               |                                                                                     |
| /poll (Only)                  |                               |                               | \[6-9\] MANAGER_SOEM_CODE: The 32-bit SoemCode of the Manager originating the poll. |
|                               |                               |                               |                                                                                     |
|                               |                               |                               | \[10-15\] TUID_LO                                                                   |
|                               |                               |                               |                                                                                     |
|                               |                               |                               | \[16-21\] TUID_HI                                                                   |
|                               |                               |                               |                                                                                     |
|                               |                               |                               | \[22-23\] END_POINT. 0xFFFF = All endpoints                                         |
|                               |                               |                               |                                                                                     |
|                               |                               |                               | \[24\] QUERY_LEVEL. See Section [11.9](#tid-polling-cross-reference)                |
+-------------------------------+-------------------------------+-------------------------------+-------------------------------------------------------------------------------------+
| Target Endpoint: Root & Data                                                                  | Queryable: No                                                                       |
+-----------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
| Notes                                                                                                                                                                               |
+-----------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                        | Node Mandated: Yes.                                                                 |
+-----------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                         | Visualiser Mandated: Yes.                                                           |
+-----------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+
| Persistent: No.                                                                               |                                                                                     |
+-----------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------+

### TID_POLL_REPLY

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports a Device\'s presence, TUID, product code and current configuration change count.                                                                                           |
+============================+============================+============================+==========================================================================================================+
| Sent by \| to URI          | Enum                       | Length                     | Value                                                                                                    |
+----------------------------+----------------------------+----------------------------+----------------------------------------------------------------------------------------------------------+
| Node                       | 0x0002                     | 12                         | \[0-5\] TUID                                                                                             |
|                            |                            |                            |                                                                                                          |
| /node/{tuid}/{endpoint}    |                            |                            | \[6-9\] SOEM_CODE                                                                                        |
|                            |                            |                            |                                                                                                          |
|                            |                            |                            | \[10-11\] CHANGE_COUNT. A 16-bit wrap around counter defined in Section [10.4.4](#consistency-tracking). |
+----------------------------+----------------------------+----------------------------+----------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root & Data                                                         | Queryable: No                                                                                            |
+--------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------+
| Note.                                                                                                                                                                                           |
+--------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                               | Node Mandated: Yes.                                                                                      |
+--------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                | Visualiser Mandated: Yes.                                                                                |
+--------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                      |                                                                                                          |
+--------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------+

### TID_SET_REPLY

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Trailing TLV generated by a Node to convey the CHANGE_COUNT.                                                                                                                     |
+============================+============================+============================+========================================================================================================+
| Sent by \| to URI          | Enum                       | Length                     | Value                                                                                                  |
+----------------------------+----------------------------+----------------------------+--------------------------------------------------------------------------------------------------------+
| Node                       | 0x0003                     | 3                          | \[0\] Flags (Reserved)                                                                                 |
|                            |                            |                            |                                                                                                        |
| /node/{tuid}/{endpoint}    |                            |                            | \[1-2\] CHANGE_COUNT. A 16-bit wrap around counter defined in Section [10.4.4](#consistency-tracking). |
+----------------------------+----------------------------+----------------------------+--------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root & Data                                                         | Queryable: No                                                                                          |
+--------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+
| Note. Appended exclusively as the final trailing TLV in a proactive configuration confirmation response.                                                                                      |
+--------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                               | Node Mandated: Yes.                                                                                    |
+--------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                | Visualiser Mandated: Yes.                                                                              |
+--------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                      |                                                                                                        |
+--------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------+

## Sender Type Identifiers

### TID_LEVEL

+-------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits up to 512 bytes of standard \[DMX512\] slot level data.                                          |
+=======================+=======================+=======================+=================================================+
| Sent by \| to URI     | Enum                  | Length                | Value                                           |
+-----------------------+-----------------------+-----------------------+-------------------------------------------------+
| Sender                | 0x0101                | 1-512                 | Up to 512 bytes of level data.                  |
|                       |                       |                       |                                                 |
| /level/{universe}     |                       |                       |                                                 |
+-----------------------+-----------------------+-----------------------+-------------------------------------------------+
| Target Endpoint: Data                                                 | Queryable: No                                   |
+-----------------------------------------------------------------------+-------------------------------------------------+
| Notes: This carries zero start-code only.                                                                               |
+-----------------------------------------------------------------------+-------------------------------------------------+
| Manager Mandated: No.                                                 | Node Mandated: Yes if Data Endpoints supported. |
+-----------------------------------------------------------------------+-------------------------------------------------+
| Sender Mandated: Yes.                                                 | Visualiser Mandated: Yes.                       |
+-----------------------------------------------------------------------+-------------------------------------------------+
| Persistent: No.                                                       |                                                 |
+-----------------------------------------------------------------------+-------------------------------------------------+

### TID_PRIORITY

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits per-slot priority values to govern network merging behaviour.                                                                                                                                                                                                                                                  |
+=================================================================================+=================================================================================+=================================================================================+=================================================================================+
| Sent by \| to URI                                                               | Enum                                                                            | Length                                                                          | Value                                                                           |
+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------+
| Sender                                                                          | 0x0102                                                                          | 1-512                                                                           | Up to 512 bytes of priority data                                                |
|                                                                                 |                                                                                 |                                                                                 |                                                                                 |
| /level/{universe}                                                               |                                                                                 |                                                                                 |                                                                                 |
+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------+---------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                                                               | Queryable: No                                                                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------+
| Notes: If the payload length is 1, the single byte value shall be applied uniformly to all 512 data slots, functioning as a Universe Priority. If the length is \> 1, the bytes map sequentially to the slots starting at data slot 1. Any remaining unaddressed slots (up to 512) shall be set to the default value of 100.          |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                                                                               | Node Mandated: Yes.                                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                                                                | Visualiser Mandated: Yes.                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                                                     |                                                                                 |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------+

### TID_PREVIEW

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits up to 512 bytes of standard \[DMX512\] slot level data intended for offline visualisation.                                                                                                 |
+====================================================+====================================================+====================================================+====================================================+
| Sent by \| to URI                                  | Enum                                               | Length                                             | Value                                              |
+----------------------------------------------------+----------------------------------------------------+----------------------------------------------------+----------------------------------------------------+
| Sender                                             | 0x0103                                             | 1-512                                              | Up to 512 bytes of level data.                     |
|                                                    |                                                    |                                                    |                                                    |
| /preview/{universe}                                |                                                    |                                                    |                                                    |
+----------------------------------------------------+----------------------------------------------------+----------------------------------------------------+----------------------------------------------------+
| Target Endpoint: Data                                                                                                                                        | Queryable: No                                      |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Notes: This carries zero start-code only. Senders transmitting Preview data shall direct it exclusively to the \<mult_preview\> multicast address to prevent unnecessary discard load on physical Nodes.          |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Manager Mandated: No.                                                                                                                                        | Node Mandated: No.                                 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Sender Mandated: No.                                                                                                                                         | Visualiser Mandated: Yes.                          |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+
| Persistent: No.                                                                                                                                              |                                                    |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------+

### TID_SYNC

+--------------------------------------------------------------------------------------------------+
| Description: Triggers all receiving nodes to output their buffers.                               |
+====================+====================+====================+===================================+
| Sent by \| to URI  | Enum               | Length             | Value                             |
+--------------------+--------------------+--------------------+-----------------------------------+
| Sender             | 0x0201             | 0                  |                                   |
|                    |                    |                    |                                   |
| /sync              |                    |                    |                                   |
+--------------------+--------------------+--------------------+-----------------------------------+
| Target Endpoint: Data                                        | Queryable: No                     |
+--------------------------------------------------------------+-----------------------------------+
| Notes:                                                                                           |
+--------------------------------------------------------------+-----------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                |
+--------------------------------------------------------------+-----------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.          |
+--------------------------------------------------------------+-----------------------------------+
| Persistent: No.                                              |                                   |
+--------------------------------------------------------------+-----------------------------------+

### TID_TIMECODE

+-------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits a single frame of show synchronisation timecode.                                                             |
+======================+======================+======================+================================================================+
| Sent by \| to URI    | Enum                 | Length               | Value                                                          |
+----------------------+----------------------+----------------------+----------------------------------------------------------------+
| Sender               | 0x0202               | 5                    | \[0\]: Hours (Valid range: 0--23)                              |
|                      |                      |                      |                                                                |
| /timecode/{stream}   |                      |                      | \[1\]: Minutes (Valid range: 0--59)                            |
|                      |                      |                      |                                                                |
|                      |                      |                      | \[2\]: Seconds (Valid range: 0--59)                            |
|                      |                      |                      |                                                                |
|                      |                      |                      | \[3\]: Frames (Valid range: 0-120, depending on the Type byte) |
|                      |                      |                      |                                                                |
|                      |                      |                      | \[4\]: Type (Defines the frame rate)                           |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x00 = 24 fps (Film)                                         |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x01 = 25 fps (EBU)                                          |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x02 = 29.97 fps (Drop Frame)                                |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x03 = 30 fps (SMPTE Non-Drop)                               |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x04 = 48 fps                                                |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x05 = 50 fps                                                |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x06 = 59.94 fps (Drop Frame)                                |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x07 = 60 fps (Non-Drop)                                     |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x08 = 100 fps                                               |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x09 = 119.88 fps (Drop Frame)                               |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x0A = 120 fps (Non-Drop)                                    |
|                      |                      |                      |                                                                |
|                      |                      |                      | - 0x0B - 0xFF = Reserved                                       |
+----------------------+----------------------+----------------------+----------------------------------------------------------------+
| Target Endpoint: Data                                              | Queryable: No                                                  |
+--------------------------------------------------------------------+----------------------------------------------------------------+
| Notes:                                                                                                                              |
+--------------------------------------------------------------------+----------------------------------------------------------------+
| Manager Mandated: No.                                              | Node Mandated: No.                                             |
+--------------------------------------------------------------------+----------------------------------------------------------------+
| Sender Mandated: No.                                               | Visualiser Mandated: No.                                       |
+--------------------------------------------------------------------+----------------------------------------------------------------+
| Persistent: No.                                                    |                                                                |
+--------------------------------------------------------------------+----------------------------------------------------------------+

### TID_UNIVERSE

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Proactively reports the active universes currently being transmitted by this Sender, allowing passive listeners (such as Visualisers) to dynamically manage their IGMP multicast subscriptions.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
+==================================================================================================================================================================================+==================================================================================================================================================================================+==================================================================================================================================================================================+================================================================================================================================================================================================================================================================================================================================+
| Sent by \| to URI                                                                                                                                                                | Enum                                                                                                                                                                             | Length                                                                                                                                                                           | Value                                                                                                                                                                                                                                                                                                                          |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender                                                                                                                                                                           | 0x0203                                                                                                                                                                           | 9                                                                                                                                                                                | \[0-1\] Universe: A 16-bit unsigned integer defining the Sig-Net universe (Valid range 1 to 63,999).                                                                                                                                                                                                                           |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
| /node/{tuid}/0                                                                                                                                                                   |                                                                                                                                                                                  |                                                                                                                                                                                  | \[2\] Command:                                                                                                                                                                                                                                                                                                                 |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  | - 0x01 (Join): The Sender is actively transmitting TID_LEVEL data for this universe.                                                                                                                                                                                                                                           |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  | - 0x02 (Leave): The Sender has ceased transmitting data for this universe.                                                                                                                                                                                                                                                     |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  | - 0x00, 0x03-0xFF: Reserved.                                                                                                                                                                                                                                                                                                   |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  | \[3-6\] Multicast IPv4 Address: The specific IP address the Sender is transmitting this universe to. If the Sender is using the default Multicast Folding algorithm (Section [9.2.3](#default-multicast-folding-universe-mapping)), this value shall be 0.0.0.0, instructing the receiver to calculate the default IP address. |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                                                                                                                                                                |
|                                                                                                                                                                                  |                                                                                                                                                                                  |                                                                                                                                                                                  | \[7-8\] Originating Sender Endpoint: A 16-bit unsigned integer defining the logical Endpoint on the Sender driving this universe.                                                                                                                                                                                              |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Queryable: No                                                                                                                                                                                                                                                                                                                  |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: Senders shall proactively multicast this TID to their Reply URI /node/{tuid}/0 on Endpoint 0 when transmission of a universe begins (Join) or gracefully terminates (Leave). To ensure newly connected listeners discover active streams, Senders shall periodically re-transmit the Join payload for all active universes at a background rate of \<universe_announce_interval\> seconds. Senders should pack multiple TID_UNIVERSE TLVs (representing all currently active universes on the device) into a single CoAP packet. This packing is strongly recommended for both state changes (Join/Leave) and the periodic background updates to minimize network packet rates and keep management overhead low.                                                                                                                                                                 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Node Mandated: No.                                                                                                                                                                                                                                                                                                             |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Visualiser Mandated: Yes.                                                                                                                                                                                                                                                                                                      |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |                                                                                                                                                                                                                                                                                                                                |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_OSC

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Transmits a standard \[OSC\] message wrapped within a secure Sig-Net container.                                                                                                                              |
+=========================================+=========================+=========================+=============================================================================================================================+
| Sent by \| to URI                       | Enum                    | Length                  | Value                                                                                                                       |
+-----------------------------------------+-------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Sender / Manager /aux/{tuid}/{endpoint} | 0x0204                  | Variable                | A fully formatted OSC Message (Address Pattern, Type Tag and Arguments) as defined by the Open Sound Control specification. |
+-----------------------------------------+-------------------------+-------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root & Data                                                                | Queryable: No                                                                                                               |
+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                    |
+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                       | Node Mandated: No.                                                                                                          |
+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                        | Visualiser Mandated: No.                                                                                                    |
+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                             |                                                                                                                             |
+---------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+

[\
]{.mark}

## RDM Type Identifiers

### TID_RDM_COMMAND

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Encapsulates a standard \[RDM\] request packet originating from a Manager.                                                                                                                                                           |
+============================================================+============================================================+============================================================+============================================================+
| Sent by \| to URI                                          | Enum                                                       | Length                                                     | Value                                                      |
+------------------------------------------------------------+------------------------------------------------------------+------------------------------------------------------------+------------------------------------------------------------+
| Manager                                                    | 0x0301                                                     | 26-257                                                     | RDM command                                                |
|                                                            |                                                            |                                                            |                                                            |
| /manager/{tuid}/{endpoint}                                 |                                                            |                                                            |                                                            |
+------------------------------------------------------------+------------------------------------------------------------+------------------------------------------------------------+------------------------------------------------------------+
| Target Endpoint: Root\* & Data                                                                                                                                                       | Queryable: No                                              |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------+
| Note: \*Root Endpoint Limitation: TID_RDM_COMMAND payloads directed to the Root Endpoint are limited to firmware updates, conditional upon the Device declaring Root_Firmware_Support. All other RDM commands shall be ignored.                   |
|                                                                                                                                                                                                                                                   |
| Note: A Command Class (CC) of DISCOVERY_COMMAND (0x10) shall not be encapsulated by this command.                                                                                                                                                 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                                               | Node Mandated: Yes if Endpoint supports RDM.               |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                 | Visualiser Mandated: No.                                   |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                      |                                                            |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------+

### TID_RDM_RESPONSE

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Encapsulates an \[RDM\] response or a proactive state-change notification originating from a Node.                                                                                                                               |
+===========================================================+===========================================================+===========================================================+===========================================================+
| Sent by \| to URI                                         | Enum                                                      | Length                                                    | Value                                                     |
+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+
| Node                                                      | 0x0302                                                    | 26-257                                                    | \[RDM\] Response.                                         |
|                                                           |                                                           |                                                           |                                                           |
| /node/{tuid}/{endpoint}                                   |                                                           |                                                           |                                                           |
+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+
| Target Endpoint: Root\* & Data                                                                                                                                                    | Queryable: No                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Notes: \*Root Endpoint Limitation: TID_RDM_COMMAND payloads directed to the Root Endpoint are limited to firmware updates, conditional upon the Device declaring Root_Firmware_Support. All other \[RDM\] commands shall be ignored.          |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                                            | Node Mandated: Yes if Endpoint supports \[RDM\].          |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                              | Visualiser Mandated: No.                                  |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Persistent: No.                                                                                                                                                                   |                                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+

### TID_RDM_TOD_CONTROL 

+--------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands a Node to force an immediate \[RDM\] discovery cycle or flush its current Table of Devices.                                |
+===============================+===============================+===============================+==================================================+
| Sent by \| to URI             | Enum                          | Length                        | Value                                            |
+-------------------------------+-------------------------------+-------------------------------+--------------------------------------------------+
| Manager                       | 0x0303                        | 1                             | \[0\] Command Enum:                              |
|                               |                               |                               |                                                  |
| /manager/{tuid}/{endpoint}    |                               |                               | 0x00: Force Node to Send TID_RDM_TOD_DATA        |
|                               |                               |                               |                                                  |
|                               |                               |                               | 0x01: Flush ToD and Force Full Discovery         |
+-------------------------------+-------------------------------+-------------------------------+--------------------------------------------------+
| Target Endpoint: Data                                                                         | Queryable: No                                    |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------+
| Notes:                                                                                                                                           |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------+
| Manager Mandated: Yes.                                                                        | Node Mandated: Yes if Endpoint supports \[RDM\]. |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------+
| Sender Mandated: No.                                                                          | Visualiser Mandated: No.                         |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------+
| Persistent: No.                                                                               |                                                  |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------+

### TID_RDM_TOD_DATA 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the array of RDM-Responder UIDs currently discovered on the specified endpoint.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
+=============================================================================+=============================================================================+=============================================================================+=============================================================================+==================================================================================================================================================================================================================================================================================================================+
| Sent by \| to URI                                                           | Enum                                                                        | Length                                                                                                                                                    | Value                                                                                                                                                                                                                                                                                                            |
+-----------------------------------------------------------------------------+-----------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                                                     | 0x0304                                                                      | Variable, 2 -- 1200 (2+ multiples of 6)                                                                                                                   | \[0\] Packet_Index: An 8-bit unsigned integer defining the sequence number of this specific payload (ranging from 1 to Total_Packets).                                                                                                                                                                           |
|                                                                             |                                                                             |                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                  |
| /manager/{tuid}/{endpoint} Node                                             |                                                                             |                                                                                                                                                           | \[1\] Total_Packets: An 8-bit unsigned integer defining the total number of TID_RDM_TOD_DATA payloads required to transmit the complete Table of Devices for this endpoint.                                                                                                                                      |
|                                                                             |                                                                             |                                                                                                                                                           |                                                                                                                                                                                                                                                                                                                  |
| /node/{tuid}/{endpoint}                                                     |                                                                             |                                                                                                                                                           | \[2-Length\] UID_Array: An array of 48-bit (6-byte) \[RDM\] UIDs representing all currently discovered RDM-Responders on this endpoint included in this packet block. (If no RDM-Responders are discovered on the endpoint, Total_Packets shall be 1, Packet_Index shall be 1 and the UID_Array shall be empty). |
+-----------------------------------------------------------------------------+-----------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                                                                                                                                 | Queryable: No                                                                                                                                                                                                                                                                                                    |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: To prevent UDP fragmentation, Nodes shall ensure the UID_Array within a single payload does not cause the CoAP packet to exceed the 1,400-byte limit (Section [10.2.4](#fragmentation)). For large discovery tables, the Node shall sequentially transmit multiple TID_RDM_TOD_DATA payloads, incrementing the Packet_Index for each block.                                                                                                                                                                                                                                                                                       |
|                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Notes: This TID is not directly queryable via a standard GET (length-0) command. To retrieve the Table of Devices, a Manager must transmit a TID_RDM_TOD_CONTROL (0x0303) command with a value of 0x00.                                                                                                                                                                                                                                                                                                                                                                                                                                  |
|                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Notes: When a large discovery table requires splitting across multiple sequential TID_RDM_TOD_DATA packets, the Node shall transmit these packets back-to-back without inserting any inter-packet pacing delay. The \<endpoint_spacing_delay\> pacing rule is strictly scoped to multi-endpoint queries (0xFFFF) and does not apply to single-endpoint fragmented data streams.                                                                                                                                                                                                                                                          |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                                                                                                  | Node Mandated: Yes if Endpoint supports \[RDM\].                                                                                                                                                                                                                                                                                                                                               |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                                                    | Visualiser Mandated: No.                                                                                                                                                                                                                                                                                                                                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                                                                                |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_RDM_EP_CONFIG 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Enables or disables the continuous background \[RDM\] discovery process on the specified endpoint.                                                                          |
+=================================+================================+================================+======================================================================================+
| Sent by \| to URI               | Enum                           | Length                         | Value                                                                                |
+---------------------------------+--------------------------------+--------------------------------+--------------------------------------------------------------------------------------+
| Manager                         | 0x0305                         | 0/1                            | \[0\] An 8-bit bitfield:                                                             |
|                                 |                                |                                |                                                                                      |
| /manager/{tuid}/{endpoint} Node |                                |                                | - Bit 0 (0x01): Enable Background Discovery (Default: On).                           |
|                                 |                                |                                |                                                                                      |
| /node/{tuid}/{endpoint}         |                                |                                | - Bit 1 (0x02): Enable Background Queue Polling (GET_QUEUED_MESSAGES) (Default: On). |
+---------------------------------+--------------------------------+--------------------------------+--------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                             | Queryable: Yes                                                                       |
+---------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                   |
+---------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                            | Node Mandated: Yes if Endpoint supports \[RDM\].                                     |
+---------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                              | Visualiser Mandated: No.                                                             |
+---------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                                   |                                                                                      |
+---------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------+

### TID_RDM_FLOW_CONTROL 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description:  Reports the real-time capacity of the endpoint\'s internal \[RDM\] command queue (FIFO buffer), allowing Managers to dynamically burst \[RDM\] traffic without overflowing the DMX512 UART.                                                                                                                    |
+=====================================================+=====================================================+=====================================================+============================================================================================================================================================+
| Sent by \| to URI                                   | Enum                                                | Length                                              | Value                                                                                                                                                      |
+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                             | 0x0306                                              | 0/2                                                 | \[0\] Total \[RDM\] FIFO Buffers: An 8-bit unsigned integer defining the maximum number of \[RDM\] commands this Endpoint can queue simultaneously.        |
|                                                     |                                                     |                                                     |                                                                                                                                                            |
| /manager/{tuid}/{endpoint} Node                     |                                                     |                                                     | \[1\] Available \[RDM\] FIFO Buffers: An 8-bit unsigned integer defining how many slots in the queue are currently empty and ready to accept new commands. |
|                                                     |                                                     |                                                     |                                                                                                                                                            |
| /node/{tuid}/{endpoint}                             |                                                     |                                                     |                                                                                                                                                            |
+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                           | Queryable: Yes                                                                                                                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: A Node shall proactively multicast this TID to its Reply URI whenever its Available FIFO Buffer count changes. Nodes should append this TLV to any outbound TID_RDM_RESPONSE when possible.                                                                                                                           |
|                                                                                                                                                                                                                                                                                                                              |
| Managers shall respect the Available buffer count to prevent command loss.                                                                                                                                                                                                                                                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                          | Node Mandated: Yes if Endpoint supports \[RDM\].                                                                                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                            | Visualiser Mandated: No.                                                                                                                                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                 |                                                                                                                                                            |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------+

## Offboarding Type Identifiers

The Type Identifiers in this section shall only be used with the root endpoint (0).

### TID_RT_OFFBOARD

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands a Node to permanently delete its cryptographic keys and return to an offboarded state.                                                                                                          |
+=====================================================+=====================================================+=====================================================+=====================================================+
| Sent by \| to URI                                   | Enum                                                | Length                                              | Value                                               |
+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+
| Manager                                             | 0x0401                                              | 4                                                   | \[0-3\] Magic Word 0x57495045 (ASCII \"WIPE\").     |
|                                                     |                                                     |                                                     |                                                     |
| /manager/{tuid}/0                                   |                                                     |                                                     |                                                     |
+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+
| Target Endpoint: Root                                                                                                                                           | Queryable: No                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------+
| Notes: Instructs the Device to permanently delete all cryptographic keys, reset session counters and return to the Offboarded state (Beacon Mode). Payload values other than 0x57495045 shall be ignored.             |
|                                                                                                                                                                                                                       |
| Nodes only accept the TID_RT_OFFBOARD command within the first \<offboard_lockout\> seconds after the Node physically powers on.                                                                                      |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------+
| Manager Mandated: No.                                                                                                                                           | Node Mandated: No.                                  |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------+
| Sender Mandated: No.                                                                                                                                            | Visualiser Mandated: No.                            |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------+
| Persistent: No.                                                                                                                                                 |                                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------+

## Network Configuration Type Identifiers

The Type Identifiers in this section are used to configure the fundamental IP network stack of the Device. They shall only be used with the root endpoint (0). Support for these parameters is optional, but strongly recommended.

### TID_NW_MAC_ADDRESS

+--------------------------------------------------------------------------------------------------------------------+
| Description: Reports the physical MAC address of the network interface.                                            |
+======================+======================+======================+===============================================+
| Sent by \| to URI    | Enum                 | Length               | Value                                         |
+----------------------+----------------------+----------------------+-----------------------------------------------+
| Manager              | 0x0501               | 0/6                  | \[0-5\] The 48-bit MAC address of the Device. |
|                      |                      |                      |                                               |
| /manager/{tuid}/0    |                      |                      |                                               |
|                      |                      |                      |                                               |
| Node                 |                      |                      |                                               |
|                      |                      |                      |                                               |
| /node/{tuid}/0       |                      |                      |                                               |
+----------------------+----------------------+----------------------+-----------------------------------------------+
| Target Endpoint: Root                                              | Queryable: Yes                                |
+--------------------------------------------------------------------+-----------------------------------------------+
| Notes:                                                                                                             |
+--------------------------------------------------------------------+-----------------------------------------------+
| Manager Mandated: No.                                              | Node Mandated: No.                            |
+--------------------------------------------------------------------+-----------------------------------------------+
| Sender Mandated: No.                                               | Visualiser Mandated: No.                      |
+--------------------------------------------------------------------+-----------------------------------------------+
| Persistent: Yes. Stored in NVR.                                    |                                               |
+--------------------------------------------------------------------+-----------------------------------------------+

### TID_NW_IPV4_MODE

+--------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the IPv4 address allocation mode.                                         |
+====================+====================+====================+=========================================+
| Sent by \| to URI  | Enum               | Length             | Value                                   |
+--------------------+--------------------+--------------------+-----------------------------------------+
| Manager            | 0x0502             | 0/1                | \[0\] Mode: 0x00 = Static. 0x01 = DHCP. |
|                    |                    |                    |                                         |
| /manager/{tuid}/0  |                    |                    |                                         |
|                    |                    |                    |                                         |
| Node               |                    |                    |                                         |
|                    |                    |                    |                                         |
| /node/{tuid}/0     |                    |                    |                                         |
+--------------------+--------------------+--------------------+-----------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                          |
+--------------------------------------------------------------+-----------------------------------------+
| Notes:                                                                                                 |
+--------------------------------------------------------------+-----------------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                      |
+--------------------------------------------------------------+-----------------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.                |
+--------------------------------------------------------------+-----------------------------------------+
| Persistent: Yes. Stored in NVR.                              |                                         |
+--------------------------------------------------------------+-----------------------------------------+

### TID_NW_IPV4_ADDRESS

+--------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the configured Static IPv4 Address.                                             |
+=========================+====================+====================+==========================================+
| Sent by \| to URI       | Enum               | Length             | Value                                    |
+-------------------------+--------------------+--------------------+------------------------------------------+
| Manager                 | 0x0503             | 0/4                | \[0-3\] The 32-bit static IPv4 Address.  |
|                         |                    |                    |                                          |
| /manager/{tuid}/0       |                    |                    |                                          |
|                         |                    |                    |                                          |
| Node                    |                    |                    |                                          |
|                         |                    |                    |                                          |
| /node/{tuid}/{endpoint} |                    |                    |                                          |
+-------------------------+--------------------+--------------------+------------------------------------------+
| Target Endpoint: Root                                             | Queryable: Yes                           |
+-------------------------------------------------------------------+------------------------------------------+
| Notes:                                                                                                       |
+-------------------------------------------------------------------+------------------------------------------+
| Manager Mandated: No.                                             | Node Mandated: No.                       |
+-------------------------------------------------------------------+------------------------------------------+
| Sender Mandated: No.                                              | Visualiser Mandated: No.                 |
+-------------------------------------------------------------------+------------------------------------------+
| Persistent: Yes. Stored in NVR.                                   |                                          |
+-------------------------------------------------------------------+------------------------------------------+

### TID_NW_IPV4_NETMASK

+------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the configured Static IPv4 Subnet Mask.                                       |
+====================+====================+====================+=============================================+
| Sent by \| to URI  | Enum               | Length             | Value                                       |
+--------------------+--------------------+--------------------+---------------------------------------------+
| Manager            | 0x0504             | 0/4                | \[0-3\] The 32-bit static IPv4 Subnet Mask. |
|                    |                    |                    |                                             |
| /manager/{tuid}/0  |                    |                    |                                             |
|                    |                    |                    |                                             |
| Node               |                    |                    |                                             |
|                    |                    |                    |                                             |
| /node/{tuid}/0     |                    |                    |                                             |
+--------------------+--------------------+--------------------+---------------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                              |
+--------------------------------------------------------------+---------------------------------------------+
| Notes:                                                                                                     |
+--------------------------------------------------------------+---------------------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                          |
+--------------------------------------------------------------+---------------------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.                    |
+--------------------------------------------------------------+---------------------------------------------+
| Persistent: Yes. Stored in NVR.                              |                                             |
+--------------------------------------------------------------+---------------------------------------------+

### TID_NW_IPV4_GATEWAY

+----------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the configured Static IPv4 Default Gateway.                                       |
+====================+====================+====================+=================================================+
| Sent by \| to URI  | Enum               | Length             | Value                                           |
+--------------------+--------------------+--------------------+-------------------------------------------------+
| Manager            | 0x0505             | 0/4                | \[0-3\] The 32-bit static IPv4 Default Gateway. |
|                    |                    |                    |                                                 |
| /manager/{tuid}/0  |                    |                    |                                                 |
|                    |                    |                    |                                                 |
| Node               |                    |                    |                                                 |
|                    |                    |                    |                                                 |
| /node/{tuid}/0     |                    |                    |                                                 |
+--------------------+--------------------+--------------------+-------------------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                                  |
+--------------------------------------------------------------+-------------------------------------------------+
| Notes:                                                                                                         |
+--------------------------------------------------------------+-------------------------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                              |
+--------------------------------------------------------------+-------------------------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.                        |
+--------------------------------------------------------------+-------------------------------------------------+
| Persistent: Yes. Stored in NVR.                              |                                                 |
+--------------------------------------------------------------+-------------------------------------------------+

### TID_NW_IPV4_CURRENT

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the currently active IPv4 network settings, regardless of whether they were set statically or obtained via DHCP.                                                                                                                                               |
+====================================+====================================+====================================+======================================================================================================================================================================+
| Sent by \| to URI                  | Enum                               | Length                             | Value                                                                                                                                                                |
+------------------------------------+------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                            | 0x0506                             | 0/12                               | \[0-3\] Currently active IPv4 Address.                                                                                                                               |
|                                    |                                    |                                    |                                                                                                                                                                      |
| /manager/{tuid}/0                  |                                    |                                    | \[4-7\] Currently active IPv4 Subnet Mask.                                                                                                                           |
|                                    |                                    |                                    |                                                                                                                                                                      |
| Node                               |                                    |                                    | \[8-11\] Currently active IPv4 Default Gateway.                                                                                                                      |
|                                    |                                    |                                    |                                                                                                                                                                      |
| /node/{tuid}/0                     |                                    |                                    | All values are 32-bit IPv4 addresses in network byte order. These reflect the operational values regardless of whether they were set statically or assigned by DHCP. |
+------------------------------------+------------------------------------+------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                        | Queryable: Yes                                                                                                                                                       |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                                              |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                        | Node Mandated: No.                                                                                                                                                   |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                         | Visualiser Mandated: No.                                                                                                                                             |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                              |                                                                                                                                                                      |
+--------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_NW_IPV6_MODE

+------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the IPv6 address allocation mode.                                                         |
+====================+====================+====================+=========================================================+
| Sent by \| to URI  | Enum               | Length             | Value                                                   |
+--------------------+--------------------+--------------------+---------------------------------------------------------+
| Manager            | 0x0581             | 0/1                | \[0\] Mode: 0x00 = Static. 0x01 = SLAAC. 0x02 = DHCPv6. |
|                    |                    |                    |                                                         |
| /manager/{tuid}/0  |                    |                    |                                                         |
|                    |                    |                    |                                                         |
| Node               |                    |                    |                                                         |
|                    |                    |                    |                                                         |
| /node/{tuid}/0     |                    |                    |                                                         |
+--------------------+--------------------+--------------------+---------------------------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                                          |
+--------------------------------------------------------------+---------------------------------------------------------+
| Notes:                                                                                                                 |
+--------------------------------------------------------------+---------------------------------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                                      |
+--------------------------------------------------------------+---------------------------------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.                                |
+--------------------------------------------------------------+---------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                              |                                                         |
+--------------------------------------------------------------+---------------------------------------------------------+

### TID_NW_IPV6_ADDRESS

+----------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the configured Static IPv6 Address.                                         |
+====================+====================+====================+===========================================+
| Sent by \| to URI  | Enum               | Length             | Value                                     |
+--------------------+--------------------+--------------------+-------------------------------------------+
| Manager            | 0x0582             | 0/16               | \[0-15\] The 128-bit static IPv6 Address. |
|                    |                    |                    |                                           |
| /manager/{tuid}/0  |                    |                    |                                           |
|                    |                    |                    |                                           |
| Node               |                    |                    |                                           |
|                    |                    |                    |                                           |
| /node/{tuid}/0     |                    |                    |                                           |
+--------------------+--------------------+--------------------+-------------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                            |
+--------------------------------------------------------------+-------------------------------------------+
| Notes:                                                                                                   |
+--------------------------------------------------------------+-------------------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                        |
+--------------------------------------------------------------+-------------------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.                  |
+--------------------------------------------------------------+-------------------------------------------+
| Persistent: Yes. Stored in NVR.                              |                                           |
+--------------------------------------------------------------+-------------------------------------------+

### TID_NW_IPV6_PREFIX

+----------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the configured Static IPv6 Routing Prefix Length.                                       |
+=======================+=======================+=======================+==============================================+
| Sent by \| to URI     | Enum                  | Length                | Value                                        |
+-----------------------+-----------------------+-----------------------+----------------------------------------------+
| Manager               | 0x0583                | 0/1                   | \[0\] The prefix length (Valid range 0-128). |
|                       |                       |                       |                                              |
| /manager/{tuid}/0     |                       |                       |                                              |
|                       |                       |                       |                                              |
| Node                  |                       |                       |                                              |
|                       |                       |                       |                                              |
| /node/{tuid}/0        |                       |                       |                                              |
+-----------------------+-----------------------+-----------------------+----------------------------------------------+
| Target Endpoint: Root                                                 | Queryable: Yes                               |
+-----------------------------------------------------------------------+----------------------------------------------+
| Notes:                                                                                                               |
+-----------------------------------------------------------------------+----------------------------------------------+
| Manager Mandated: No.                                                 | Node Mandated: No.                           |
+-----------------------------------------------------------------------+----------------------------------------------+
| Sender Mandated: No.                                                  | Visualiser Mandated: No.                     |
+-----------------------------------------------------------------------+----------------------------------------------+
| Persistent: Yes. Stored in NVR.                                       |                                              |
+-----------------------------------------------------------------------+----------------------------------------------+

### TID_NW_IPV6_GATEWAY

+------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the configured Static IPv6 Default Gateway.                                         |
+====================+====================+====================+===================================================+
| Sent by \| to URI  | Enum               | Length             | Value                                             |
+--------------------+--------------------+--------------------+---------------------------------------------------+
| Manager            | 0x0584             | 0/16               | \[0-15\] The 128-bit static IPv6 Default Gateway. |
|                    |                    |                    |                                                   |
| /manager/{tuid}/0  |                    |                    |                                                   |
|                    |                    |                    |                                                   |
| Node               |                    |                    |                                                   |
|                    |                    |                    |                                                   |
| /node/{tuid}/0     |                    |                    |                                                   |
+--------------------+--------------------+--------------------+---------------------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                                    |
+--------------------------------------------------------------+---------------------------------------------------+
| Notes:                                                                                                           |
+--------------------------------------------------------------+---------------------------------------------------+
| Manager Mandated: No.                                        | Node Mandated: No.                                |
+--------------------------------------------------------------+---------------------------------------------------+
| Sender Mandated: No.                                         | Visualiser Mandated: No.                          |
+--------------------------------------------------------------+---------------------------------------------------+
| Persistent: Yes. Stored in NVR.                              |                                                   |
+--------------------------------------------------------------+---------------------------------------------------+

### TID_NW_IPV6_CURRENT

+-----------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the currently active IPv6 network settings, regardless of how they were assigned.                      |
+=============================+=============================+=============================+===================================+
| Sent by \| to URI           | Enum                        | Length                      | Value                             |
+-----------------------------+-----------------------------+-----------------------------+-----------------------------------+
| Manager                     | 0x0585                      | 0/33                        | \[0-15\] Active IPv6 Address.     |
|                             |                             |                             |                                   |
| /manager/{tuid}/0           |                             |                             | \[16\] Active Prefix Length.      |
|                             |                             |                             |                                   |
| Node                        |                             |                             | \[17-32\] Active Default Gateway. |
|                             |                             |                             |                                   |
| /node/{tuid}/0              |                             |                             |                                   |
+-----------------------------+-----------------------------+-----------------------------+-----------------------------------+
| Target Endpoint: Root                                                                   | Queryable: Yes                    |
+-----------------------------------------------------------------------------------------+-----------------------------------+
| Notes:                                                                                                                      |
+-----------------------------------------------------------------------------------------+-----------------------------------+
| Manager Mandated: No.                                                                   | Node Mandated: No.                |
+-----------------------------------------------------------------------------------------+-----------------------------------+
| Sender Mandated: No.                                                                    | Visualiser Mandated: No.          |
+-----------------------------------------------------------------------------------------+-----------------------------------+
| Persistent: No.                                                                         |                                   |
+-----------------------------------------------------------------------------------------+-----------------------------------+

## Root Endpoint Type Identifiers

The Type Identifiers in this section shall only be used with the root endpoint (0).

### TID_RT_SUPPORTED_TIDS 

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the complete array of Type Identifiers (TIDs) supported by the Device.                                                                                                                                                                                                                                                                   |
+=====================+=====================+=====================+=====================+=======================================================================================================================================================================================================================================================================+
| Sent by \| to URI   | Enum                | Length                                    | Value                                                                                                                                                                                                                                                                 |
+---------------------+---------------------+-------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager             | 0x0601              | 0 or Variable (2-1200), multiples of 2    | An array of 16-bit (2-byte) Type Identifiers (TID) supported by the Node. Reports the complete array of Type Identifiers (TIDs) supported by this Device. The list shall include all supported TIDs regardless of whether they are mandated, optional or proprietary. |
|                     |                     |                                           |                                                                                                                                                                                                                                                                       |
| /manager/{tuid}/0   |                     |                                           |                                                                                                                                                                                                                                                                       |
|                     |                     |                                           |                                                                                                                                                                                                                                                                       |
| Node                |                     |                                           |                                                                                                                                                                                                                                                                       |
|                     |                     |                                           |                                                                                                                                                                                                                                                                       |
| /node/{tuid}/0      |                     |                                           |                                                                                                                                                                                                                                                                       |
+---------------------+---------------------+-------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                 | Queryable: Yes                                                                                                                                                                                                                                                        |
+---------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                                                                                                                        |
+-----------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                          | Node Mandated: Yes.                                                                                                                                                                                                                                                                         |
+-----------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                           | Visualiser Mandated: Yes.                                                                                                                                                                                                                                                                   |
+-----------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                 |                                                                                                                                                                                                                                                                                             |
+-----------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_RT_ENDPOINT_COUNT

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the total number of physical or logical data endpoints available on the Device.                                                                                                                                                    |
+===========================+===========================+===========================+=====================================================================================================================================================================+
| Sent by \| to URI         | Enum                      | Length                    | Value                                                                                                                                                               |
+---------------------------+---------------------------+---------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                   | 0x0602                    | 0/2                       | \[0-1\] Total number of data endpoints (Endpoints 1 to N) on this Device. Does not include Endpoint 0. A value of 0x0000 indicates a Device with no data endpoints. |
|                           |                           |                           |                                                                                                                                                                     |
| /manager/{tuid}/0         |                           |                           |                                                                                                                                                                     |
|                           |                           |                           |                                                                                                                                                                     |
| Node                      |                           |                           |                                                                                                                                                                     |
|                           |                           |                           |                                                                                                                                                                     |
| /node/{tuid}/0            |                           |                           |                                                                                                                                                                     |
+---------------------------+---------------------------+---------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                             | Queryable: Yes                                                                                                                                                      |
+-----------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                  |
+-----------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                            | Node Mandated: Yes.                                                                                                                                                 |
+-----------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                             | Visualiser Mandated: Yes.                                                                                                                                           |
+-----------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                   |                                                                                                                                                                     |
+-----------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_RT_PROTOCOL_VERSION

+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the Sig-Net protocol version supported on this Device.                                                                                                                                                                                                                                                                                               |
+=======================+=======================+=======================+===================================================================================================================================================================================================================================================================================================+
| Sent by \| to URI     | Enum                  | Length                | Value                                                                                                                                                                                                                                                                                             |
+-----------------------+-----------------------+-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager               | 0x0603                | 0/1                   | \[0\] Protocol Version. An unsigned integer representing the major architectural version of the Sig-Net specification supported by the Node. This integer corresponds directly to the \<version\> string required in the CoAP URI-Path (e.g. a value of 0x01 corresponds to the URI string /v1/). |
|                       |                       |                       |                                                                                                                                                                                                                                                                                                   |
| /manager/{tuid}/0     |                       |                       |                                                                                                                                                                                                                                                                                                   |
|                       |                       |                       |                                                                                                                                                                                                                                                                                                   |
| Node                  |                       |                       |                                                                                                                                                                                                                                                                                                   |
|                       |                       |                       |                                                                                                                                                                                                                                                                                                   |
| /node/{tuid}/0        |                       |                       |                                                                                                                                                                                                                                                                                                   |
+-----------------------+-----------------------+-----------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                 | Queryable: Yes                                                                                                                                                                                                                                                                                    |
+-----------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                                                                                                                                    |
+-----------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                | Node Mandated: Yes.                                                                                                                                                                                                                                                                               |
+-----------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                 | Visualiser Mandated: Yes.                                                                                                                                                                                                                                                                         |
+-----------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                       |                                                                                                                                                                                                                                                                                                   |
+-----------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_RT_FIRMWARE_VERSION

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the firmware version of this Device.                                                                                                                                                                          |
+====================+====================+====================+=====================================================================================================================================================================+
| Sent by \| to URI  | Enum               | Length             | Value                                                                                                                                                               |
+--------------------+--------------------+--------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager            | 0x0604             | 0/4-68             | \[0-3\] Machine Version ID: A 32-bit unsigned integer representing the manufacturer\'s firmware version. This value shall follow the convention defined in \[RDM\]. |
|                    |                    |                    |                                                                                                                                                                     |
| /manager/{tuid}/0  |                    |                    | \[4-67\] An ASCII encoded human-readable firmware version string (e.g. \"v1.2.4b\"). Maximum 64 bytes. Not null-terminated.                                         |
|                    |                    |                    |                                                                                                                                                                     |
| Node               |                    |                    |                                                                                                                                                                     |
|                    |                    |                    |                                                                                                                                                                     |
| /node/{tuid}/0     |                    |                    |                                                                                                                                                                     |
+--------------------+--------------------+--------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                        | Queryable: Yes                                                                                                                                                      |
+--------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                             |
+--------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                       | Node Mandated: Yes.                                                                                                                                                 |
+--------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                        | Visualiser Mandated: Yes.                                                                                                                                           |
+--------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                              |                                                                                                                                                                     |
+--------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_RT_DEVICE_LABEL

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the human-readable text label representing the entire physical Device.                                                                    |
+=============================+=============================+=============================+==============================================================================+
| Sent by \| to URI           | Enum                        | Length                      | Value                                                                        |
+-----------------------------+-----------------------------+-----------------------------+------------------------------------------------------------------------------+
| Manager                     | 0x0605                      | 0/1-65                      | \[0\] Encoding: 0x00 = ASCII.                                                |
|                             |                             |                             |                                                                              |
| /manager/{tuid}/0           |                             |                             | \[1-64\] Human-readable Device label. Maximum 64 bytes. Not null-terminated. |
|                             |                             |                             |                                                                              |
| Node                        |                             |                             |                                                                              |
|                             |                             |                             |                                                                              |
| /node/{tuid}/0              |                             |                             |                                                                              |
+-----------------------------+-----------------------------+-----------------------------+------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                   | Queryable: Yes                                                               |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                 |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                  | Node Mandated: Yes.                                                          |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                   | Visualiser Mandated: Yes.                                                    |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                         |                                                                              |
+-----------------------------------------------------------------------------------------+------------------------------------------------------------------------------+

### TID_RT_MULT_OVERRIDE 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Resets or reports whether the Device\'s endpoints are utilising custom multicast routing overrides.                                                                                                                               |
+====================================+====================================+====================================+=================================================================================================================================+
| Sent by \| to URI                  | Enum                               | Length                             | Value                                                                                                                           |
+------------------------------------+------------------------------------+------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Manager                            | 0x0606                             | 0/1                                | \[0\] Global Multicast Routing State:                                                                                           |
|                                    |                                    |                                    |                                                                                                                                 |
| /manager/{tuid}/0                  |                                    |                                    | 0x00: Default. All Data Endpoints on this Node are exclusively using the default folded mapping (\<mult_u1\> to \<mult_u109\>). |
|                                    |                                    |                                    |                                                                                                                                 |
| Node                               |                                    |                                    | 0x01: Custom. One or more Data Endpoints on this Node are patched to a custom Multicast IP.                                     |
|                                    |                                    |                                    |                                                                                                                                 |
| /node/{tuid}/0                     |                                    |                                    |                                                                                                                                 |
+------------------------------------+------------------------------------+------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                        | Queryable: Yes                                                                                                                  |
+--------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Notes: When sent by manager, only the payload value of 0x00 is valid and shall return all multicast addresses to their default value.                                                                                                          |
+--------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                       | Node Mandated: Yes.                                                                                                             |
+--------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                                        | Visualiser Mandated: Yes.                                                                                                       |
+--------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                                              |                                                                                                                                 |
+--------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------+

### TID_RT_IDENTIFY 

+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands the Device to visually or audibly identify itself to an operator.                                                                                                                                                                                                                                                                                                                                                          |
+=========================================================================================================+=========================================================================================================+=========================================================================================================+====================================================================================================================+
| Sent by \| to URI                                                                                       | Enum                                                                                                    | Length                                                                                                  | Value                                                                                                              |
+---------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Manager                                                                                                 | 0x0607                                                                                                  | 0/1                                                                                                     | \[0\] Identify State:                                                                                              |
|                                                                                                         |                                                                                                         |                                                                                                         |                                                                                                                    |
| /manager/{tuid}/0                                                                                       |                                                                                                         |                                                                                                         | 0x00: Identify off. Normal operation.                                                                              |
|                                                                                                         |                                                                                                         |                                                                                                         |                                                                                                                    |
| Node                                                                                                    |                                                                                                         |                                                                                                         | 0x01: Identify Subtle. Causes the Device to identify itself in a subtle way that could be used in show conditions. |
|                                                                                                         |                                                                                                         |                                                                                                         |                                                                                                                    |
| /node/{tuid}/0                                                                                          |                                                                                                         |                                                                                                         | 0x02: Identify Full. Causes the Device to identify itself in an obvious way.                                       |
|                                                                                                         |                                                                                                         |                                                                                                         |                                                                                                                    |
|                                                                                                         |                                                                                                         |                                                                                                         | 0x03: Mutes all indicators and backlights for dark-sky operation.                                                  |
|                                                                                                         |                                                                                                         |                                                                                                         |                                                                                                                    |
|                                                                                                         |                                                                                                         |                                                                                                         | 0x04: Un-mutes all indicators and backlights.                                                                      |
+---------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                                                                                                                                                                       | Queryable: Yes                                                                                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Notes: The Identify state shall be stored in volatile memory (RAM) only and shall default to 0x00 (Off) upon Device initialisation or power cycle. It shall not persist across reboots.\                                                                                                                                                                                                                                                         |
| There is no interaction between the Root Identify state and the Endpoint Identify states. Transmitting a Root Identify command (including 0x00 Off) does not overwrite or clear the active Identify states of individual Data Endpoints. To clear all indicators on a multi-port Device simultaneously, a Manager should transmit both TID_RT_IDENTIFY and TID_EP_IDENTIFY (set to 0x00) to the Broadcast Endpoint (0xFFFF).                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                                                                                                                                                                                      | Node Mandated: Yes.                                                                                                |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                                                                                                                                                                                                                                                       | Visualiser Mandated: Yes.                                                                                          |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                                                                                                                             |                                                                                                                    |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+

### TID_RT_STATUS 

+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports a bitfield detailing the global hardware health and configuration lock status of the Device.                                            |
+===============================+===============================+===============================+==============================================================+
| Sent by \| to URI             | Enum                          | Length                        | Value                                                        |
+-------------------------------+-------------------------------+-------------------------------+--------------------------------------------------------------+
| Manager                       | 0x0608                        | 0/4                           | \[0-3\] A 32-bit bitfield representing global Device health. |
|                               |                               |                               |                                                              |
| /manager/{tuid}/0             |                               |                               | Bit 0: Hardware Fault.                                       |
|                               |                               |                               |                                                              |
| Node                          |                               |                               | Bit 1: Booted from factory defaults.                         |
|                               |                               |                               |                                                              |
| /node/{tuid}/0                |                               |                               | Bit 2: Configuration locked via local UI.                    |
|                               |                               |                               |                                                              |
|                               |                               |                               | Bit 3: Operating in Open Mode (Unauthenticated).             |
|                               |                               |                               |                                                              |
|                               |                               |                               | Bits 4-31: Reserved.                                         |
+-------------------------------+-------------------------------+-------------------------------+--------------------------------------------------------------+
| Target Endpoint: Root                                                                         | Queryable: Yes                                               |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Notes:                                                                                                                                                       |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Manager Mandated: Yes.                                                                        | Node Mandated: Yes.                                          |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Sender Mandated: Yes.                                                                         | Visualiser Mandated: Yes.                                    |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------------------+
| Persistent: No.                                                                               |                                                              |
+-----------------------------------------------------------------------------------------------+--------------------------------------------------------------+

### TID_RT_ROLE_CAPABILITY 

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description:  Reports the functional Sig-Net roles embedded within the Device.                                                                                        |
+=======================+=======================+=======================+===============================================================================================+
| Sent by \| to URI     | Enum                  | Length                | Value                                                                                         |
+-----------------------+-----------------------+-----------------------+-----------------------------------------------------------------------------------------------+
| Manager               | 0x0609                | 0/4                   | \[0-3\] A 32-bit bitfield supported roles.                                                    |
|                       |                       |                       |                                                                                               |
| /manager/{tuid}/0     |                       |                       | - Bit 0: Node Role Supported.                                                                 |
|                       |                       |                       |                                                                                               |
| Node                  |                       |                       | - Bit 1: Sender Role Supported.                                                               |
|                       |                       |                       |                                                                                               |
| /node/{tuid}/0        |                       |                       | - Bit 2: Manager Role Supported.                                                              |
|                       |                       |                       |                                                                                               |
|                       |                       |                       | - Bit 3: Visualiser Role Supported.                                                           |
|                       |                       |                       |                                                                                               |
|                       |                       |                       | - Bits 4-5: Reserved.                                                                         |
|                       |                       |                       |                                                                                               |
|                       |                       |                       | - Bit 6: Root_Firmware_Support (Firmware updates via encapsulated \[RDM\] supported on Root). |
|                       |                       |                       |                                                                                               |
|                       |                       |                       | - Bit 7: Open Mode supported.                                                                 |
|                       |                       |                       |                                                                                               |
|                       |                       |                       | - Bits 8-31: Reserved.                                                                        |
+-----------------------+-----------------------+-----------------------+-----------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                 | Queryable: Yes                                                                                |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                | Node Mandated: Yes.                                                                           |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                 | Visualiser Mandated: Yes.                                                                     |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------------------------------+
| Persistent: No.                                                       |                                                                                               |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------------------------------+

### TID_RT_REBOOT 

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands the Device to perform a reboot.                                                                                                                                                                                         |
+===========================================================+===========================================================+===========================================================+===========================================================+
| Sent by \| to URI                                         | Enum                                                      | Length                                                    | Value                                                     |
+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+
| Manager                                                   | 0x060A                                                    | 5                                                         | \[0\] An 8-bit command representing reboot type:          |
|                                                           |                                                           |                                                           |                                                           |
| /manager/{tuid}/0                                         |                                                           |                                                           | 0xFF: Hardware Reset.                                     |
|                                                           |                                                           |                                                           |                                                           |
|                                                           |                                                           |                                                           | 0xFE: Warm Reboot.                                        |
|                                                           |                                                           |                                                           |                                                           |
|                                                           |                                                           |                                                           | 0x00-0xFD: Not used.                                      |
|                                                           |                                                           |                                                           |                                                           |
|                                                           |                                                           |                                                           | \[1-4\] Magic Word "BOOT"                                 |
+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+-----------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                             | Queryable: No                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Notes: Instructs the Device to immediately cease network operations, gracefully close any open hardware states if possible and perform the requested reboot. The command shall be ignored if the Magic Word does not match.                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                             | Node Mandated: No.                                        |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                              | Visualiser Mandated: No.                                  |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+
| Persistent: No.                                                                                                                                                                   |                                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------+

### TID_RT_MODEL_NAME

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the human-readable product model name of the physical Device.                                                                              |
+========================+========================+========================+======================================================================================+
| Sent by \| to URI      | Enum                   | Length                 | Value                                                                                |
+------------------------+------------------------+------------------------+--------------------------------------------------------------------------------------+
| Manager                | 0x060B                 | 0/1-65                 | \[0\] Encoding: 0x00 = ASCII.                                                        |
|                        |                        |                        |                                                                                      |
| /manager/{tuid}/0      |                        |                        | \[1-64\] Human-readable product model string. Maximum 64 bytes. Not null-terminated. |
|                        |                        |                        |                                                                                      |
| Node                   |                        |                        |                                                                                      |
|                        |                        |                        |                                                                                      |
| /node/{tuid}/0         |                        |                        |                                                                                      |
+------------------------+------------------------+------------------------+--------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                    | Queryable: Yes                                                                       |
+--------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                          |
+--------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                   | Node Mandated: Yes.                                                                  |
+--------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                    | Visualiser Mandated: Yes.                                                            |
+--------------------------------------------------------------------------+--------------------------------------------------------------------------------------+
| Persistent: No.                                                          |                                                                                      |
+--------------------------------------------------------------------------+--------------------------------------------------------------------------------------+

### TID_RT_OTW_CAPABILITY 

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the network port and cryptographic protocols supported by the Device for Over-The-Wire (OTW) onboarding and key rotation.                                                                                                                                          |
+=======================================+=======================================+=======================================+=================================================================================================================================================================+
| Sent by \| to URI                     | Enum                                  | Length                                | Value                                                                                                                                                           |
+---------------------------------------+---------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                               | 0x060D                                | 0/3                                   | \[0-1\] OTW Listener Port: A 16-bit unsigned integer defining the TCP or UDP port on which the Device is actively listening for a secure onboarding handshake.\ |
|                                       |                                       |                                       | \[2\] Supported Protocols Bitfield:                                                                                                                             |
| /manager/{tuid}/0                     |                                       |                                       |                                                                                                                                                                 |
|                                       |                                       |                                       | - Bit 0 (0x01): DTLS 1.2 Supported                                                                                                                              |
| Node                                  |                                       |                                       |                                                                                                                                                                 |
|                                       |                                       |                                       | - Bit 1 (0x02): DTLS 1.3 Supported                                                                                                                              |
| /node/{tuid}/0                        |                                       |                                       |                                                                                                                                                                 |
|                                       |                                       |                                       | - Bit 2 (0x04): TLS 1.2 Supported (TCP)                                                                                                                         |
|                                       |                                       |                                       |                                                                                                                                                                 |
|                                       |                                       |                                       | - Bit 3 (0x08): TLS 1.3 Supported (TCP)                                                                                                                         |
|                                       |                                       |                                       |                                                                                                                                                                 |
|                                       |                                       |                                       | - Bit 4 (0x10): Method B, PIN Onboarding Supported.                                                                                                             |
|                                       |                                       |                                       |                                                                                                                                                                 |
|                                       |                                       |                                       | - Bits 5-7: Reserved.                                                                                                                                           |
+---------------------------------------+---------------------------------------+---------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                 | Queryable: Yes                                                                                                                                                  |
+-----------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: Devices that do not support OTW onboarding shall not support this TID.                                                                                                                                                                                                           |
+-----------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes if OTW supported.                                                                               | Node Mandated: Yes if OTW supported.                                                                                                                            |
+-----------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes if OTW supported.                                                                                | Visualiser Mandated: Yes if OTW supported.                                                                                                                      |
+-----------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                       |                                                                                                                                                                 |
+-----------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+

## Data Endpoint Type Identifiers

The Type Identifiers in this section shall only be used with the data endpoint (1-n).

### TID_EP_UNIVERSE

+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the operational Sig-Net universe assigned to a specific endpoint.                                                              |
+=================================+===========================+===========================+===================================================================+
| Sent by \| to URI               | Enum                      | Length                    | Value                                                             |
+---------------------------------+---------------------------+---------------------------+-------------------------------------------------------------------+
| Manager                         | 0x0901                    | 0/2                       | \[0-1\] UNIVERSE_VALUE. Valid range 1 to 63,999 and 0 if not set. |
|                                 |                           |                           |                                                                   |
| /manager/{tuid}/{endpoint} Node |                           |                           |                                                                   |
|                                 |                           |                           |                                                                   |
| /node/{tuid}/{endpoint}         |                           |                           |                                                                   |
+---------------------------------+---------------------------+---------------------------+-------------------------------------------------------------------+
| Target Endpoint: Data                                                                   | Queryable: Yes                                                    |
+-----------------------------------------------------------------------------------------+-------------------------------------------------------------------+
| Notes:                                                                                                                                                      |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Mandated: Support for this TID is mandated for Nodes that support Data Endpoints.                                                                           |
+-----------------------------------------------------------------------------------------+-------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                  | Node Mandated: Yes if Data Endpoints supported.                   |
+-----------------------------------------------------------------------------------------+-------------------------------------------------------------------+
| Sender Mandated: No.                                                                    | Visualiser Mandated: No.                                          |
+-----------------------------------------------------------------------------------------+-------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                         |                                                                   |
+-----------------------------------------------------------------------------------------+-------------------------------------------------------------------+

### TID_EP_LABEL

+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the human-readable text label assigned to a specific endpoint.                                                                                                                                    |
+=================================+===========================+===========================+======================================================================================================================================+
| Sent by \| to URI               | Enum                      | Length                    | Value                                                                                                                                |
+---------------------------------+---------------------------+---------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Manager                         | 0x0902                    | 0/1-65                    | \[0\] Encoding: 0x00 = ASCII.                                                                                                        |
|                                 |                           |                           |                                                                                                                                      |
| /manager/{tuid}/{endpoint} Node |                           |                           | \[1-64\] Human-readable endpoint label. Maximum 64 bytes. Not null-terminated. A Node shall store this label in non-volatile memory. |
|                                 |                           |                           |                                                                                                                                      |
| /node/{tuid}/{endpoint}         |                           |                           |                                                                                                                                      |
+---------------------------------+---------------------------+---------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                   | Queryable: Yes                                                                                                                       |
+-----------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                         |
+-----------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                  | Node Mandated: Yes if Data Endpoints supported.                                                                                      |
+-----------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                    | Visualiser Mandated: No.                                                                                                             |
+-----------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                         |                                                                                                                                      |
+-----------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_MULT_OVERRIDE 

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Applies or clears a custom, non-standard multicast IP address for a specific endpoint.                                                                                                                                                                                                                                                                     |
+=================================+=============================+=============================+===========================================================================================================================================================================================================================================================================+
| Sent by \| to URI               | Enum                        | Length                      | Value                                                                                                                                                                                                                                                                     |
+---------------------------------+-----------------------------+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                         | 0x0903                      | 0/4                         | \[0-3\] Multicast IPv4 Address: The specific custom multicast IP this endpoint shall use. A value of 0.0.0.0 (all zero bytes) acts as a clear command, instructing the Node to disable the override and use the default folded pool based on its TID_EP_UNIVERSE setting. |
|                                 |                             |                             |                                                                                                                                                                                                                                                                           |
| /manager/{tuid}/{endpoint} Node |                             |                             |                                                                                                                                                                                                                                                                           |
|                                 |                             |                             |                                                                                                                                                                                                                                                                           |
| /node/{tuid}/{endpoint}         |                             |                             |                                                                                                                                                                                                                                                                           |
+---------------------------------+-----------------------------+-----------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                       | Queryable: Yes                                                                                                                                                                                                                                                            |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                                                                                                                                  |
+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Mandated: Support for this TID is mandated for Nodes that support Multicast IP Override.                                                                                                                                                                                                                                                                                |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                      | Node Mandated: Yes if Multicast IP override supported.                                                                                                                                                                                                                    |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                        | Visualiser Mandated: No.                                                                                                                                                                                                                                                  |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                             |                                                                                                                                                                                                                                                                           |
+---------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_CAPABILITY 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the fixed hardware and logical capabilities of the Data Endpoint.                                                                                                                                                                                                                                                                                       |
+==========================================+==========================================+==========================================+=============================================================================================================================================================================================================================================+
| Sent by \| to URI                        | Enum                                     | Length                                   | Value                                                                                                                                                                                                                                       |
+------------------------------------------+------------------------------------------+------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                  | 0x0904                                   | 0/6                                      | \[0-3\] Port Capability bit field:                                                                                                                                                                                                          |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
| /manager/{tuid}/{endpoint} Node          |                                          |                                          | - Bit 0 (0x01): Can Consume TID_LEVEL (Outputs \[DMX512\] or consumes internally).                                                                                                                                                          |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
| /node/{tuid}/{endpoint}                  |                                          |                                          | - Bit 1 (0x02): Can Supply TID_LEVEL (Receives \[DMX512\], transmits Sig-Net).                                                                                                                                                              |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | - Bit 2 (0x04): Can Consume \[RDM\] (Proxies or terminates TID_RDM_COMMAND).                                                                                                                                                                |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | - Bit 3 (0x08): Can Supply \[RDM\] (Receives \[RDM\], transmits Sig-Net).                                                                                                                                                                   |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | - Bit 4 (0x10): Virtual Endpoint (This Endpoint terminates inside the Device and hosts an internal RDM-Responder; it is not a physical \[DMX512\] port).                                                                                    |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | - Bit 5 (0x20): Supports Per-Slot Priority Merging. If set, Node supports full, independent per-slot priority. If clear, Node uses universe priority.                                                                                       |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | - Bits 6-31: Reserved.                                                                                                                                                                                                                      |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | \[4--5\] Maximum Merge Sources: A 16-bit unsigned integer defining the maximum number of simultaneous TID_LEVEL sources this endpoint can merge concurrently. For endpoints capable of consuming TID_LEVEL (Bit 0 set), this value shall be |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | Greater than or equal to 4.                                                                                                                                                                                                                 |
|                                          |                                          |                                          |                                                                                                                                                                                                                                             |
|                                          |                                          |                                          | For endpoints that do not consume TID_LEVEL, this value shall be 0x0000.                                                                                                                                                                    |
+------------------------------------------+------------------------------------------+------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                          | Queryable: Yes                                                                                                                                                                                                                              |
+--------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: Prior to v1.11 of this document the \[4-5\] entry did not exist. Early adopters should accept a payload of length 4 and set Maximum Merge Sources = 4.                                                                                                                                                                                                                |
+--------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                         | Node Mandated: Yes if Data Endpoints supported.                                                                                                                                                                                             |
+--------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                           | Visualiser Mandated: No.                                                                                                                                                                                                                    |
+--------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                |                                                                                                                                                                                                                                             |
+--------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_DIRECTION 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sets or reports whether the endpoint port is actively operating as an input, an output, or is disabled.                                                                                                                                                                                                                      |
+=================================+==============================+==============================+==============================================================================================================================================================================================================================+
| Sent by \| to URI               | Enum                         | Length                       | Value                                                                                                                                                                                                                        |
+---------------------------------+------------------------------+------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                         | 0x0905                       | 0/1                          | \[0\] Port Direction and Feature Bitfield:                                                                                                                                                                                   |
|                                 |                              |                              |                                                                                                                                                                                                                              |
| /manager/{tuid}/{endpoint} Node |                              |                              | Bits 0-1 (Direction):                                                                                                                                                                                                        |
|                                 |                              |                              |                                                                                                                                                                                                                              |
| /node/{tuid}/{endpoint}         |                              |                              | - 00 (0): Disabled (Port is inactive).                                                                                                                                                                                       |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | - 01 (1): Consumer (Receives Sig-Net, outputs physical \[DMX512\]).                                                                                                                                                          |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | - 10 (2): Supplier (Receives physical \[DMX512\], transmits Sig-Net).                                                                                                                                                        |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | - 11 (3): Fallback (Port actively monitors the \[DMX512\] line as an input; if no valid \[DMX512\] signal is detected, the port automatically transitions to a Consumer output to drive a severed \[DMX512\] loop topology). |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | Bit 2 (\[RDM\] Enable):                                                                                                                                                                                                      |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | - 0: \[RDM\] processing disabled on this port.                                                                                                                                                                               |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | - 1: \[RDM\] processing enabled on this port (subject to TID_EP_CAPABILITY).                                                                                                                                                 |
|                                 |                              |                              |                                                                                                                                                                                                                              |
|                                 |                              |                              | Bits 3-7: Reserved.                                                                                                                                                                                                          |
+---------------------------------+------------------------------+------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                         | Queryable: Yes                                                                                                                                                                                                               |
+-----------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes:                                                                                                                                                                                                                                                                                                                       |
+-----------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                        | Node Mandated: Yes if Data Endpoints supported.                                                                                                                                                                              |
+-----------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                          | Visualiser Mandated: No.                                                                                                                                                                                                     |
+-----------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                               |                                                                                                                                                                                                                              |
+-----------------------------------------------------------------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_INPUT_PRIORITY 

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the per-slot priority values that an input port will assign to incoming \[DMX512\] data.                                                                                                                                                                                                                                           |
+==================================================================+==================================================================+==================================================================+========================================================================================================================================================+
| Sent by \| to URI                                                | Enum                                                             | Length                                                           | Value                                                                                                                                                  |
+------------------------------------------------------------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                                          | 0x0906                                                           | 0/1-512                                                          | \[0-511\] Defines the \[ETC 0xDD\] Priority value (0-200) this endpoint will assign to its network transmissions when TID_EP_DIRECTION is set to Input |
|                                                                  |                                                                  |                                                                  |                                                                                                                                                        |
| /manager/{tuid}/{endpoint} Node                                  |                                                                  |                                                                  |                                                                                                                                                        |
|                                                                  |                                                                  |                                                                  |                                                                                                                                                        |
| /node/{tuid}/{endpoint}                                          |                                                                  |                                                                  |                                                                                                                                                        |
+------------------------------------------------------------------+------------------------------------------------------------------+------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                  | Queryable: Yes                                                                                                                                         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: If payload length is 1, the single byte value shall be applied to all 512 priority slots. If length \> 1, the bytes map sequentially to the priority slots starting at slot 1. Any remaining unaddressed priority slots (up to 512) shall be set to 0.                                                                                                   |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                                  | Node Mandated: No.                                                                                                                                     |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                   | Visualiser Mandated: No.                                                                                                                               |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                                                                                                                                        |                                                                                                                                                        |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_STATUS 

+------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Reports a live status bitfield detailing the current data activity and fault state of the endpoint port.                                                         |
+=================================+============================+============================+======================================================================+
| Sent by \| to URI               | Enum                       | Length                     | Value                                                                |
+---------------------------------+----------------------------+----------------------------+----------------------------------------------------------------------+
| Manager                         | 0x0907                     | 0/4                        | \[0-3\] A 32-bit bitfield representing endpoint health and status.   |
|                                 |                            |                            |                                                                      |
| /manager/{tuid}/{endpoint} Node |                            |                            | Bit 0: This endpoint is actively transmitting or receiving.          |
|                                 |                            |                            |                                                                      |
| /node/{tuid}/{endpoint}         |                            |                            | Bit 1: Hardware fault.                                               |
|                                 |                            |                            |                                                                      |
|                                 |                            |                            | Bit 2: Configuration locked via local UI.                            |
|                                 |                            |                            |                                                                      |
|                                 |                            |                            | Bit 3: This endpoint is receiving TID_LEVEL.                         |
|                                 |                            |                            |                                                                      |
|                                 |                            |                            | Bit 4: This endpoint is receiving more than one stream of TID_LEVEL. |
|                                 |                            |                            |                                                                      |
|                                 |                            |                            | Bit 5: This endpoint is in Fallback mode.                            |
|                                 |                            |                            |                                                                      |
|                                 |                            |                            | Bit 6: This endpoint is in Failover mode.                            |
|                                 |                            |                            |                                                                      |
|                                 |                            |                            | Bits 7-31: Reserved.                                                 |
+---------------------------------+----------------------------+----------------------------+----------------------------------------------------------------------+
| Target Endpoint: Data                                                                     | Queryable: Yes                                                       |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------------+
| Notes:                                                                                                                                                           |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                    | Node Mandated: Yes if Data Endpoints supported.                      |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------------+
| Sender Mandated: No.                                                                      | Visualiser Mandated: No.                                             |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------------+
| Persistent: No.                                                                           |                                                                      |
+-------------------------------------------------------------------------------------------+----------------------------------------------------------------------+

### TID_EP_FAILOVER 

+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the data-loss failover behaviour for a specific data endpoint. Defines the physical output state if the network stream is lost (as defined by \<universe_lost_timeout\>).                                                                                                                                                                                                                                                 |
+=====================================================+=====================================================+=====================================================+======================================================================================================================================================================================================================================================================================+
| Sent by \| to URI                                   | Enum                                                | Length                                              | Value                                                                                                                                                                                                                                                                                |
+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                             | 0x0908                                              | 0/3                                                 | \[0\] Failover Mode:                                                                                                                                                                                                                                                                 |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
| /manager/{tuid}/{endpoint} Node                     |                                                     |                                                     | - 0x00: Hold Last State.                                                                                                                                                                                                                                                             |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
| /node/{tuid}/{endpoint}                             |                                                     |                                                     | - 0x01: Blackout (All slots to 0).                                                                                                                                                                                                                                                   |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
|                                                     |                                                     |                                                     | - 0x02: Full (All slots to 255).                                                                                                                                                                                                                                                     |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
|                                                     |                                                     |                                                     | - 0x03: Play Scene (Execute internal preset/scene).                                                                                                                                                                                                                                  |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
|                                                     |                                                     |                                                     | - 0x04: Stop generating \[DMX512\].                                                                                                                                                                                                                                                  |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
|                                                     |                                                     |                                                     | - 0x05-0xFF: Reserved.                                                                                                                                                                                                                                                               |
|                                                     |                                                     |                                                     |                                                                                                                                                                                                                                                                                      |
|                                                     |                                                     |                                                     | \[1-2\] Scene Number: A 16-bit unsigned integer defining the internal preset or scene to execute when Mode is 0x03. Valid range is 1 to 65,535. (If Mode is not 0x03, these bytes shall be ignored by the Node but must still be transmitted to maintain the 3-byte payload length). |
+-----------------------------------------------------+-----------------------------------------------------+-----------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                           | Queryable: Yes                                                                                                                                                                                                                                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: Nodes that do not support internal scenes shall silently reject SET commands specifying Mode 0x03.                                                                                                                                                                                                                                                                                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                           | Node Mandated: No.                                                                                                                                                                                                                                                                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                            | Visualiser Mandated: No.                                                                                                                                                                                                                                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                                                                                                 |                                                                                                                                                                                                                                                                                      |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_DMX_TIMING 

+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the physical DMX512 transmission timing and update mode for a specific output port.                                                                                                                                                                                                                       |
+=======================================================+=======================================================+=======================================================+================================================================================================================================================================+
| Sent by \| to URI                                     | Enum                                                  | Length                                                | Value                                                                                                                                                          |
+-------------------------------------------------------+-------------------------------------------------------+-------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                               | 0x0909                                                | 0/2                                                   | \[0\] Transmission Mode:                                                                                                                                       |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
| /manager/{tuid}/{endpoint} Node                       |                                                       |                                                       | - 0x00: Continuous (The port continuously transmits \[DMX512\] frames at the configured framerate, regardless of whether slot data has changed).               |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
| /node/{tuid}/{endpoint}                               |                                                       |                                                       | - 0x01: Delta / Change-Only (The port only transmits \[DMX512\] frames when the underlying Sig-Net slot data changes, or to satisfy the 1 Hz keep-alive rule). |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
|                                                       |                                                       |                                                       | - 0x02-0xFF: Reserved.                                                                                                                                         |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
|                                                       |                                                       |                                                       | \[1\] Output Timing:                                                                                                                                           |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
|                                                       |                                                       |                                                       | - 0x00: Maximum DMX512 timing and refresh rate.                                                                                                                |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
|                                                       |                                                       |                                                       | - 0x01: Medium DMX512 timing and refresh rate.                                                                                                                 |
|                                                       |                                                       |                                                       |                                                                                                                                                                |
|                                                       |                                                       |                                                       | - 0x02: Minimum DMX512 timing and refresh rate.                                                                                                                |
+-------------------------------------------------------+-------------------------------------------------------+-------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                 | Queryable: Yes                                                                                                                                                 |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Notes: Nodes that only support fixed continuous output shall silently ignore SET commands attempting to change the Transmission Mode or Framerate, but must accurately report their fixed state if queried.                                                                                                                            |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                 | Node Mandated: No.                                                                                                                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                  | Visualiser Mandated: No.                                                                                                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                                                                                                       |                                                                                                                                                                |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_REFRESH_CAPABILITY 

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the maximum physical refresh rate (in frames per second) that the endpoint\'s hardware can output.                                                                                                                                                                                                                   |
+==================================================================+==================================================================+==================================================================+==================================================================================================================================+
| Sent by \| to URI                                                | Enum                                                             | Length                                                           | Value                                                                                                                            |
+------------------------------------------------------------------+------------------------------------------------------------------+------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Manager                                                          | 0x090A                                                           | 0/1                                                              | \[0\] An 8-bit unsigned integer representing the maximum supported framerate.                                                    |
|                                                                  |                                                                  |                                                                  |                                                                                                                                  |
| /manager/{tuid}/{endpoint} Node                                  |                                                                  |                                                                  | - 0 - 44: The endpoint supports the standard \[DMX512\] maximum of 44Hz. (Nodes shall NOT declare a capability lower than 44Hz). |
|                                                                  |                                                                  |                                                                  |                                                                                                                                  |
| /node/{tuid}/{endpoint}                                          |                                                                  |                                                                  | - 45 - 250: The endpoint supports high-speed output (e.g. for SPI LED tape) up to the specified framerate.                       |
|                                                                  |                                                                  |                                                                  |                                                                                                                                  |
|                                                                  |                                                                  |                                                                  | - 251 - 255: Reserved.                                                                                                           |
+------------------------------------------------------------------+------------------------------------------------------------------+------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                  | Queryable: Yes                                                                                                                   |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Notes: This is a read-only hardware capability report. It does not configure the network stream rate. Managers may use this value to warn operators if a Sender is configured to transmit a universe faster than the consuming Node can physically output.                                                                                |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                                  | Node Mandated: No. (Defaults to 44Hz if unsupported).                                                                            |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                   | Visualiser Mandated: No.                                                                                                         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                        |                                                                                                                                  |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------------+

### TID_EP_PROTOCOL 

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Sets or reports the active network protocol from which this endpoint consumes its lighting level data.                                                                                                                                                                                                                                                                                                           |
+=======================================================================================================+=======================================================================================================+=======================================================================================================+=======================================================================================================+
| Sent by \| to URI                                                                                     | Enum                                                                                                  | Length                                                                                                | Value                                                                                                 |
+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+
| Manager                                                                                               | 0x090B                                                                                                | 0/1                                                                                                   | \[0\] Enumerated value:                                                                               |
|                                                                                                       |                                                                                                       |                                                                                                       |                                                                                                       |
| /manager/{tuid}/{endpoint} Node                                                                       |                                                                                                       |                                                                                                       | 0x00: Sig-Net (Default).                                                                              |
|                                                                                                       |                                                                                                       |                                                                                                       |                                                                                                       |
| /node/{tuid}/{endpoint}                                                                               |                                                                                                       |                                                                                                       | 0x01: Art-Net 4.                                                                                      |
|                                                                                                       |                                                                                                       |                                                                                                       |                                                                                                       |
|                                                                                                       |                                                                                                       |                                                                                                       | 0x02: sACN.                                                                                           |
|                                                                                                       |                                                                                                       |                                                                                                       |                                                                                                       |
|                                                                                                       |                                                                                                       |                                                                                                       | 0x03-0xff: Reserved.                                                                                  |
+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                                                                                                                                 | Queryable: Yes                                                                                        |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+
| Notes: This TID determines which protocol stream the endpoint actively forwards to its physical/virtual \[DMX512\] output. Regardless of the active protocol selected for level data, the Node shall maintain its active Sig-Net Control Plane and process authenticated Sig-Net Management commands.                                                                                                                         |
|                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Regardless of the active protocol selected for level data, the Node shall maintain its active Sig-Net Control Plane and process authenticated Sig-Net Management commands. Switching an endpoint to a legacy protocol removes cryptographic authentication from the level data stream; Managers shall warn operators and require confirmation before applying such a configuration change to a Secure Node.                   |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                                                                                                                                                                                | Node Mandated: No.                                                                                    |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                                                                                                                                  | Visualiser Mandated: No.                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+
| Persistent: Yes. Stored in NVR.                                                                                                                                                                                                                                                                                       |                                                                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-------------------------------------------------------------------------------------------------------+

### TID_EP_IDENTIFY 

+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Commands the Device to visually or audibly identify a specific data endpoint.                                                                                                                                                                                                                                                 |
+=======================================================================+=======================================================================+=======================================================================+====================================================================================================================+
| Sent by \| to URI                                                     | Enum                                                                  | Length                                                                | Value                                                                                                              |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------+-----------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Manager                                                               | 0x090C                                                                | 0/1                                                                   | \[0\] Identify State:                                                                                              |
|                                                                       |                                                                       |                                                                       |                                                                                                                    |
| /manager/{tuid}/{endpoint} Node                                       |                                                                       |                                                                       | 0x00: Identify off. Normal operation.                                                                              |
|                                                                       |                                                                       |                                                                       |                                                                                                                    |
| /node/{tuid}/{endpoint}                                               |                                                                       |                                                                       | 0x01: Identify Subtle. Causes the Device to identify itself in a subtle way that could be used in show conditions. |
|                                                                       |                                                                       |                                                                       |                                                                                                                    |
|                                                                       |                                                                       |                                                                       | 0x02: Identify Full. Causes the Device to identify itself in an obvious way.                                       |
+-----------------------------------------------------------------------+-----------------------------------------------------------------------+-----------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                                                 | Queryable: Yes                                                                                                     |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Notes: The Identify state shall be stored in volatile memory (RAM) only and shall default to 0x00 (Off) upon Device initialisation. It operates independently of the global TID_RT_IDENTIFY state.                                                                                                                                         |
|                                                                                                                                                                                                                                                                                                                                            |
| Global Mute Interaction: If the Device\'s Root Endpoint is currently set to Mute (TID_RT_IDENTIFY = 0x03), the Node shall accept and store the TID_EP_IDENTIFY state change in RAM, but shall suppress the physical indicator until the global Mute state is cleared.                                                                      |
|                                                                                                                                                                                                                                                                                                                                            |
| Hardware Limitation: If the physical hardware lacks an independent indicator for a specific endpoint, the Node shall accept the command and accurately report its requested state when queried, but shall take no physical action. It shall not map this command to TID_RT_IDENTIFY.                                                       |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                                                 | Node Mandated: No.                                                                                                 |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                                  | Visualiser Mandated: No.                                                                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                       |                                                                                                                    |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------------------------------------------------------------+

[\
]{.mark}

## Diagnostic Endpoint Type Identifiers

The Type Identifiers in this section are used for diagnostics and testing.

### TID_DG_SECURITY_EVENT

+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports security events.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
+============================================================================================================================+============================================================================================================================+============================================================================================================================+===========================================================================================================================================================+
| Sent by \| to URI                                                                                                          | Enum                                                                                                                       | Length                                                                                                                     | Value                                                                                                                                                     |
+----------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager                                                                                                                    | 0xFF01                                                                                                                     | 0/7/11/23                                                                                                                  | \[0-1\] Event Code:                                                                                                                                       |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
| /manager/{tuid}/0                                                                                                          |                                                                                                                            |                                                                                                                            | - 0x0001: HMAC Verification Failure.                                                                                                                      |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
| Node                                                                                                                       |                                                                                                                            |                                                                                                                            | - 0x0002: Replay Attack Detected (Sequence/Session ID anomaly).                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
| /node/{tuid}/0                                                                                                             |                                                                                                                            |                                                                                                                            | - 0x0003: DoS Rate-Limiting Activated.                                                                                                                    |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | - 0x0004: Unauthorised Onboarding Attempt.                                                                                                                |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | - 0x0005: Sender Table Saturated. Triggered when a 33rd Sender tries to connect and the LRU entries are all less than 1 hour old.                         |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | - 0x0006: Cryptographic Epoch Regression. Triggered when a known TUID sends a lower Session ID than previously recorded.                                  |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | - 0x0007: Sequence Contiguity Violation. Triggered when the Session ID is correct, but the Sequence Number is lower than or equal to the stored value.    |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | - 0x0008: Failed Offboard. Triggered when a device receives an attempt to offboard that is rejected due to \<offboard_lockout\> expiry.                   |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | \[2-5\] Event Counter: A 32-bit unsigned integer representing the total number of times this event has occurred since the Device initialized (RAM-based). |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | \[6\] Address Type: 0x00=None, 0x01=IPv4, 0x02=IPv6.                                                                                                      |
|                                                                                                                            |                                                                                                                            |                                                                                                                            |                                                                                                                                                           |
|                                                                                                                            |                                                                                                                            |                                                                                                                            | \[7-n\] Source IP Address: The IP address of the most recent packet that triggered this event. (0bytes if None, 4 bytes if IPv4, 16 bytes if IPv6).       |
+----------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                                                                                                                                                                                                                                | Queryable: Yes                                                                                                                                            |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| Note: A Device shall unilaterally multicast this TID upon detecting a qualifying security event. To prevent network flooding during a sustained attack, Nodes shall aggressively rate-limit the transmission of this TID (recommended maximum: 1 packet per second per Event Code). When a Manager gets this TID (Length = 0), the Node shall respond by sequentially packing multiple TID_DG_SECURITY_EVENT TLVs into the reply packet, providing one TLV for each Event Code it actively tracks.                                               |
|                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| (Informative Note for Managers: Because UDP source IP addresses are trivially spoofed, the IP address reported in this payload should be treated as a diagnostic indicator rather than absolute proof of an attacker\'s location).                                                                                                                                                                                                                                                                                                               |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: Yes.                                                                                                                                                                                                                                                                                                                                                               | Node Mandated: Yes.                                                                                                                                       |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: Yes.                                                                                                                                                                                                                                                                                                                                                                | Visualiser Mandated: Yes.                                                                                                                                 |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                                                                                                                                                                                      |                                                                                                                                                           |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------+

### TID_DG_MESSAGE

+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the human-readable diagnostic message.                                                                                                                                                                                                                                                                               |
+================================================================================+================================================================================+================================================================================+========================================================================================+
| Sent by \| to URI                                                              | Enum                                                                           | Length                                                                         | Value                                                                                  |
+--------------------------------------------------------------------------------+--------------------------------------------------------------------------------+--------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| Node                                                                           | 0xFF02                                                                         | 0-64                                                                           | ASCII encoded human-readable diagnostic message. Strings shall NOT be null-terminated. |
|                                                                                |                                                                                |                                                                                |                                                                                        |
| /node/{tuid}/0                                                                 |                                                                                |                                                                                |                                                                                        |
+--------------------------------------------------------------------------------+--------------------------------------------------------------------------------+--------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| Target Endpoint: Root                                                                                                                                                                                                                            | Queryable: Yes                                                                         |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| Notes: A Node proactively multicasts a diagnostic message to \<mult_node_send\> to alert all listening Managers of a significant internal event (e.g. hardware faults, thermal warnings, or port errors).                                                                                                                                 |
|                                                                                                                                                                                                                                                                                                                                           |
| Rate Limit: To prevent a recurring hardware or software fault from generating a multicast storm that congests the management network, Nodes shall aggressively rate-limit the autonomous transmission of TID_DG_MESSAGE payloads (e.g. to a maximum of one message every 5 seconds per unique fault condition).                           |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                                                                            | Node Mandated: No.                                                                     |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                                                                             | Visualiser Mandated: No.                                                               |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                                                                                  |                                                                                        |
+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+----------------------------------------------------------------------------------------+

### TID_DG_LEVEL_FOLDBACK 

+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Description: Reports the levels for a specific universe.                                                                                                                                                                                                                                                                    |
+===============================================================+===============================================================+===============================================================+=============================================================================================================================+
| Sent by \| to URI                                             | Enum                                                          | Length                                                        | Value                                                                                                                       |
+---------------------------------------------------------------+---------------------------------------------------------------+---------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Manager                                                       | 0xFF03                                                        | 0/1-512                                                       | \[0-511\] Copy of the current 512-byte \[DMX512\] level buffer actively being processed or generated by this Data Endpoint. |
|                                                               |                                                               |                                                               |                                                                                                                             |
| /manager/{tuid}/{endpoint} Node /node/{tuid}/{endpoint}       |                                                               |                                                               |                                                                                                                             |
+---------------------------------------------------------------+---------------------------------------------------------------+---------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Target Endpoint: Data                                                                                                                                                                         | Queryable: Yes                                                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Notes: If a Node is queried for this TID but its internal \[DMX512\] buffer is currently empty or uninitialised (e.g. following a reboot), the Node shall reply with length = 1 and data = 0. It shall not transmit a zero-length response.                                                                                 |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Mandated: Support for this TID is mandated for Nodes that support Data Endpoints.                                                                                                                                                                                                                                           |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Manager Mandated: No.                                                                                                                                                                         | Node Mandated: Yes if Data Endpoints supported.                                                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Sender Mandated: No.                                                                                                                                                                          | Visualiser No.                                                                                                              |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+
| Persistent: No.                                                                                                                                                                               |                                                                                                                             |
+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------+

[\
]{.mark}

## TID Polling Cross Reference

This table provides a master summary of all Type Identifiers (TIDs) defined in this specification.

The QUERY_LEVEL column defines how a Node handles the TID when it receives a TID_POLL command (Section [11.1.1](#tid_poll)):

- Categories (0x00 to 0x03): The TID shall be packed into the Node\'s bulk poll response if the Manager requests that level or higher.

- None (Get Only): The TID is Queryable via a direct Parameter Query (GET) with a Length = 0 header, but it shall not be included in any bulk TID_POLL responses.

- N/A (Not Queryable): The TID represents a write-only command, a proactive state push, or a unidirectional data stream. It cannot be queried.

  -------------------------------------------------------------------------------------
  **TID Name**                **Enum**   **Target Endpoint**   **QUERY_LEVEL**
  --------------------------- ---------- --------------------- ------------------------
  TID_POLL_REPLY              0x0002     Root & Data           QUERY_HEARTBEAT (0x00)

  TID_RT_ENDPOINT_COUNT       0x0602     Root                  QUERY_HEARTBEAT (0x00)

  TID_RT_MULT_OVERRIDE        0x0606     Root                  QUERY_HEARTBEAT (0x00)

  TID_RDM_EP_CONFIG           0x0305     Data                  QUERY_CONFIG (0x01)

  TID_RDM_FLOW_CONTROL        0x0306     Data                  QUERY_CONFIG (0x01)

  TID_RT_DEVICE_LABEL         0x0605     Root                  QUERY_CONFIG (0x01)

  TID_RT_IDENTIFY             0x0607     Root                  QUERY_CONFIG (0x01)

  TID_RT_STATUS               0x0608     Root                  QUERY_CONFIG (0x01)

  TID_EP_UNIVERSE             0x0901     Data                  QUERY_CONFIG (0x01)

  TID_EP_LABEL                0x0902     Data                  QUERY_CONFIG (0x01)

  TID_EP_MULT_OVERRIDE        0x0903     Data                  QUERY_CONFIG (0x01)

  TID_EP_CAPABILITY           0x0904     Data                  QUERY_CONFIG (0x01)

  TID_EP_DIRECTION            0x0905     Data                  QUERY_CONFIG (0x01)

  TID_EP_INPUT_PRIORITY       0x0906     Data                  QUERY_CONFIG (0x01)

  TID_EP_STATUS               0x0907     Data                  QUERY_CONFIG (0x01)

  TID_EP_FAILOVER             0x0908     Data                  QUERY_CONFIG (0x01)

  TID_EP_DMX_TIMING           0x0909     Data                  QUERY_CONFIG (0x01)

  TID_EP_REFRESH_CAPABILITY   0x090A     Data                  QUERY_CONFIG (0x01)

  TID_EP_PROTOCOL             0x090B     Data                  QUERY_CONFIG (0x01)

  TID_EP_IDENTIFY             0x090C     Data                  QUERY_CONFIG (0x01)

  TID_RT_SUPPORTED_TIDS       0x0601     Root                  QUERY_FULL (0x02)

  TID_RT_PROTOCOL_VERSION     0x0603     Root                  QUERY_FULL (0x02)

  TID_RT_FIRMWARE_VERSION     0x0604     Root                  QUERY_FULL (0x02)

  TID_RT_ROLE_CAPABILITY      0x0609     Root                  QUERY_FULL (0x02)

  TID_RT_MODEL_NAME           0x060B     Root                  QUERY_FULL (0x02)

  TID_RT_OTW_CAPABILITY       0x060D     Root                  QUERY_FULL (0x02)

  TID_NW_MAC_ADDRESS          0x0501     Root                  QUERY_FULL (0x02)

  TID_NW_IPV4_MODE            0x0502     Root                  QUERY_FULL (0x02)

  TID_NW_IPV4_ADDRESS         0x0503     Root                  QUERY_FULL (0x02)

  TID_NW_IPV4_NETMASK         0x0504     Root                  QUERY_FULL (0x02)

  TID_NW_IPV4_GATEWAY         0x0505     Root                  QUERY_FULL (0x02)

  TID_NW_IPV4_CURRENT         0x0506     Root                  QUERY_FULL (0x02)

  TID_NW_IPV6_MODE            0x0581     Root                  QUERY_FULL (0x02)

  TID_NW_IPV6_ADDRESS         0x0582     Root                  QUERY_FULL (0x02)

  TID_NW_IPV6_PREFIX          0x0583     Root                  QUERY_FULL (0x02)

  TID_NW_IPV6_GATEWAY         0x0584     Root                  QUERY_FULL (0x02)

  TID_NW_IPV6_CURRENT         0x0585     Root                  QUERY_FULL (0x02)

  TID_DG_SECURITY_EVENT       0xFF01     Root                  QUERY_EXTENDED (0x03)

  TID_DG_MESSAGE              0xFF02     Root & Data           QUERY_EXTENDED (0x03)

  TID_POLL                    0x0001     Root & Data           N/A (Not Queryable)

  TID_SET_REPLY               0x0003     Root & Data           N/A (Not Queryable)

  TID_LEVEL                   0x0101     Data                  N/A (Not Queryable)

  TID_PRIORITY                0x0102     Data                  N/A (Not Queryable)

  TID_PREVIEW                 0x0103     Data                  N/A (Not Queryable)

  TID_SYNC                    0x0201     Data                  N/A (Not Queryable)

  TID_TIMECODE                0x0202     Data                  N/A (Not Queryable)

  TID_UNIVERSE                0x0203     Data                  N/A (Not Queryable)

  TID_OSC                     0x0204     Root & Data           N/A (Not Queryable)

  TID_RDM_COMMAND             0x0301     Root\* & Data         N/A (Not Queryable)

  TID_RDM_RESPONSE            0x0302     Root\* & Data         N/A (Not Queryable)

  TID_RDM_TOD_CONTROL         0x0303     Data                  N/A (Not Queryable)

  TID_RDM_TOD_DATA            0x0304     Data                  N/A (Not Queryable)

  TID_RT_OFFBOARD             0x0401     Root                  N/A (Not Queryable)

  TID_RT_REBOOT               0x060A     Root                  N/A (Not Queryable)

  TID_DG_LEVEL_FOLDBACK       0xFF03     Data                  None (Get Only)
  -------------------------------------------------------------------------------------

[\
]{.mark}

## TID Informative Summary

+---------------------------+----------+---------------------+------------------------------------------------------+
| ** **                     | ** **    | ** **               | **Mandated**                                         |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| **TID Name**              | **Enum** | **Target Endpoint** | **Manager** | **Node** | **Sender** | **Visualiser** |
+===========================+==========+=====================+=============+==========+============+================+
| TID_POLL                  | 0x0001   | Root & Data         | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_POLL_REPLY            | 0x0002   | Root & Data         | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_SET_REPLY             | 0x0003   | Root & Data         | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_LEVEL                 | 0x0101   | Data                | No          | Yes\*    | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_PRIORITY              | 0x0102   | Data                | No          | No       | No         | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_PREVIEW               | 0x0103   | Data                | No          | No       | No         | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_SYNC                  | 0x0201   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_TIMECODE              | 0x0202   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_UNIVERSE              | 0x0203   | Data                | No          | No       | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_OSC                   | 0x0204   | Root & Data         | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RDM_COMMAND           | 0x0301   | Root\*^2^ & Data    | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RDM_RESPONSE          | 0x0302   | Root\*^2^ & Data    | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RDM_TOD_CONTROL       | 0x0303   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RDM_TOD_DATA          | 0x0304   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RDM_EP_CONFIG         | 0x0305   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RDM_FLOW_CONTROL      | 0x0306   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_OFFBOARD           | 0x0401   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_MAC_ADDRESS        | 0x0501   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV4_MODE          | 0x0502   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV4_ADDRESS       | 0x0503   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV4_NETMASK       | 0x0504   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV4_GATEWAY       | 0x0505   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV4_CURRENT       | 0x0506   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV6_MODE          | 0x0581   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV6_ADDRESS       | 0x0582   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV6_PREFIX        | 0x0583   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV6_GATEWAY       | 0x0584   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_NW_IPV6_CURRENT       | 0x0585   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_SUPPORTED_TIDS     | 0x0601   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_ENDPOINT_COUNT     | 0x0602   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_PROTOCOL_VERSION   | 0x0603   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_FIRMWARE_VERSION   | 0x0604   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_DEVICE_LABEL       | 0x0605   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_MULT_OVERRIDE      | 0x0606   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_IDENTIFY           | 0x0607   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_STATUS             | 0x0608   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_ROLE_CAPABILITY    | 0x0609   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_REBOOT             | 0x060A   | Root                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_MODEL_NAME         | 0x060B   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_RT_OTW_CAPABILITY     | 0x060D   | Root                | Yes\*^1^    | Yes\*^1^ | Yes\*^1^   | Yes\*^1^       |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_UNIVERSE           | 0x0901   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_LABEL              | 0x0902   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_MULT_OVERRIDE      | 0x0903   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_CAPABILITY         | 0x0904   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_DIRECTION          | 0x0905   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_INPUT_PRIORITY     | 0x0906   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_STATUS             | 0x0907   | Data                | Yes         | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_FAILOVER           | 0x0908   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_DMX_TIMING         | 0x0909   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_REFRESH_CAPABILITY | 0x090A   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_PROTOCOL           | 0x090B   | Data                | Yes         | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_EP_IDENTIFY           | 0x090C   | Data                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_DG_SECURITY_EVENT     | 0xFF01   | Root                | Yes         | Yes      | Yes        | Yes            |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_DG_MESSAGE            | 0xFF02   | Both                | No          | No       | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+
| TID_DG_LEVEL_FOLDBACK     | 0xFF03   | Data                | No          | Yes\*^1^ | No         | No             |
+---------------------------+----------+---------------------+-------------+----------+------------+----------------+

\*1 Conditional -- refer to detailed TID definition above.

\*2 Root Endpoint Limitation: TID_RDM_COMMAND payloads directed to the Root Endpoint are limited to firmware updates, conditional upon the Device declaring Root_Firmware_Support. All other \[RDM\] commands shall be ignored.

# Protocol Versioning and Compatibility

The Sig-Net protocol uses a Major.Minor versioning scheme.

- Major Version: Defines the core architectural framework, including the URI prefix (e.g. /v1/), Key Derivation Function (KDF) info strings and HMAC calculation methodology. A change in the Major version represents a breaking change.

- Minor Version: Defines non-breaking extensions, such as the addition of new Type Identifiers (TIDs). A change in the Minor version does not alter the URI prefix or cryptographic foundations.

## Document and URI Relationship

The Major number of this specification (e.g. V1.x) shall correspond to the version component of the CoAP URI-Path (e.g. /sig-net/v1/\<scope\>/\...).

## Node Versioning Requirements 

A Node shall report its supported Major version in the TID_RT_PROTOCOL_VERSION TLV.

A Node shall inspect the version component of the URI-Path for every incoming packet. If the URI version does not match the Node\'s supported Major version, the Node shall silently discard the packet without attempting further parsing or cryptographic verification.

A Node shall not attempt to interpret or process packets belonging to a higher Major version than it supports.

## Manager Compatibility Requirements (Normative)

To ensure system-wide interoperability in mixed-version environments, Managers shall adhere to the following:

- Version Discovery: A Manager shall be capable of discovering Nodes of its own Major version and at least one previous Major version (if applicable).

- Discovery Broadcasts: To fulfil the discovery requirement, a Manager shall independently multicast network-wide discovery requests (TID_POLL) to the Discovery URI of its native Major version (e.g. /sig-net/v2/poll) and to the Discovery URI of the supported legacy version (e.g. /sig-net/v1/poll).

- Multi-Stack Communication: When communicating with a discovered legacy Node, the Manager shall use the specific URI prefix, KDF strings and HMAC calculation rules natively associated with that Node's Major version for all targeted communication.

## Sender Compatibility Requirements

Sender traffic (e.g. TID_LEVEL, TID_SYNC, TID_TIMECODE) is transmitted globally via multicast, Senders are not required to individually track the Major versions of the Nodes actively consuming their streams.

A Sender shall transmit its payload using its native Major protocol version and the corresponding URI prefix (e.g. /sig-net/v2/level/).

Mixed-Version Environments: In environments containing legacy Nodes, a Sender transmitting a higher Major version will not be decoded by lower-version Nodes (as required by Section [12.2](#node-versioning-requirements)). To ensure interoperability in mixed-version deployments, Senders should provide a user-configurable option to support legacy Major versions. Senders may support legacy networks by either globally downgrading their transmission version, or by dual-casting payloads to both the native and legacy URIs simultaneously (e.g. transmitting a TID_LEVEL to /v2/level/1 and /v1/level/1). When generating legacy traffic, the Sender shall use the exact URI prefix, KDF strings and HMAC methodology defined by that legacy Major version.

# Example Sig-Net Transaction (Informative) 

This section provides guidance and flowcharts to describe how to implement Sig-Net functionality.

## Sig-Net Device Discovery

A Sig-Net Device is any network Device that communicates natively with Sig-Net (e.g. a moving light, dimmer rack, or \[DMX512\] gateway). Device-discovery is the continuous background process by which a Manager finds all active Sig-Net Nodes on the network and tracks their configuration state.

The flowchart below demonstrates a routine polling cycle using the dedicated administrative multicast addresses.

![[]{#_Toc240901080 .anchor}Figure 10 Example TID Polling Cycle](media/image11.png){width="6.268055555555556in" height="5.589583333333334in"}

Message Flow

1)  The Poll: The Manager initiates Device-discovery by sending a CoAP NON POST to /sig-net/\<version\>/\<scope\>/poll. It includes a TID_POLL block. Because QUERY_LEVEL=QUERY_HEARTBEAT, it is only asking for TID_POLL_REPLY.

2)  The Reply: Every Device whose TUID falls within the requested range waits a random back-off period (to prevent a network storm) and then sends a CoAP NON POST to /sig-net/\<version\>/\<scope\>/node/{tuid}/0. The payload is a TID_POLL_REPLY block containing its TUID, its SoemCode (product identifier) and its current CHANGE_COUNT.

3)  Consistency Check: The Manager logs the Node as \"Online.\" It compares the received CHANGE_COUNT to its internal cache. If the count has increased, the Manager knows the Node's configuration has changed and will follow up with a targeted TID_POLL (QUERY_LEVEL=QUERY_CONFIG) to download the new settings.

## Example Node Endpoint Configuration

The following example demonstrates a Manager configuring Endpoint 1 of a specific Sig-Net Device (TUID: 123456789ABC) to listen to Universe 5. This uses the TID_EP_UNIVERSE Type Identifier (defined in Section [11.7.1](#tid_ep_universe)).

![[]{#_Toc240901081 .anchor}Figure 11 Example Endpoint Configuration](media/image12.png){width="6.268055555555556in" height="5.135416666666667in"}

Message Flow

1)  The Command: The Manager constructs a Sig-Net TLV containing the TID_EP_UNIVERSE Type Identifier with a value of 5. It encapsulates this in a CoAP NON POST message and sends to URI /sig-net/\<version\>/\<scope\>/manager/123456789ABC/1.

2)  Node Processing: The Node receives the packet, validates the HMAC and parses the URI to determine that the command is intended for its own TUID and specifically for Endpoint 1. The Node applies Universe 5 to Endpoint 1\'s configuration and increments its global CHANGE_COUNT by 1.

3)  The Confirmation: To transmit its new state, the Node constructs an identical TLV (TID_EP_UNIVERSE = 5). It transmits this via CoAP NON POST to the URI /sig-net/\<version\>/\<scope\>/node/123456789ABC/1.

4)  Stateless Sync: The originating Manager (and any other Managers passively listening to \<mult_node_send\>) receives the reply, extracts the target TUID and Endpoint from the URI and updates its internal patch sheet to reflect that the Node is now operating on Universe 5.

## Example Multi-Manager Environments 

Sig-Net relies entirely on cryptographic key possession to determine network authority. The following examples illustrate how multiple Managers interact.

### Equal Managers

A Main Console and a Backup Console operate on the same network scope. The Main Console provisions the Backup Console with the Master Root Key (K0). Both consoles now operate as Equal Managers. If the Main Console fails mid-show, the Backup Console possesses K0 and can immediately derive the Km_local keys required to onboard a replacement moving light or re-patch the rig.

### Guest Manager

A Touring Console arrives at a House Venue. The House Technician wishes to grant the tour temporary control of the rig, but prevent the tour from accidentally altering fixture IP addresses or configurations. The House Technician provisions the Touring Console with the derived Guest Keys (Km_global, Ks, Kc) but explicitly withholds the Root Key (K0) and all Node-Specific Manager Keys (Km_local).

The Touring Console operates as a Guest Manager. It can discover the rig via Km_global and transmit \[DMX512\] via Ks, but any attempt to transmit a configuration SET command will fail HMAC verification at the Node, providing a cryptography-enforced Read-Only state.

# Implementation Guidelines (Informative) 

This section provides guidance on miscellaneous concepts that an implementor should consider.

## Hardware Considerations

### Non-Volatile Memory Wear Endurance

The Session ID presents a significant memory endurance consideration. It must be committed to non-volatile memory before the first packet of every new session (see Section [8.3](#security-options)).

Manufacturers are therefore strongly recommended to store the Session ID in high endurance non-volatile memory or use a wear levelling algorithm.

Devices acting as Nodes (Receivers) are not required to use NVM for security tracking, as received state is stored in RAM only (see Section [8.6](#packet-processing-and-replay-attack-prevention)).

### Key Storage Hardware

All derived keys retained by a Sig-Net Device shall be stored in hardware that is resistant to external, physical extraction. Storing derived keys in unprotected, easily accessible external flash memory is not recommended for new product designs.

Legacy Hardware (Informative): It is recognised that legacy entertainment devices use standard, unprotected non-volatile memory (e.g. SPI flash) and lack dedicated cryptographic secure elements. To support the secure adoption of Sig-Net on legacy hardware platforms, manufacturers may store derived keys in standard non-volatile memory, provided they explicitly document this hardware limitation in their cybersecurity risk assessment. Manufacturers declaring this limitation must mandate compensating controls in their user documentation, explicitly requiring that the physical security of the Device (e.g. restricting access to the lighting rig or equipment racks) is maintained to prevent key extraction.

Furthermore, it is recommended that devices lacking dedicated secure elements should encrypt derived keys before committing them to standard non-volatile memory.

Manager Devices: Managers additionally retain the Root Key (K0)---or the plaintext passphrase used to derive it---permanently. Given the extreme sensitivity of K0 and its source material as the sole root of trust for the entire network, manufacturers are strongly encouraged to utilise dedicated Secure Elements, Cryptographic Co-Processors, or hardware-secured enclaves within the primary MCU to isolate these secrets from general application memory.

### Multicast Folding™ Load Scaling

In the default 109-address pool configuration, Sig-Net uses Multicast Folding. For systems using 109 universes or fewer, the mapping is 1:1, resulting in a Discard Load of zero.

For large installations, the universes mathematically fold back over the pool. Because multiple universes share a single multicast group, a Node will naturally receive packets for universes it is not actively consuming. The processing overhead required to parse the CoAP URI and drop these unneeded packets is known as the Discard Load.

At the standard 44Hz transmission rate, a Node assigned to a single universe in a fully loaded 500-universe installation will receive packets for 5 universes (its own, plus 4 folded ones), resulting in a Discard Load of only 4 × 44 = 176 packets per second. Even on a 1,000-universe system, the modulo 109 allocation equation (see Section [9.2.3](#default-multicast-folding-universe-mapping)) caps this Discard Load at 10 × 44 = 440 packets per second. This load is trivial for modern embedded microcontrollers to parse and drop based on the cleartext CoAP URI.

If a specific hardware implementation requires further reduction of the Discard Load, the Manager can use the TID_EP_MULT_OVERRIDE command to re-allocate the Node to an isolated custom multicast group.

## Network Considerations

### CoAP Port Coexistence

Sig-Net uses the standard registered CoAP port \<coap_port\>. In environments where Sig-Net coexists with other CoAP-based systems on the same physical Device, the /sig-net/ URI prefix is used as the application-layer discriminator. Network-level VLAN separation is recommended where Sig-Net traffic coexists with other CoAP protocols on shared infrastructure.

### Multicast Address Exclusivity

The 239.254.0.0/24 block is drawn from the Administratively Scoped range (RFC 2365) and is not globally reserved exclusively for Sig-Net. In deployments where other multicast applications share the same physical network, operators should verify that no address conflicts exist between Sig-Net\'s allocated addresses and those used by other protocols. VLAN segmentation is recommended in shared infrastructure environments to provide additional isolation.

## Manufacturer Specific Extensions

The Sig-Net cryptographic framework is designed to be highly extensible. Manufacturers may use the Sig-Net transport layer to secure their own proprietary protocols.

When transmitting proprietary payloads over the Sig-Net framework, manufacturers shall adhere to the following guidelines to prevent interference with standard Sig-Net devices:

1)  Mfg-Code Flagging: Packets containing proprietary application payloads must include the Sig-Net-Mfg-Code option (Section [8.3](#security-options)) set to the manufacturer\'s specific ESTA ID.

2)  Custom URIs: Proprietary traffic should utilise custom CoAP URI-Paths (e.g. /mfg/1234/sync) rather than the standard /sig-net/\<version\>/\<scope\>/ namespace. This ensures standard nodes drop the packets immediately at the URI Routing Check phase (Section [8.6](#packet-processing-and-replay-attack-prevention), Step 4).

3)  Multicast Isolation: To prevent unnecessary Discard Load, high-bandwidth proprietary traffic (such as continuous console tracking data) should be transmitted to dedicated, manufacturer-selected multicast IP addresses outside of the standard Sig-Net default pools defined in Section [15](#appendix-a-multicast-addresses).

4)  Key Use: Manufacturers should map their proprietary network actors to the standard Sig-Net cryptographic roles. For example, proprietary configuration protocols should be authenticated using Km_local, while proprietary playback or trigger protocols should be authenticated using Ks.

# 

# Appendix A Multicast Addresses 

The following section defines the multicast address allocation based on URI.

+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| **Name**                | **URI**                                                  | **Universe**       | **Key**   | **Multicast**      | **Notes**    |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_node_beacon\>^1^ | /sig-net/\<version\>/\<scope\>/node_beacon/{tuid}/0      | n/a                |           | 239.254.255.255^2^ | Fixed        |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_node_lost\>      | /sig-net/\<version\>/\<scope\>/node_lost/{tuid}/0        | n/a                | Kc        | 239.254.255.254    | Fixed        |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_node_send\>      | /sig-net/\<version\>/\<scope\>/node/{tuid}/{endpoint}    | n/a                | Kc        | 239.254.255.253    | Fixed        |
+=========================+==========================================================+====================+===========+====================+==============+
| \<mult_manager_poll\>   | /sig-net/\<version\>/\<scope\>/poll                      | n/a                | Km_global | 239.254.255.252    | Fixed        |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_manager_send\>   | /sig-net/\<version\>/\<scope\>/manager/{tuid}/{endpoint} | n/a                | Km_local  | 239.254.255.251    | Fixed        |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_time\>           | /sig-net/\<version\>/\<scope\>/sync                      | n/a                | Ks        | 239.254.255.250    | Fixed        |
|                         |                                                          |                    |           |                    |              |
|                         | /sig-net/\<version\>/\<scope\>/timecode/{stream}         |                    |           |                    |              |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_preview\>        | /sig-net/\<version\>/\<scope\>/preview/{stream}          | n/a                | Ks        | 239.254.255.249    | Fixed        |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_aux\>            | /sig-net/\<version\>/\<scope\>/aux/{tuid}/{endpoint}     | n/a                | Ks        | 239.254.255.248    | Fixed        |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_u1\>             | /sig-net/\<version\>/\<scope\>/level/{universe}          | 1, 110, 219 ...    | Ks        | 239.254.0.1        | Programmable |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_u2\>             | /sig-net/\<version\>/\<scope\>/level/{universe}          | 2, 111, 220 ...    | Ks        | 239.254.0.2        | Programmable |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_u3\>             | /sig-net/\<version\>/\<scope\>/level/{universe}          | 3, 112, 221 ...    | Ks        | 239.254.0.3        | Programmable |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| ...                     | ...                                                      | ...                | ...       | ...                | ...          |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_u108\>           | /sig-net/\<version\>/\<scope\>/level/{universe}          | 108, 217, 326 \... | Ks        | 239.254.0.108      | Programmable |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+
| \<mult_u109\>           | /sig-net/\<version\>/\<scope\>/level/{universe}          | 109, 218, 327 ...  | Ks        | 239.254.0.109      | Programmable |
+-------------------------+----------------------------------------------------------+--------------------+-----------+--------------------+--------------+

Note 1: Offboarded devices operating in Beacon Mode transmit to this URI using Security-Mode 0xFF. These packets carry no valid key, and the Sig-Net-Auth option shall be 0 bytes in length. Receivers shall not attempt HMAC verification for packets carrying Security-Mode 0xFF.

Informative Note 2: All Sig-Net multicast addresses are allocated from the 239.254.0.0/24 block within the Administratively Scoped range defined by RFC 2365. This block is intentionally distinct from the 239.255.0.0/16 range used by \[E1.31\] (sACN) to prevent cross-protocol interference.

# 

# Appendix B Definitions 

The following section defines fixed operational parameters referenced symbolically in this specification.

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Name                                Value                   Notes
  ----------------------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  \<poll_backoff_max\>                1000                    Maximum random delay (in ms) before a Node transmits a poll reply.

  \<mult_ttl\>                        32                      Time to Live (TTL) for all Sig-Net traffic

  \<poll_time\>                       3                       Time in seconds between manager polls.

  \<node_lost_timeout\>               3                       Number of missed polls before a Node is considered lost.

  \<coap_port\>                       5683                    

  \<universe_lost_timeout\>           3                       Time in seconds before a Node considers a \[DMX512\] universe stream lost.

  \<offboard_lockout\>                300                     Time in seconds after physical power-up during which a Node will accept an authenticated network wipe command.

  \<sync_lost_timeout\>               250                     Time in milliseconds a Node will wait for a sync packet before reverting to unsynchronised output mode.

  \<ip_rollback_timer\>               60                      Time in seconds a Node waits to detect TID_POLL after an IP change, prior to rollback.

  \<timecode_lost_timeout\>           1                       Time in seconds before a Node considers a Timecode stream lost.

  \<manager_poll_jitter\>             500                     Maximum random delay (in ms) added to the Manager\'s poll interval to prevent collisions.

  \<beacon_min_interval\>             5                       Minimum time in seconds between offboarded beacons.

  \<beacon_timeout\>                  30                      Time in seconds before stale beacon entry removal.

  \<node_processing_max\>             500                     The Manager timeout threshold (in milliseconds) used to schedule retransmissions. Nodes should process commands and transmit replies within this window.

  \<endpoint_spacing_delay\>          1                       Minimum delay (in milliseconds) a Node must insert between transmitting sequential reply packets when responding to an All Endpoints (0xFFFF) query.

  \<universe_announce_interval\>      5                       Time in seconds between periodic TID_UNIVERSE announcements sent by an active Sender.

  \<status_publish_rate\>             1                       Minimum time (in seconds) a Node must wait before proactively multicasting subsequent changes to highly dynamic Status TIDs (e.g. TID_EP_STATUS) on the same endpoint.

  \<on_demand_beacon_interval\>       500                     Time in milliseconds between consecutive beacons during an on-demand burst.

  \<key_rotation_overlap\>            30                      Time in seconds a Node keeps an old key active in memory after receiving a new key via \[SNOW\].

  \<first_packet_bootstrap_window\>   2000                    Time in milliseconds after link-up during which a Device ignores high-privilege configuration commands, preventing post-reboot replay attacks.

  \<rdm_backoff_max\>                 250                     Maximum random delay (in ms) before a Node transmits an RDM response.
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Appendix C Machine-Readable TID Dictionary (Informative)

Below is a JSON dictionary of all Type Identifiers (TIDs) defined in this specification.

The JSON structure defines the Enum, Target Endpoint (Root, Data, or Both), Queryable status, Polling QUERY_LEVEL and the minimum/maximum payload byte lengths (excluding the 4-byte TLV header).

The definitive, maintainable version of this JSON file is hosted in the official Sig-Net GitHub repository.

{

"protocol": "Sig-Net",

"version": "1.01",

"tids": \[

{ "name": "TID_POLL", "enum": "0x0001", "target": "Root & Data", "Queryable": false, "query_level": null, "length_min": 25, "length_max": 25 },

{ "name": "TID_POLL_REPLY", "enum": "0x0002", "target": "Root", "Queryable": false, "query_level": "0x00", "length_min": 12, "length_max": 12 },

{ \"name\": \"TID_SET_REPLY\", \"enum\": \"0x0003\", \"target\": \"Root & Data\", \"Queryable\": false, \"query_level\": null, \"length_min\": 3, \"length_max\": 3 },

{ "name": "TID_LEVEL", "enum": "0x0101", "target": "Data", "Queryable": false, "query_level": null, "length_min": 1, "length_max": 512 },

{ "name": "TID_PRIORITY", "enum": "0x0102", "target": "Data", "Queryable": false, "query_level": null, "length_min": 1, "length_max": 512 },

{ "name": "TID_PREVIEW", "enum": "0x0103", "target": "Data", "Queryable": false, "query_level": null, "length_min": 1, "length_max": 512 },

{ "name": "TID_SYNC", "enum": "0x0201", "target": "Data", "Queryable": false, "query_level": null, "length_min": 0, "length_max": 0 },

{ "name": "TID_TIMECODE", "enum": "0x0202", "target": "Data", "Queryable": false, "query_level": null, "length_min": 5, "length_max": 5 },

{ "name": "TID_UNIVERSE", "enum": "0x0203", "target": "Data", "Queryable": false, "query_level": null, "length_min": 9, "length_max": 9 },

{ "name": "TID_OSC", "enum": "0x0204", "target": "Root & Data", "Queryable": false, "query_level": null, "length_min": 1, "length_max": 255 },

{ "name": "TID_RDM_COMMAND", "enum": "0x0301", "target": "Data", "Queryable": false, "query_level": null, "length_min": 26, "length_max": 257 },

{ "name": "TID_RDM_RESPONSE", "enum": "0x0302", "target": "Data", "Queryable": false, "query_level": null, "length_min": 26, "length_max": 257 },

{ "name": "TID_RDM_TOD_CONTROL", "enum": "0x0303", "target": "Data", "Queryable": false, "query_level": null, "length_min": 1, "length_max": 1 },

{ \"name\": \"TID_RDM_TOD_DATA\", \"enum\": \"0x0304\", \"target\": \"Data\", \"Queryable\": false, \"query_level\": null, \"length_min\": 2, \"length_max\": 1200 },

{ "name": "TID_RDM_EP_CONFIG", "enum": "0x0305", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 1 },

{ "name": "TID_RDM_FLOW_CONTROL", "enum": "0x0306", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 2 },

{ "name": "TID_RT_OFFBOARD", "enum": "0x0401", "target": "Root", "Queryable": false, "query_level": null, "length_min": 4, "length_max": 4 },

{ "name": "TID_NW_MAC_ADDRESS", "enum": "0x0501", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 6 },

{ "name": "TID_NW_IPV4_MODE", "enum": "0x0502", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 1 },

{ "name": "TID_NW_IPV4_ADDRESS", "enum": "0x0503", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 4 },

{ "name": "TID_NW_IPV4_NETMASK", "enum": "0x0504", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 4 },

{ "name": "TID_NW_IPV4_GATEWAY", "enum": "0x0505", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 4 },

{ "name": "TID_NW_IPV4_CURRENT", "enum": "0x0506", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 12 },

{ "name": "TID_NW_IPV6_MODE", "enum": "0x0581", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 1 },

{ "name": "TID_NW_IPV6_ADDRESS", "enum": "0x0582", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 16 },

{ "name": "TID_NW_IPV6_PREFIX", "enum": "0x0583", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 1 },

{ "name": "TID_NW_IPV6_GATEWAY", "enum": "0x0584", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 16 },

{ "name": "TID_NW_IPV6_CURRENT", "enum": "0x0585", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 33 },

{ "name": "TID_RT_SUPPORTED_TIDS", "enum": "0x0601", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 1200 },

{ "name": "TID_RT_ENDPOINT_COUNT", "enum": "0x0602", "target": "Root", "Queryable": true, "query_level": "0x00", "length_min": 0, "length_max": 2 },

{ "name": "TID_RT_PROTOCOL_VERSION", "enum": "0x0603", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 1 },

{ "name": "TID_RT_FIRMWARE_VERSION", "enum": "0x0604", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 68 },

{ "name": "TID_RT_DEVICE_LABEL", "enum": "0x0605", "target": "Root", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 65 },

{ "name": "TID_RT_MULT_OVERRIDE", "enum": "0x0606", "target": "Root", "Queryable": true, "query_level": "0x00", "length_min": 0, "length_max": 1 },

{ "name": "TID_RT_IDENTIFY", "enum": "0x0607", "target": "Root", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 1 },

{ "name": "TID_RT_STATUS", "enum": "0x0608", "target": "Root", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 4 },

{ "name": "TID_RT_ROLE_CAPABILITY", "enum": "0x0609", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 4 },

{ "name": "TID_RT_REBOOT", "enum": "0x060A", "target": "Root", "Queryable": false, "query_level": null, "length_min": 5, "length_max": 5 },

{ "name": "TID_RT_MODEL_NAME", "enum": "0x060B", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 65 },

{ "name": "TID_RT_OTW_CAPABILITY", "enum": "0x060D", "target": "Root", "Queryable": true, "query_level": "0x02", "length_min": 0, "length_max": 3 },

{ "name": "TID_EP_UNIVERSE", "enum": "0x0901", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 2 },

{ "name": "TID_EP_LABEL", "enum": "0x0902", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 65 },

{ "name": "TID_EP_MULT_OVERRIDE", "enum": "0x0903", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 4 },

{ "name": "TID_EP_CAPABILITY", "enum": "0x0904", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 6 },

{ "name": "TID_EP_DIRECTION", "enum": "0x0905", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 1 },

{ "name": "TID_EP_INPUT_PRIORITY", "enum": "0x0906", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 512 },

{ "name": "TID_EP_STATUS", "enum": "0x0907", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 4 },

{ "name": "TID_EP_FAILOVER", "enum": "0x0908", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 3 },

{ "name": "TID_EP_DMX_TIMING", "enum": "0x0909", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 2 },

{ "name": "TID_EP_REFRESH_CAPABILITY", "enum": "0x090A", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 1 },

{ "name": "TID_EP_PROTOCOL", "enum": "0x090B", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 1 },

{ "name": "TID_EP_IDENTIFY", "enum": "0x090C", "target": "Data", "Queryable": true, "query_level": "0x01", "length_min": 0, "length_max": 1 },

{ "name": "TID_DG_SECURITY_EVENT", "enum": "0xFF01", "target": "Root", "Queryable": true, "query_level": "0x03", "length_min": 0, "length_max": 23 },

{ "name": "TID_DG_MESSAGE", "enum": "0xFF02", "target": "Root", "Queryable": true, "query_level": "0x03", "length_min": 0, "length_max": 64 },

{ "name": "TID_DG_LEVEL_FOLDBACK", "enum": "0xFF03", "target": "Data", "Queryable": true, "query_level": null, "length_min": 0, "length_max": 512 }

\]

}

# Appendix D Glossary 

Auxiliary Lane: A dedicated secure communication path designed for non-streaming operational triggers.

Beacon Mode: The operational state of an Offboarded Device. In Beacon Mode, a Device cannot process authenticated network traffic and only transmits unauthenticated, periodic presence beacons (Security-Mode 0xFF) to alert Managers that it requires onboarding.

CHANGE_COUNT: A 16-bit wrap-around counter used to guarantee eventual consistency without requiring reliable transport.

Consumer: An endpoint or Device that receives control data from the Sig-Net network and processes, displays, or translates it into a physical format. A Consumer takes data off the network.

Discard Load: The processing burden placed on a Node by receiving multicast packets for Universes that share its multicast group, but to which the Node itself is not assigned. The Node must parse the CoAP URI of these extraneous packets to determine they are not relevant before discarding them.

Epoch Regression: A security anomaly where a Device transmits a Session ID that is lower than the value previously recorded for its TUID. This typically indicates a failure of the Device to correctly persist its session counter in non-volatile memory.

Gateway (\[DMX512\] Gateway): A specific type of Sig-Net Device designed to bridge the Sig-Net network to legacy DMX512/\[RDM\] networks. It translates between network payloads and physical serial data.

Hardware-Secure Storage: Key storage resistant to software-level extraction.

HMAC (Hash-based Message Authentication Code): A cryptographic algorithm used to guarantee that a packet was generated by an authorised Device (possessing the correct derived key role) and has not been tampered with in transit.

HKDF (HMAC-based Extract-and-Expand Key Derivation Function): A simple, standard cryptographic key derivation function defined in RFC 5869.

K0 (Root Key): A 256-bit symmetric cryptographic key that acts as the single root of trust for a Sig-Net network. It must be distributed to all devices out-of-band and is used to mathematically derive the role-specific keys.

Kc (Citizen Key): A 256-bit key derived from K0 using HKDF-Expand. Used by all onboarded Sig-Net Devices (Managers, Senders and Nodes) to cryptographically sign their On-Boot Notification packets and by Nodes to authenticate their routine discovery replies and status reports.

Ks (Sender Key): A 256-bit key derived from K0 using HKDF-Expand. Used to authenticate level data and timecode packets.

Km_global (Global Manager Key): A 256-bit key derived from K0 using HKDF-Expand. Used to authenticate global management multicasts such as TID_POLL.

Km_local (Node-Specific Manager Key): A 256-bit key derived from K0 using HKDF-Expand, bound to a specific Node's TUID. Used to authenticate targeted configuration commands.

Lost Mode: A management fallback state triggered when a fully Onboarded Node stops receiving valid TID_POLL requests from an active Manager. In Lost Mode, the Node continues to process any active Sender data normally, but begins transmitting authenticated "lost" notifications to the \<mult_node_lost\> URI to signal its orphaned status to the network.

Manager: A Sig-Net Device. See Section [6.2](#functional-roles)

Multicast Folding™: A network routing strategy where a large, technically unlimited number of universes are mathematically mapped ("folded") into a smaller, fixed pool of multicast IP addresses using a modulo operation. This prevents IGMP table exhaustion on network switches while keeping Discard Load manageable on large systems.

Native Configuration: Commands and parameters natively defined by the Sig-Net protocol using TIDs, as distinct from encapsulated \[RDM\] payloads.

Node: See Section [6.2](#functional-roles).

Offboarded: A Sig-Net Device that has not been assigned a Root Key (K0) and has not been explicitly configured for Open Mode. An offboarded Device operates exclusively in Beacon Mode; it cannot participate in standard Sig-Net communication and shall only transmit unauthenticated presence beacons to alert Managers that it requires onboarding.

Open Mode: An explicit, user-selected operational state where a Device operates without cryptographic keys or HMAC authentication. It is intended strictly for low-risk environments. To prevent downgrade attacks, Open Mode is isolated from Secure Mode devices via CoAP Option 2076.

PBKDF2 (Password-Based Key Derivation Function 2): A standard cryptographic key derivation function (defined in RFC 8018) used by Sig-Net to stretch a human-readable passphrase into a cryptographically secure 256-bit Root Key (K0), providing robust defence against offline dictionary attacks.

RDM-Responder: A non-networked Device (e.g. a standard \[DMX512\] moving light) sitting downstream of a Gateway, communicating via standard E1.20 serial \[RDM\].

Sender: See Section [6.2](#functional-roles).

Sequence Number (Sig-Net-Seq-Num): A 32-bit unsigned integer that increments by 1 for every packet transmitted within a specific session. Along with the Session ID, it guarantees packet freshness and prevents individual packet replay attacks.

Session ID (Sig-Net-Session-ID): An increasing 32-bit unsigned integer stored in non-volatile memory. It increments upon Device initialisation or when the Sequence Number overflows. It serves as the primary defence against whole-session replay attacks.

Sig-Net Device: Any physical IP-connected piece of hardware equipped with a Sig-Net network interface. A Sig-Net Device may implement the functional classes of Manager, Sender, Node, or any combination thereof.

SoemCode: A 32-bit unique product identifier self-assigned by the manufacturer. The upper 16 bits consist of the manufacturer's ESTA Manufacturer ID and the lower 16 bits are a manufacturer-defined product variant ID. It is reported during network polling, allowing Managers to identify product types during node-discovery without relying on external databases.

Supplier: An endpoint or Device that generates control data and transmits it onto the Sig-Net network.

TUID (Transport Unique Identifier): A 48-bit identifier for a Sig-Net Device.

TID (Type Identifier): A 2-byte unsigned integer forming the first field of a Sig-Net TLV, defining the structure of the data payload.

TLV (Type-Length-Value): A data encoding scheme used by Sig-Net to efficiently pack disparate data types (e.g. \[DMX512\] levels, Priority and \[RDM\] commands) into a single UDP payload.

UID (Unique Identifier): A 48-bit identifier consisting of a 16-bit ESTA Manufacturer ID and a 32-bit Device ID, used for addressing during \[RDM\] transactions, as defined in \[E1.20\].

[\
]{.mark}

# Appendix E CRA and ENISA Compliance Reference (Informative)

This appendix is provided as a navigation aid for manufacturers and security reviewers compiling Technical Files for regulatory certification. It maps the security requirements of the EU Cyber Resilience Act (CRA) and the corresponding implementation guidance from the European Union Agency for Cybersecurity (ENISA) against the relevant sections of this specification. It does not constitute a compliance assessment or guarantee. Regulatory compliance remains the sole responsibility of the manufacturer as stated in Section [1.3](#compliance-notice-disclaimer).

## CRA Annex 1, Part 1 Mapping

+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| **CRA Annex I, Part I** | **Requirement Summary**                   | **Sig-Net Reference**                                                                                                                                                                     |
+=========================+===========================================+===========================================================================================================================================================================================+
| Point 2(a)              | No known exploitable vulnerabilities      | Section [1.4](#vulnerability-disclosure) --- Vulnerability Disclosure                                                                                                                     |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(b)              | Secure by default configuration           | Section [7.2](#root-key-k0-specification) --- K0 onboarding mandate;                                                                                                                      |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [7.2.3](#input-and-transfer-formats) --- Passphrase Mapping & Strength Requirements;                                                                                              |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2 (c)             | Protection against unauthorised access    | Section [4.5](#authentication) --- Authentication;                                                                                                                                        |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [4.7](#authorisation) --- Authorisation;                                                                                                                                          |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [7.3](#key-derivation-function-kdf) --- Key Derivation                                                                                                                            |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(d)              | Protection of confidentiality             | Section [4.4](#encryption) --- Encryption rationale; Section [5.6](#eavesdropping-sniffing) --- Eavesdropping;                                                                            |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [7.6](#storage-and-security) --- Key storage                                                                                                                                      |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2 (e)             | Protection of integrity                   | Section [4.4](#encryption) --- Encryption rationale; Section [4.6](#integrity) --- Integrity;                                                                                             |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [8.5](#hmac-calculations) --- HMAC Calculation; Section [8.6](#packet-processing-and-replay-attack-prevention) --- Replay Prevention.                                             |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section 8.6.4 -- Post-Reboot Replay Protection.                                                                                                                                           |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Note: Sig-Net addresses integrity via HMAC. The confidentiality aspect of this point is addressed through the manufacturer's risk assessment as described in Section [4.4](#encryption).  |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(f)              | Protection of stored and transmitted data | Section [7.6](#storage-and-security) --- Key storage;                                                                                                                                     |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [14.1.2](#key-storage-hardware) --- Key storage hardware                                                                                                                          |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(g)              | Minimisation of attack surface            | Section [4.7](#authorisation) --- Implicit authorisation; Section [5.7](#compromised-node-or-sender) --- Blast radius containment;                                                        |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [7.3](#key-derivation-function-kdf) --- Per-Device Km_local                                                                                                                       |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(h)              | Resilience against denial of service      | Section [8.6](#packet-processing-and-replay-attack-prevention) Step 9 --- DoS rate limiting; Section [10.2.1](#offboarded-operation-beacon-mode-1) --- Beacon Mode (multicast isolation); |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [10.2.2](#manager-operation) Manager Operation (poll snooping)                                                                                                                    |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(i)              | Limitation of impact of incidents         | Section [5.7](#compromised-node-or-sender) --- Compromised Device blast radius;                                                                                                           |
|                         |                                           |                                                                                                                                                                                           |
|                         |                                           | Section [7.3.2](#key-lifecycle-and-erasure) --- Key Lifecycle and Erasure (Discard K0 after onboarding)                                                                                   |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(j)              | Recording and monitoring capability       | Section [11.8.1](#tid_dg_security_event) -- TID_DG_SECURITY_EVENT (provides a standardised network- reporting mechanism for security anomalies, supporting manufacturer compliance).      |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Point 2(k)              | Secure update mechanism                   | Section [4.9.1](#firmware-updates) --- Firmware updates (manufacturer responsibility); Section [4.9.2](#key-rotation) --- Key rotation                                                    |
+-------------------------+-------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

## ENISA Security by Design and Default Playbook Mapping

The following table maps the architectural features of Sig-Net to the specific implementation playbooks published by ENISA to assist manufacturers in proving "Security by Design and Default."

  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **ENISA Playbook**                   **Playbook Objective**                                                                 **Sig-Net Implementation Reference**
  ------------------------------------ -------------------------------------------------------------------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  4.2 Least Privilege                  Limit blast radius and prevent lateral movement.                                       Section 10.3.3: The Global Manager Key (Km_global) is stripped of configuration privileges. All configuration is restricted to the specific Km_local key of the target node.

  4.3 Strong Identity & Auth           Prevent impersonation.                                                                 Section 7.3: All roles (Manager, Sender, Node) utilise mathematically distinct keys derived via HKDF, backed by stateless HMAC-SHA256 signatures.

  4.4 Attack Surface Minimisation      Remove unnecessary interfaces.                                                         Section 8.6: The Device state machine drops unsupported cryptographic modes, malformed CoAP codes and unpatched universes at the routing layer before processing.

  4.6 Open Design                      Avoid security through obscurity.                                                      Sig-Net utilises open, peer-reviewed cryptographic standards (PBKDF2, HKDF, HMAC, SHA-256) rather than proprietary obfuscation.

  4.10 Logging & Monitoring            Provide visibility to detect misuse.                                                   Section [11.8.1](#tid_dg_security_event): Nodes are mandated to track and report HMAC failures, replay anomalies and DoS rate-limiting events via TID_DG_SECURITY_EVENT.

  4.16 Restrictive Initial Access      Eliminate shared/default credentials.                                                  Section 7.2: Explicitly prohibits shipping with default Root Keys. Manual hexadecimal entry is banned to prevent trivial/weak key reuse.

  4.18 Unique Device Secrets           Ship unique cryptographic identities.                                                  Section 7.3: Device management keys (Km_local) are mathematically bound to the Node's unique hardware identifier (TUID).

  4.19 Mandatory Security Onboarding   Block operation until setup is complete.                                               Section 7.2.2: Devices lacking a Root Key are completely locked out of authenticated traffic and restricted to an isolated "Beacon Mode" until physical onboarding occurs.

  4.21 Transparent Security Posture    Clearly warn users of degraded security states.                                        Open Mode Transparency: TID_RT_STATUS Bit 3 dynamically alerts Managers when a Device is operating in unauthenticated Open Mode, allowing consoles to render clear UI warnings in compliance with ENISA guidelines.

  4.22 Secure Recovery Lifecycle       Provide secure reset mechanisms.                                                       Section 7.7: Defines authenticated network wipe commands (TID_RT_OFFBOARD) with strict boot-time safety lockouts, alongside out-of-band physical wipe requirements.

  5.0 Machine Readable Attestation     Automate security validation.                                                          Section [11.6](#root-endpoint-type-identifiers): Nodes dynamically report their Protocol Version, Firmware Version and Role Capabilities via Root TIDs, directly supporting the automated generation of Machine-Readable Security Manifests (MRSM) by conformance tools.

  Replay Prevention and Freshness      Prevent the unauthorized reuse of captured valid sessions or packets across reboots.   Section 8.6.2 --- The Lane Model; Section 8.6.4 --- Post-Reboot Replay Protection.
  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Appendix F Architectural Rationale (Informative)

This appendix provides the engineering and cryptographic justification for several key design decisions within the Sig-Net protocol, answering common implementation questions regarding the choice of underlying technologies.

## Why CoAP?

The Constrained Application Protocol (RFC 7252) provides an ultra-lightweight, standardised UDP header that is natively understood by modern IT infrastructure. While MQTT was evaluated---and in some respects represents a superior conceptual match for Sig-Net's Publish/Subscribe state model---the ESTA FENCE project has selected CoAP as its foundation. Standardising on CoAP aligns Sig-Net with the industry's future trajectory, allowing manufacturers to reuse underlying network libraries and minimise firmware bloat.

## Why Cleartext Routing

\[OSCORE\] classifies the CoAP Uri-Path as an encrypted inner option. While a proxy-routing URI can technically be exposed in the outer header, doing so duplicates data and wastes CPU cycles. Sig-Net explicitly relies on the cleartext URI (e.g. /sig-net/v1/\<scope\>/level/101) as the definitive hardware-layer routing filter for its Multicast Folding™ architecture. Because multiple universes share a single multicast group, a Node receives significant traffic destined for other devices. By keeping the URI in cleartext and appending the HMAC as a trailing CoAP Option, network switches and multi-port Gateways can parse routing targets at line-rate, dropping irrelevant multicast universes (the Discard Load) without wasting critical CPU cycles invoking a cryptographic decryption engine.

## Why Out-of-Band Keying?

Because Sig-Net V1 prioritises real-time execution speed by using plaintext payloads, a new Root Key (K0) cannot safely be transmitted over the network without encryption. Out-of-band Onboarding (e.g. USB, NFC, or local UI) guarantees that physical proximity is the root of trust, eliminating remote, network-based key interception vectors during initial setup.

## Why a Custom HMAC structure instead of OSCORE?

Standard secure CoAP (OSCORE, RFC 8613) is a point-to-point (unicast) protocol, rendering it fundamentally incompatible with the decision to use multicast.

While \[Group OSCORE\] extends support to multicast, it achieves group-level source authentication by mandating the use of asymmetric digital signatures (e.g. Ed25519/ECDSA). Verifying asymmetric signatures at a sustained 44Hz per universe on mid-range embedded microcontrollers introduces unacceptable latency.

Instead, Sig-Net uses a custom trailing symmetric HMAC. This provides the required stateless integrity and implicit group authentication while remaining highly performant on constrained silicon. Furthermore, Sig-Net requires cleartext URIs for line-rate hardware routing (allowing \[DMX512\] Gateways to drop unpatched universes without invoking cryptography), which standard \[OSCORE\] explicitly obscures.

## Why a Custom TLV structure instead of CBOR?

The standard data serialisation format for CoAP environments is Concise Binary Object Representation (CBOR, RFC 8949). While CBOR is highly flexible and self-describing, parsing dynamic maps and arrays introduces unnecessary computational overhead and memory fragmentation risks on constrained microcontrollers.

Entertainment control data---such as a fixed 512-byte \[DMX512\] universe, an encapsulated \[RDM\] packet, or a 5-byte timecode frame---is highly deterministic. A simple, flat Type-Length-Value (TLV) structure allows receivers to parse payloads using basic pointer arithmetic, entirely avoiding the CPU overhead and library footprint of a full CBOR decoder. This custom TLV approach maximises bandwidth efficiency and execution speed, matching the extreme real-time processing requirements of the live events industry.

## Why CoAP NON POST only?

Sig-Net is designed for extreme real-time performance and multi-manager environments. Relying on CoAP Confirmable (CON) messages introduces state-tracking overhead, retry-loop fragility and potentially ACK storms on large networks. By exclusively using Non-Confirmable (NON) POST messages, Sig-Net relies on the deterministic CHANGE_COUNT mechanism (Section 10.2.7) to guarantee eventual consistency across the network, completely decoupling state synchronisation from transport reliability.

## Why multicast RDM responses?

Standard E1.20 \[RDM\] is historically a Request/Response protocol. However, the latest E1.20-2025 standard introduces asynchronous "Push Notifications" (Qued Message mandate) precisely because the old polling model cannot scale on dense IP networks. By mandating that all nodes proactively multicast their TID_RDM_RESPONSE packets to \<mult_node_send\>, Sig-Net natively implements this new \[RDM\] push model into its Pub/Sub architecture.

This allows a Main Console to track a patch change made by a Riggers Remote, achieving real-time, stateless synchronisation across all Managers and completely eliminating the need for a fragile, centralised RDMnet Broker.

## Future Extensibility

The protocol is structurally designed to accommodate future security requirements via the Sig-Net-Security-Mode (Option 2076) and the v1 URI namespace. Should future silicon advancements or legislative mandates require payload encryption, in-band key exchange (e.g. DTLS handshakes), or new CoAP verbs, a version update (e.g. Security-Mode 0x80 or /sig-net/v2/) can introduce these features without breaking the core TLV routing or HMAC architecture.

# Appendix G Cryptographic Test Vectors (Normative)

This appendix provides a verified test vector and Python script for the Sig-Net security pipeline.

## Input Parameters

- Passphrase (ASCII String): SigNetT3stVector1!

- Salt (ASCII String): Sig-Net-K0-Salt-v1

- Iterations: 100000

- Algorithm: PBKDF2-HMAC-SHA256

  - Section 7.2.3: PBKDF2-HMAC-SHA256, 100,000 iterations, fixed 18-byte ASCII salt.

## Key Derivation Reference Script (Python 3)

import hashlib

import hmac

\# Inputs

passphrase = b\"SigNetT3stVector1!\"

salt = b\"Sig-Net-K0-Salt-v1\"

iterations = 100000

\# 1. PBKDF2 Derivation for K0

K0 = hashlib.pbkdf2_hmac(\"sha256\", passphrase, salt, iterations, 32)

print(f\"K0: {K0.hex()}\")

\# Helper for HKDF-Expand (L=32 matches SHA256 output, simplifying to T(1))

def hkdf_expand(prk, info):

return hmac.new(prk, info + b\"\\x01\", hashlib.sha256).digest()

\# 2. Key Derivation (HKDF-Expand) --- info strings per Section 7.3

Ks = hkdf_expand(K0, b\"Sig-Net-Sender-v1\")

Kc = hkdf_expand(K0, b\"Sig-Net-Citizen-v1\")

Km_global = hkdf_expand(K0, b\"Sig-Net-Manager-v1\")

Km_local = hkdf_expand(K0, b\"Sig-Net-Manager-v1-123456789ABC\")

print(f\"Ks: {Ks.hex()}\")

print(f\"Kc: {Kc.hex()}\")

print(f\"Km_global: {Km_global.hex()}\")

print(f\"Km_local: {Km_local.hex()}\")

\# 3. HMAC Input Message Construction (Section 8.5, field order and widths)

uri = b\"/sig-net/v1/local/level/1\"

security_mode = b\"\\x00\"

sender_id = bytes.fromhex(\"123456789ABC0001\") \# 6-byte TUID + 2-byte Endpoint

mfg_code = bytes.fromhex(\"0000\")

session_id = bytes.fromhex(\"00000005\")

seq_num = bytes.fromhex(\"000000A2\")

payload = bytes.fromhex(\"01010003FF8000\") \# TID_LEVEL TLV: TID(2)=0x0101 + Length(2)=3 + 3 value bytes

hmac_input = uri + security_mode + sender_id + mfg_code + session_id + seq_num + payload

print(f\"HMAC Input: {hmac_input.hex()}\")

\# 4. HMAC-SHA256 Calculation using Ks (Section 7.3.1: Ks signs /level/ traffic)

auth_tag = hmac.new(Ks, hmac_input, hashlib.sha256).digest()

print(f\"HMAC Tag: {auth_tag.hex()}\")

## Real Calculated Key Outputs

Running the reference script yields the following hexadecimal keys:

- Derived Root Key (K0):

  - 06577c606a72282988c7919752b72a52380b57ff49118091dea5815dc148d3e3

- Sender Key (Ks):

  - 23ffd543990f2253c884af7fc6c47255aa1606a4f2f30e082381bb17c9a6c242

- Citizen Key (Kc):

  - eac261f8782065387816c0c9ea72aa8083565eb871a3392363a5b31611a26f81

- Global Manager Key (Km_global):

  - c00b7fefaaff7ba30821019bc99526c6be58ad0fba3ea3f27f378db344043457

- Node-Specific Manager Key (Km_local) for TUID 123456789ABC:

  - 8f41d6df9a5ac9d8f8c7c0580a0c5fb90026154dd2dca6469cc3929ec5bb4889

## HMAC Input Construction and Output Digest

This test case demonstrates the byte-level construction of the HMAC input message (Section 8.5) and the resulting tag for a standard TID_LEVEL packet signed with Ks (Section 7.3.1, Ks authenticates /level/ traffic).

- HMAC Input Byte Stream (51 bytes total: 25-byte URI + 1 + 8 + 2 + 4 + 4 + 7-byte payload):

  - 2f7369672d6e65742f76312f6c6f63616c2f6c6576656c2f3100123456789abc0001000000000005000000a201010003ff8000

- HMAC-SHA256 Output Tag (Signed using Ks):

  - c7126005fb474564dc7ce4c122e3e60d4b13dedeb8c6ad1e8daa51e5c66a8225

# Appendix H Document Revisions (Informative)

V0.1 (9/2/2026)

- Initial concept draft.

V0.7 (7/3/2026)

- Release to three companies for preliminary peer review.

V0.8 (13/3/2026)

- Changed TI to TID for RDM PID analogy.

- Changed all section cross references to Word style for pdf hot-links.

- Implemented PR suggestion to change default universe to multicast mapping.

- Added note about edge case where universe could be mapped to different multicast on different nodes. Strong do not do this recommendation.

- Added to 10.1 a rule to define how we handle an unknown TID.

- Reorganised the actual multicast address defaults in Appendix A to put the streaming and administrative on different subnets.

- Defined broadcast and Vendorcast tuid.

- Defined broadcast endpoint as all data endpoints.

- Reworked Native Configuration Commands and RDM to use unicast with a mandated multicast update mechanism.

- Resolved numerous errors where Manager and Sender use was confused for historical reasons.

- Defined concept of "Discard Load". See glossary.

- Added concept of Sig-Net-Sender-ID which is a concatenation of TUID+Endpoint. This is used as a CID replacement for slot-priority and also to resolve the backup console reply attack scenario.

- Mandate unilateral RDM Get Response on a change (single TLV in payload)

- Include xxx for both RDM and Sig-Net Device firmware upload.

- Added support for proprietary protocol wrapping.

- Fixed two security issues relating to Session ID across boots (replay attack).

- Added and then deleted an attempt at OTW keying and key rotation.

- Added Node power on behaviour (poll reply)

- Added mandated fields to TID list.

- Changed port direction terminology to supplier/consumer.

- Implemented version number and protocol number support TIDs.

- Implemented TID for Supported TIDs.

- Implemented Diagnostics TIDs.

- Released to additional companies for peer review.

V0.9 (16/3/2026)

- Clarified that Change Count is only incremented for TID changes, not PID.

- Added TID_SYNC

- Added all the network setting TIDs

- Add rollback timer for network changes.

- Added concept of Lost Mode and Beacon Mode.

- Move Beacon to its own multicast to allow filtering for DoS.

- Reorganised section 10.2 to make difference between Lost Mode and Beacon Mode more obvious.

- Changed the equation for the default Multicast Folding patch. (Provides zero Discard Load for shows \< 100 universe).

- Added node reply mandate to ensure MTU limit for fragmentation not broken.

- Corrected node receiver parsing state machine to include check for version.

- Resolved storage ambiguity in 13.1.2

- Fixed broadcast tuid key flaw.

- Added limits for session tracking.

- Add password base K0 option for 'PC based systems'.

- Changed RDM response to multicast irrelevant of whether the command was unicast or multicast.

- Clarified how per-universe priority is handled.

- Allowed but discouraged unicast TID_LEVEL.

- Made Multicast Folding configuration optional.

- Moved responsibility for Entropy check to the manager.

- Renamed Controller to Sender.

- Clarified Root Endpoint is mandated, Data Endpoint is not.

- Removed references to Secure Boot.

- Added diagram to show how key types are used.

- Fixed TID enum collision.

- Added URI destination to all TID definitions.

V0.10 (21/3/2026)

- Acknowledgements updated.

- Terms updated.

- Section 7.2.2 added. This defines password stretching to avoid manual entry of k0 and allow 8-char password.

- Section 1.3. Clarify that it is also a user / integrator responsibility.

- Section 4.5/4.7. Slightly informal text improved.

- Section 6.3 redrafted to clarify the human aspect.

- Section 6.5 clarify this is expected to be the same as the RDM ID.

- Section 7.4 clarify the k0 generation intent.

- Added section 8.6 stp 9 to clarify NV burn out issue.

- Section 7.6 updated to describe the concept of 'stateless' and avoid k0 storage.

- Section 8.3 Session-ID definition updated to encompass software Device.

- Major rework on TID Get. Poll argument ALL changed to QUERY_LEVEL Section 11.9. Plus Length = 0 is now globally a TID Get.

- Added Wireshark example.

- Changed 8.6 stp 6: We're moving to keep session ID in ram on the Node. This fixes our NV wear and 'reboot to fix' issue with a trivial increase in threat surface.

V0.11 (21/3/2026)

- Fixed TID length = 0 option on all Queryable TIDs

- Fixed error caused by Node Sender ID stored in ram. See First Packet Bootstrapping.

- Softened conditions of use.

- Changed name to Sig-Net (changed all uri syntax).

- Added logo.

- New Section 12 added to address versioning. Section 8.6-4 updated to point to Section 12.

- The passcode updates from v0.10 had not fully been implemented in other sections. Additionally, the simple hash was not adequate. Updated 7.3 to add a specific key life cycle section. Updated 7.6 to match. Updated 7.2.2 for higher security.

- Passcode vs k0 entry is now mandated based on hardware. i.e. humans are not allowed to enter 64-char code. Numerous sections updated including 7.2.2

- TID_POLL payload changed to add manager tuid and manager SoemCode. Purpose is to make it simpler for managers to discard their own comms when backing off in a multi-manager environment.

- Added the concept of Manufacturer specific TIDs (Section 10.1.1). Note this is in addition to manufacturer specific payload.

- 10.4.3 updated to make it clear that packing query TIDs is allowed and expected.

- Section 8.5-3. This is a wire breaker. Sig-Net_Sender_ID was shown a 1 byte. Corrected to 8 bytes.

- TID_SYNC definition had trailing slash in URI. Fixed.

- Thread modelling led to these changes:

  - Section 8.6 DoS mitigation has been changed to mandate rate limiting. This conclusion was reach from the threat modelling process.

  - Section 10.2.2 reworked to add a poll jitter. This is to avoid colliding polls in multi-manager environment.

  - Assorted trivial cleaning.

  - Added mandates for beacon mode to mitigate DoS vector.

  - Section 7.2.3 Passphase entry made more onerous in order to achieve 50 bits entropy implicitly required for compliance. Also, SALT added to HMAC.

  - Section 10.2.1 Beacon rules enhanced.

  - Traceability is required for CRA audit. Nodes were fine but Senders and Managers previously had no 'announce' onto the network. Updated 10.2.5 / 7.1 to require all devices to do an announce of: TID_POLL_REPLY, TID_RT_FIRMWARE_VERSION, TID_RT_PROTOCOL_VERSION. Also rebranded Node Key (Kc) as Citizen Key (Kc).

  - Appendix D updated to match Threat Analysis.

- Introduced \<node_prosessing_max\> to give a deterministic timeout on lost TID/PID responses.

- Increased \<sync_lost_timeout\>.

V0.12 (25/3/2026)

- Fig1 added. Key Hierarchy.

- Section 7.2.3 passphrase length error corrected.

- Section 7.2.3 Added informative notes regarding the passphrase to K0 algorithm using a fixed public SALT. Making the point that whilst a variable SALT (e.g. Venue name) would be preferred, it destroys the UI gain of a 10-digit pass code. Also, that a fixed public SALT is still better than a null SALT as it guards against existing rainbow table use.

- Section 7.2.3 Added recommendation that Manager 'offer' strong passphrases. This is to improve the \[Shannon\] score relative to human created passcodes which are intrinsically weaker.

- Kn to Kc replacement completed.

- TUID broadcast and Vendorcast deleted from document. It was causing a security vulnerability (Km_global attack vector).

- Section 7.2.3 updated for passcode entry. Max length defined. Manager mandated checks, node and sender not mandated. Reference code recommended. Also rework text to make the entry options clearer.

- Section 8.6. Improves DoS mitigation.

- General. Removed association of Session ID with Boot Counting.

- Added TID_RT_ROLE_CAPABILITY.

- Credits update.

- Peer review feedback that HMAC vs encryption processing power argument is flawed. Redrafted Section 4.2 to clarify the rationale is about multi-universe scaling (particularly on platforms without cyber hardware assist).

- Section 7.7. Added info note on epoch ending for clarity.

- Section 7.6 updated to address storage realities.

- Section 7.7.2 / 7.5 updated to specifically allow secure out-of-band.

- Section 8.8 updated to deal with a session exhaustion issue.

- Section 8.3 reworded for clarity.

- Section 8.2/6.8.4 updated to clarify that non-tuid indices are decimal in URI.

- Section 11.3 updated. RDM TIDs are allowed to root endpoint (config / firmware)

- Section 9.2.5. Mandate TID_EP_MULT_COMMAND user initiated by Manager.

- General terminology clean up for Parameter Queries

- Section 10.4.2 Batching applies to SET (clarification)

- Updated Wireshark example (was showing Endpoint = 0 == illegal)

- Section 10.8.1 Timecode stop and stutter addressed.

- Contradiction is TID_DG_SECURITY_EVENT mandate fixed. (Shall throughout).

- Section 11.1.1 URI was incorrect, fixed.

- Section 10.3.1 The poll URI not listed, fixed.

- Section 11.6.1 wording improved.

- Section 11.6.5/11.7.2 the issue of a "clear command" resolved.

- Section 11.6.7 Clarified Identify does not persist.

- Section 11. Major clean up on length and URI (particularly Endpoints)

- Section 11.6.10 TID_RT_REBOOT added.

- Section 11.8.1 clarified TLV packing expectation.

- Section 11.9 evolved into a summary.

- Added Section 12.4 to deal with legacy senders in future versions of Sig-Net

- Figure 2 improved.

- TID_EP_DIRECTION changed to include RDM enable / disable.

- TID_EP_FAILOVER added

- TID_RT_MODEL_NAME added

- TID_EP_DMX_TIMING added

- \[sACN\] Normative corrected.

- Added Appendix E.

- Section 4.4 reworked.

- Mandated lower case for K0 display 'B' vs '8' issue.

- Section 8.5 (1-1) improved with \[CoAP\] section references.

- \[Shannon\] added.

- \[CSPRNG\] added.

- Section 8.6. Numerous pleasingly pedantic improvements.

- Section 10.4.5. Fixed Rollback verification issue.

- Section 10.6.3. Active data changed to Dynamic data.

V0.14 (2/4/2026)

- Inadvertent deletion of \<mult_manager_send\> reinstated.

<!-- -->

- Section 9.2.2 updated for above.

- Section 10.3.1 updated for above.

- Section 10.3.2 updated for above.

- TID_EP_REFRESH_CAPABILITY added. Section 10.6.3 adjusted to implement new TID.

- Added new Section 18.2 To provide a summary cross reference for the new ENISA document.

- Section 11.6.7 Updated identify and added mute.

- \<ip_rollback_timer\> increased to 60s. 30s was deemed too low to allow for (eg) spanning tree cycle times.

- Section 10.2.4 updated to clarify that an individual TLV must also not exceed the MTU limit.

- Section 11.8.1 clarified that attacker IP is indicative only.

V0.15 (3/4/2026)

- Added Section 2.2 informative references.

- Updated Section 8.3 to make Option 2236 variable length. This is for future compatibility of a potentially encrypted payload.

- Updated preface.

- Updates Section 4.4

- Section 11.7.4 Changed name and expanded functions.

- Section 11.3.1-5 Corrected to remove root endpoint.

- Section 10.5.3 Added to exclude certain PID classes from RDM payload on Virtual Endpoints. This plugs a security hole where a virtual endpoint can adjust the root via legacy protocols.

- Section 6.8.2 Introduced concept of a Virtual Endpoint.

- Normative updated.

- TID_RDM_FLOW_CONTROL added.

- Section 6.6 updated to define ephemeral TUIDs.

V0.16 (9/4/2026)

- Section 10.7.2. Dealt with the 'Sync problem' by linking TID_SYNC to Sig-Net-Sender-ID.

- Wire breaking change. Scope now added to URI to avoid multi-tenanted networks tripping over each other.

- Added normative \[URI\].

- TID_RT_MODEL_NAME payload change.

- Numerous trivial fixes.

- Section 10.2.3 Dealt with potential endpoint broadcast storm.

- Section 10.2.7 Resolved IP change consistency tracking.

- Section 10.4.5 Mandated IP change confirmation from old IP.

- Section 10.4.2 Added notes about data endpoint hardware limitations.

- Section 11.7.8 Added stop DMX option.

- Section 11.7.5 Added Fallback mode.

- Section 11.8.1/2 Updated endpoint to zero only.

- Section 11.8.2 Added rate limiting to resolve DoS attack concern.

- Section 14.1.2 Rolled in dealing with legacy product storage.

- Section 7.6 and 14.1.2 Expanded to ban export of derived keys and address derived key storage in legacy products.

- Section 8.2 Corrected ASCII value error.

- Section 10.2.1 Corrected Beacon rate error.

- Section 10.2.1 Beacon logging limited to managers.

- Section 10.1 Incorrect Appendix reference.

- All Appendix cross references changed to section number references.

- Section 10.5.2 Added clarification that gateways do not need to cache downstream RDM data and that they can and should rely on the \[RDM\]-2025 Queue mandate.

- Section 11.3.4 Breaking Change: x of y packets added to payload.

- Section 11.6.1 typo fixed.

- Section 8.3 Made it clearer that CoAP requires the exact option order to be maintained.

- Sections 11.7.8 / 11.8.3 / 11.7.4 Typos fixed.

- New Appendix C with json definitions of TIDs.

V0.16a (15/4/2026)

- Removed references to unpublished ANSI standards

V0.17 (14/4/2026)

- Section 10.2.6 Updated the mandated tids in heartbeat to match announce

- TID_EP_STATUS bit fields updated.

- Prohibition on E1.37-7 was a typo -- removed.

- Modified Sections 7.2, 7.5, 4.9.2 to remove the OTW mandate.

- Added \<mult_preview\>

- Section 11.2.3 TID_PREVIEW added.

- Section 11.6.12. Added warning about loss of contact.

- Replaced "Provisioning" with "Onboarding" ready for OTW.

- Mandated a Sender respond to Poll (OTW requirement).

- Section 6.2. Defined Visualiser role. (OTW requirement).

- Section 11.6.9. Added Visualiser role flag.

- Section 8.3. Use of term thread caused confusion -- replaced.

- Section 11.6.10 added TID_RT_OTW_CAPABILITY.

- Section 10.2.1 updated for revised mandated TLVs.

- Section 10.2.5 updated for revised mandated TLVs.

- Section 10.2.6 updated for revised mandated TLVs.

V0.18 (20/4/2026)

- Section 11.7.7 Updated bit fields.

- Section 11.2.1/2 Mandate for Visualisers added.

- Section 11.8.3 Visualiser mandate changed to no.

- Section 10.6/11.7.6. Short packet priority clarified.

- Section 7.2.3 Removed ambiguity.

- Section 16. Definitions added.

- Section 10.2.7 / 10.4.2. Updated to clarify that status changes as well as config changes should generate a 'publish' and a CHANGE_COUNT increment.

- Section 7.2.2 updated to reference 10.2.1 to remove ambiguity.

- Section 7.7.1/7.2.3 updated for clarity.

- Section 6.6. Added informative on how TUID is displayed.

V0.19 (3/5/2026)

- Section 6.6. Corrected TUID display type to upper case hex.

- Section 8.6.9. Redraft throttling per Discord discussion.

- Section 7.2. Added reference to SNOW.

- Section 7.2.3. was contradicting 7.6. Updated 7.2.3 to clarify that a Manager does not drop K0.

- Section 7.6. Visualiser role included.

- Section 7.7.1. Fixed the warm reboot security concern.

- Section 8.3. Visualiser role included.

- Section 6.6. updated to replace ephemeral TUID with Dynamic TUID and clarify they can be stored. Also added informative notes on collision and seeding.

- Section 6.2. Introduced the Equal Manager and Guest Manager concepts.

- Section 7.5. Added the key export for restricted guest mode.

- Section 10.4.3. Clarified query mechanics for Guest Mode.

- Added Section 13.3. to give examples of multi-manager mode operation.

- Added Section 7.2.5. to introduce Open Mode.

- Section 8.3. Added 0x01 = Open Mode.

- Section 8.6. Defined Open Mode operation.

- Section 11.6.8. Added bit field for Open Mode.

- Section 18. Added Open Mode definition.

- Section 18. Deleted Unprovisioned.

- Section 18. Updated Offboarded.

- Section 8.4. Added Scope to table.

- Section 6.2. Changed logical roles to 4.

- Section 8.2. Fixed ASCII UTF-8 issue.

- Changed TID_PATCH to TID_UNIVERSE

- Appendix A corrected for missing endpoint in uri.

V0.20 (4/5/2026)

- Section 11.6.9. Open Mode supported bit added.

- Section 7.2.5. Prohibit of Open Mode only devices.

- Added Section 11.10 TID summary.

- Errant TID_PATCH fixed.

- Section 11. Changed TID_POLL_REPLY to target all endpoint.

- Section 10.2.3. Updated to clarify that all poll responses, independent of endpoint, start with a poll response. This was previously ambiguous and has been clarified to ensure the CHANGE_COUNT mechanism is not compromised.

- TID_EP_CAPABILITY and TID_EP_REFRESH_CAPABILITY moved to the QUERY_CONFIG category.

- Section 11.2.5. Updated to modern frame rates.

- Section 11.8.2. Corrected target to Root to match URI (typo).

- Section 11.6.4. Referenced RDM for version.

- Section 15, 14.1.3, 11.6.6, 9.2.3 updated for changes to Multicast Folding.

V1.0 (9/5/2026)

- Section 8.3. Typo

- Section 13.3. Clarified Km_local status in example.

- Section 8.6.1. Updated c & d for typo.

- Section 12.3/4. Updated to resolve logical error.

- Section 8.3. Updated for better resolution of Session exhaustion.

- Section 10.6.3. Integrated TID_PRIORITY and added informative re sACN and Art-Net expectations.

- Section 8.3. Typo in hex number.

- Appendix C. Updated for new TIDs

- Section 14.1.3. Corrected example.

- Section 7.5.1. Informative note to Guest Access.

- Section 8.3 & 10.2.1. Reduced HMAC length to zero on mode 0x01 and 0xff. (Beacon Mode Wire Break).

- Section 8.3. Session and Sequence exemption for Open Mode and Beacon Mode.

- Section 10.2.2. Open Mode clarification.

- Section 10.6.2. Renamed to encompass open mode.

- Section 11.7.11. TID_EP_PROTOCOL added

- Section 10.6.4. Defined stream loss on non-Sig-Net protocols.

- Section 10.5.4 added. Gateway responsibilities. Queue polling, ACK_OVERFLOW handling, ACK_TIMER handling.

- Section 10.5.2. Updated for state sync and background get anti-overload mandate.

- Section 10.2.2. Open mode clarification.

- Section 10.6.2. Open mode clarification.

V1.01 (11/5/2026)

- Section 11.9 and 11.10 improvements. Not substantive

- Section 11.3.1-6. Manager mandate corrected.

- Section 10.2.2. Updates to resolve Discovery Master Token Thrashing concern.

- Section 7.3.1 inserted for key use summary.

- Section 19.2. Updated re ENISA Playbook to include Open Mode reference.

- Section 6.8.4. Updated. Text was ambiguous and could be interpreted as for SET only. Also, an unintended root Device exclusion removed.

- Section 11.6.9. Added Root_Firmware_Support flag. We previously had no way to check if a devices could take a firmware update.

- Section 6.8.1. Text relating to allowed RDM use was ambiguous. Updated to match the TID destination fields.

- Section 4.9.1. Ambiguous text improved.

- Section 11.3.1/2. Table was excluding root destination. Adjusted to specifically allow file transfer.

- Section 11.9/10. Updated to correct same errors as above.

- Section 11.7.12. Added TID_EP_IDENTIFY.

- Section 11.6.7. Updated notes to clarify that RT and EP identify are exclusive functions.

- Section 7.2.3. Added note that longer passphrases are better.

- Section 10.2.7. Updated to clarify status changes are excluded from change count.

- Section 10.4.3. Tightened the definition of TLV length =0.

- Section 11.6.11. Clarified read only.

- Section 11.6.5/11/2. Clarified zero length reply not allowed.

- Section 11.8.1. Security Event changed to root only.

- Section 11.8.3. Mandate no-reply if data not available.

- Section 15. Modulo 109 example corrected.

- Section 11.8.1. Expanded event codes.

- Section 8.6. Updated saturated table action.

- Section 11.1.1. Noted that only the '/poll' may be used.

- Section 10.6. Updated to specify HTP on identical priority value.

- Section 10.5.4. Expanded flow control description and added flow control flow chart.

- All diagrams updated and converted to Mermaid script.

- Added additional diagrams to Sections 9.2.3, 10.4.5.

- Section 10.2.3. Re-titled and updated. Previous text implied only nodes respond. New text clarifies that all devices must respond.

- Section 10.3.3. Added for aux lane.

- Section 15. Added Aux multicast.\
  Section 11.9/10. Updated for TID_OSC

- Section 8.6.1. Strengthened mandate.

- Section 18. Misc additions.

- Section 11.6.9. TID_RT_ROLE_CAPABILITY payload increased 🡸=========== Wire breaking change.

- Section 11.7.4. TID_EP_CAPABILITY payload increased 🡸=========== Wire breaking change.

- Section 11.6.5/11, 11.7.2. Updated for encoding byte. Payload increased 🡸=========== Wire breaking change.

V1.02 (29/5/2026)

- Section 8.6.1. Inconsistency corrected related to tracking TUID+EP

- Section 8.6.2. Added to centralise the description of how sequence numbers work. New drawing added.

- Section 9.2.4. Corrected Node / Device use.

- Section 9.3.3. Updated.

- All cross references audited and updated.

- All Node/Device use audited and updated.

- Capitalisation audited and updated.

- Section 8.6.2. Added note to clarify that open-mode packet duplicates do not increment security event counters.

- Section 7.2.4. Moved to Section 8.6.3. for clarity and consistency.

- Section 8.3. Updated to clarify sequence number wrap behaviour.

- Section 9.5.4. Updated to remove the suggestion that virtual and physical endpoints should behave differently.

- Section 10.6.7. Added missing enum.

- Renamed TID_RDM_TOD_BACKGROUND to TID_RDM_EP_CONFIG.

- Added to  TID_RDM_EP_CONFIG -- enable background queue.

- Section 9.5.4. updated to clarify the node closes its flow control while pumping overflow.

- Section 6.9.2. Updated to remove mixed mode text.

V1.03 (4/6/2026)

- Option Number 2140 definition improved.

- Section 9.4.2. Slight change to reply requirement to avoid a NOP SET having same non-response as a failed SET. Also addresses a potential DOS amplification concern. Also added drawing.

- Audit Responder terminology and implemented a division between Sig-Net Device and RDM-Responder.

- Audited and corrected \[RDM\] and \[DMX512\].

- Section 8.6.1. Fixed cut-paste error.

- Section 10.7.11. Clarification to text.

- Section 9.5.4. Clarification.

- Section 9.5.4. Evolved text to accept both FIFO and binary gate style of flow control

- Sig-Net-HMAC and Sig-Net-Auth deconflicted to Sig-Net-Auth

- Section 9.5.4. Pumping text tweaked to focus on FIFO output rather than input.

- Section 9.2.7 and all TID definitions. Our definition of Native Configuration Change had led to an ambiguity on which TID SETs would increment Change Count. This has been resolved by adding a 'Persistent' definition field to the TID tables and updating the condition for incrementing change count to be only if the parameter is persistent.

V1.04 (7/6/2026)

- Section 10.2.6. The notes said "Multiple TID_UNIVERSE payloads should be packed efficiently into a single CoAP packet.". This is not possible as the sender_id.ep in the header defines the source. This sentence was well intentioned but not possible and has been deleted.

- Section 10.1.3. added to clarify TLV validation.

- Sig-Net trademark and conditions of use updated. ® to ®

- Section 8.6.2. updated Data Lanes for clarity.

- Section 10.2.1. updated for On-demand Beaconing.

V1.05 (22/6/2026)

- \<key_rotation_overlap\> added

- Section 10.2.1. Added TID_RT_ROLE_CAPABILTY to beacon payload so that the manager understands which device roles it is talking to.

- Section 11.6.12. Added new bit field to declare whether the device support Type B (PIN) verification.

V1.06 (3/7/2026)

- Section 11.8.1. Added additional event code.

- Section 7.5. The json format of equal and guest had different syntax and the equal key was missing scope. All fixed and recommended file extension added.

- Updates related to change_count. Early implementors discovered a multi-controller flaw in change_count. Essentially two problems a) we were overloading poll_reply use and b) change_count was counting TLV when actually packet makes more senses.

  - Section 10.4.5. Added informative section on anticipated implementation of change_count and flowchat.

  - Added Figure 6 for above

  - Section 10.2.7. Deleted and moved to new 10.4

  - Section 11.1.3. Added TID_SET_REPLY

  - Section 10.4.2. Changed description on when change_count increments.

  - Figure 5 updated inline with 10.4.2

  - Section 11.9 / 11.10 updated for TID_SET_REPLY.

V1.07 (15/7/2026)

- Section 11.2.6. Reworked TID_UNIVERSE to fix the scaling issue introduced in the v1.04 update.

V1.07 (16/7/2026)

- Section 8.2 reference fixed.

V1.08 (31/8/2026) Includes CyberFest feedback.

- Reference to E1.37-4 \[FTC\] added.

- Section 10.6 and Section 11.7.4 updated. Allocated Bit 5 (0x20) of TID_EP_CAPABILITY to explicitly declare if a Data Endpoint supports full Per-Slot Priority Merging or is utilizing the Constrained Node Fallback. Wire break.

- Appendix C updated to match document.

- 10.1.1 Corrected for TID range.

- 6.8.2 Updated to clarify that data endpoints start at one.

- 11.8.1 updated for length on an IP = None.

- 11.2.5 updated max frames.

- 10.6.2 Added TID_PREVIEW

- 8.3 Added informative note about CoAP int encoding.

- 10.2.1 URI typo corrected

- TID_RDM_TOD_DATA definition typos corrected

- 11.9 TID_DG_LEVEL_FOLDBACK queryability typo corrected.

- 10.2.4. Fixed the fragmentation definition and adjusted 11.3.4 and 11.6.1 to match.

- 10.5.2 Removed the unicast/multicast conditioning as not always possible to implement.

- 10.2.3 and \<node_processing_max\> definition updated to clarify this is actually a manager side timeout for retransmission.

- 10.1.3 updated to handle precedence -- last writer wins.

- 10.1.3 updated for TLV validation rules.

- 11.3.4 Clarification on the scope of \<endpoint_spacing_delay\>

- 10.5.5 Added and 11.3.1 updated to clarify that RDM discovery shall not be sent over TID_RDM_COMMAND

- Appendix C TID_SET_REPLY added.

- Appendix G with key calculations and Python added.

- Added 8.6.4, \<first_packet_bootstrap_window\> and updated E.1, E.2 to add lock out window to address SEC-006 peer review comments.

V1.09 (14/9/2026) Includes CyberFest feedback.

- Updated 8.3 and 7.7 to address network reaction to a device recovering from Session-ID exhaustion.

- 10.5.2 changed to mandate backoff in all circumstances as the application layer may not have access to whether the command was unicast or multicast. \<rdm_backoff_max\> added to decouple Poll and RDM timing.

- Minor typos and style in 11.6.1, 11.3.1, 11.3.2, 11.3.3, 11.7.5 and 11.7.7

- 7.7 changed to clarify Session-ID persists.

V1.10 (15/9/2026)

- Corrected ASCII / UTF-8 errors throughout document.

- 7.3.1 table updated and corrected.

- 7.6 corrected for key holding.

- 10.2.5 added missing visualiser.

- 10.3.x deconflated Node and Device.

- 10.3.1 Added informative note about 'Device'.

- 11.4.1 Corrected Device / Node.

- 11.8.1 Corrected Device / Node.

- 8.3 We had tripped over the Coap mandate to transmit uint options as minimum number of bytes. Real world tests show there is minimal support for this and it is likely an interoperability issue. Hence we have redefined the 4 x uint option fields as CoAP 'opaque' in order to legally send fixed width options.

V1.11 (17/9/2026)

- 10.5.5 typo fixed

- 11.2.2 node mandate fixed (to match 10.5.5 shall).

- Section 10.6 & 11.7.4: Mandated a minimum of 4 simultaneous merge sources for endpoints consuming TID_LEVEL.

- Section 11.7.4: Expanded TID_EP_CAPABILITY payload to 6 bytes to report Maximum Merge Sources \[4--5\], and clarified Bit 5 Priority Merge Mode definition. Wire break.

- Appendix C: Updated TID_EP_CAPABILITY maximum length to 6.

Copyright © Singularity (UK) Ltd 2026. All rights reserved.\
Sig-Net®, Multicast Folding™, SNACtest™, SNOW™, SNOWman™ SNOWboard™ ,SNOWboarding™ and NETworkshop™ are trademarks of Singularity (UK) Ltd.
