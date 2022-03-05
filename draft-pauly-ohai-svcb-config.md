---
title: "Distribution of Oblivious Configurations via Service Binding Records"
abbrev: "Oblivious Configs in SVCB"
category: info

docname: draft-pauly-ohai-svcb-config-latest
ipr: trust200902
area: "Security"
workgroup: "Oblivious HTTP Application Intermediation"
keyword: Internet-Draft
venue:
  group: "Oblivious HTTP Application Intermediation"
  type: "Working Group"
  mail: "ohai@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ohai/"

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Tommy Pauly
    organization: Apple Inc.
    email: tpauly@apple.com

    name: Tirumaleswar Reddy
    organization: Akamai
    email: kondtir@gmail.com

normative:

informative:


--- abstract

This document defines a parameter that can be included in SVCB and HTTPS
DNS resource records to denote that a service is accessible as an Oblivious
HTTP target, along with one or more oblivious key configurations.

--- middle

# Introduction

Oblivious HTTP {{!OHTTP=I-D.draft-ietf-ohai-ohttp}} allows clients to encrypt
messages exchanged with an HTTP server accessed via a proxy, in such a way
that the proxy cannot inspect the contents of the message and the target HTTP
server does not discover the client's identity. In order to use Oblivious
HTTP, clients need to possess a key configuration to use to encrypt messages
to the oblivious target.

Since Oblivious HTTP deployments will often involve very specific coordination
between clients, proxies, and targets, the key configuration can often be
shared in a bespoke fashion. However, some deployments involve clients
discovering oblivious targets more dynamically. For example, a network may
want to advertise a DNS resolver that is accessible over Oblivious HTTP
and applies local network resolution policies via mechanisms like Discovery
of Designated Resolvers ({{!DDR=I-D.draft-ietf-add-ddr}}. Clients
can work with trusted proxies to access these target servers.

This document defines a mechanism to distribute Oblivious HTTP key
configurations in DNS records, as a parameter that can be included in SVCB and
HTTPS DNS resource records {{!SVCB=I-D.draft-ietf-dnsop-svcb-https}}.
The presence of this parameter indicates that a service is an oblivious
target; see {{Section 3 of OHTTP}} for a description of oblivious targets.

This mechanism does not aid in the discovery of proxies to use to access
oblivious targets; the configurations of proxies is out of scope for this
document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# The ohttp-configs and ohttp-path SvcParamKeys

The "ohttp-configs" SvcParamKey {{iana}} is used to convey one or more
key configurations that can be used by clients to issue oblivious requests
to a target server described by the SVCB record.

In wire format, the value of the parameter is one or more `KeyConfig`
structures {{OHTTP}} concatenated together. In presentation format,
the value is the same concatenated `KeyConfig` structures encoded
in Base64 {{!BASE64=RFC4648}}.

The meaning of the "ohttp-configs" parameter depends on the scheme
of the SVCB record. This document defines the interpretation for
the "https" {{SVCB}} and "dns" {{!DNS-SVCB=I-D.draft-ietf-add-svcb-dns}}
schemes. Other schemes that want to use this parameter MUST define the
interpretation and meaning of the configuration.

The "ohttp-path" SvcParamKey {{iana}} is used to convey the URI path of
the oblivious target to which oblivious HTTP requests can sent. In both
wire format and presentation format, this is a UTF-8 encoded string
that contains the path segment of a URI. If this path parameter is not
present, oblivious requests can be made to the root "/" path.

## Use in HTTPS service records

For the "https" scheme, which uses the HTTPS RR type instead of SVCB,
the presence of the "ohttp-configs" parameter means that the service
being described is an Oblivious HTTP service that uses the default
"message/bhttp" media type {{OHTTP}}
{{!BINARY-HTTP=I-D.draft-ietf-httpbis-binary-message}}.

When present in an HTTPS record, the "ohttp-configs" MUST be included
in the mandatory parameter list, to ensure that implementations that
do not understand the key do not interpret this service as a generic
HTTP service.

Clients MUST validate that they can parse the value of "ohttp-configs"
as a valid key configuration before attempting to use the service.

## Use in DNS server SVCB records

For the "dns" scheme, as defined in {{DNS-SVCB}}, the presence of
the "ohttp-configs" parameter means that the DNS server being
described is an Oblivious DNS over HTTP (DoH) service. The default
media type expected for use in Oblivious HTTP to DNS resolvers
is "application/dns-message" {{!DOH=RFC8484}}.

The "ohttp-configs" parameter is only defined for use with DoH, so
the "alpn" SvcParamKey MUST indicate support for a version of HTTP
and the "dohpath" SvcParamKey MUST be present. The "ohttp-configs"
MUST also be included in the mandatory parameter list, to ensure
that implementations that do not understand the key do not interpret
this service as a generic DoH service.

Clients MUST validate that they can parse the value of "ohttp-configs"
as a valid key configuration before attempting to use the service.

### Use with DDR {#ddr}

Clients can discover an oblivious DNS server configuration using
DDR, by either querying _dns.resolver.arpa to a locally configured
resolver or querying using the name of a resolver {{DDR}}.

In the case of oblivious DNS servers, the client might not be able to
directly use the verification mechanisms described in {{DDR}}, which
rely on checking for known resolver IP addresses or hostnames in TLS
certificates, since clients do not generally perform TLS with oblivious
targets. A client MAY perform a direct connection to the oblivious
target server to do this TLS check, however this may be impossible
or undesirable if the client does not want to ever expose its IP
address to the oblivious target. If the client does not use the standard
DDR verification check, it MUST use some alternate mechanism to verify
that it should use an oblivious target. For example, the client could have
a local policy of known oblivious target names that it is allowed to
use, or the client could coordinate with the oblivious proxy to either
have the oblivious proxy check the properties of the target's TLS
certificate or filter to only allow targets known and trusted by the
proxy.

Clients also need to ensure that they are not being targeted with unique
key configurations that would reveal their identity. See {{security}} for
more discussion.

### Use with DNR {#dnr}

The SvcParamKeys defined in this document also can be used with Discovery
of Network-designated Resolvers (DNR) {{!DNR=I-D.draft-ietf-add-dnr}}. In this
case, the oblivious configuration and path parameters can be included
in DHCP and Router Advertisement messages.

While DNR does not require the same kind of verification as DDR, clients
still need to ensure that they are not being targeted with unique
key configurations that would reveal their identity. See {{security}} for
more discussion.

### Handling Oblivious DoH Configurations

Oblivious DoH was originally defined in
{{?ODOH=I-D.draft-pauly-dprive-oblivious-doh}}. This version of
Oblivious DoH uses a different key configuration format than
generic Oblivious HTTP. SVCB records using the "dns" scheme
can include one or more `ObliviousDoHConfig` structures 
using the "odoh-configs" parameter.

In wire format, the value of the "odoh-configs" parameter is one
or more `ObliviousDoHConfigs` structures {{ODOH}} concatenated
together. In presentation format, the value is the same structures
encoded in Base64 {{!BASE64=RFC4648}}.

All other requirements for "ohttp-configs" in this document apply
to "odoh-configs".

# Deployment Considerations

Deployments that add the "ohttp-configs" SvcParamKey need to be
careful to add this only to services meant to be accessed using
Oblivious HTTP. Information in a single SVCB record that contains
"ohttp-configs" only applies to the oblivious service, not
other HTTP services.

If a service offers both traditional HTTP and oblivious HTTP, these can
be represented by separate SVCB or HTTPS records, both with and
without the "ohttp-configs" SvcParamKey.

# Security and Privacy Considerations {#security}

When discovering designated oblivious DNS servers using this mechanism,
clients need to ensure that the designation is trusted in lieu of
being able to directly check the contents of the target server's TLS
certificate. See {{ddr}} for more discussion.

As discussed in {{OHTTP}}, client requests using Oblivious HTTP
can only be linked by recognizing the key configuration. In order to
prevent unwanted linkability and tracking, clients using any key
configuration discovery mechanism need to be concerned with attacks
that target a specific user or population with a unique key configuration.

There are several approaches clients can use to mitigate key targetting
attacks. {{?CONSISTENCY=I-D.draft-wood-key-consistency}} provides an analysis
of the options for ensuring the key configurations are consistent between
different clients. Clients SHOULD employ some technique to mitigate key
targetting attack. One mitigation specific to this mechanism is validating
that SVCB or HTTPS records including the "oblivious-configs"
are protected by DNSSEC {{?DNSSEC=RFC4033}}. This prevents attacks
where a unique response is generated for each client of a resolver.

# IANA Considerations {#iana}

IANA is requested to add the following entry to the SVCB Service Parameters
registry ({{SVCB}}).

| Number  | Name           | Meaning                            | Reference       |
| ------- | -------------- | ---------------------------------- | --------------- |
| TBD     | ohttp-configs  | Oblivious HTTP key configurations  | (This document) |
| TBD     | ohttp-path     | Oblivious HTTP request path        | (This document) |
| TBD     | odoh-configs   | Oblivious DoH key configurations   | (This document) |

--- back
