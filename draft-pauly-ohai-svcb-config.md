---
title: "Discovery of Oblivious Services via Service Binding Records"
abbrev: "Oblivious Services in SVCB"
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
 -
    name: Tirumaleswar Reddy
    organization: Akamai
    email: kondtir@gmail.com

normative:

informative:


--- abstract

This document defines a parameter that can be included in SVCB and HTTPS
DNS resource records to denote that a service is accessible as an Oblivious
HTTP target, as well as a mechanism to look up oblivious key configurations
using a well-known URI.

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

This document defines a mechanism to advertise that an HTTP service supports
Oblivious HTTP using DNS records, as a parameter that can be included in SVCB
and HTTPS DNS resource records {{!SVCB=I-D.draft-ietf-dnsop-svcb-https}}.
The presence of this parameter indicates that a service has an oblivious
target; see {{Section 3 of OHTTP}} for a description of oblivious targets.

This document also defines a well-known URI {{!RFC8615}}, "oblivious-configs",
that can be used to look up key configurations on a service that is known
to have an oblivious target.

This mechanism does not aid in the discovery of proxies to use to access
oblivious targets; the configurations of proxies is out of scope for this
document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# The oblivious SvcParamKey

The "oblivious" SvcParamKey {{iana}} is used to indicate that a service
described in an SVCB record can act as an oblivious target. Clients
can issue requests to this service through an oblivious proxy once
they learn the key configuration to use to encrypt messages to the
oblivious target.

The value of the "oblivious" parameter is a number that encodes
the different states for how the described service supports oblivious
requests and non-oblivious requests. The values are:

- 0: the service does not support receiving requests as an oblivious
target.

- 1: the service only supports receiving requests as an oblivious
target.

- 2: the service supports receiving requests as an oblivious target, as
well as direct requests.

If the value of "oblivious" is 1, which indicates that this service
is not a generic service, but only support oblivious access, the
"oblivious" parameter MUST be in the mandatory parameter list,
to ensure that implementations that do not understand the key
do not interpret this service as a generic service.

The presentation value of the SvcParamValue is a single decimal integer
between 0 and 2 in ASCII. Any other value (e.g. an empty value) is a
syntax error. To enable simpler parsing, this SvcParam MUST NOT contain
escape sequences.

The wire format of the SvcParamValue is the corresponding 1 octet numeric
value.

The scheme to use for oblivious requests made to a service depends on
the scheme of the SVCB record. This document defines the interpretation for
the "https" {{SVCB}} and "dns" {{!DNS-SVCB=I-D.draft-ietf-add-svcb-dns}}
schemes. Other schemes that want to use this parameter MUST define the
interpretation and meaning of the configuration.

## Use in HTTPS service records

For the "https" scheme, which uses the HTTPS RR type instead of SVCB,
the presence of the "oblivious" parameter means that the service
being described is an Oblivious HTTP service that uses the default
"message/bhttp" media type {{OHTTP}}
{{!BINARY-HTTP=I-D.draft-ietf-httpbis-binary-message}}.

TODO: Example

## Use in DNS server SVCB records

For the "dns" scheme, as defined in {{DNS-SVCB}}, the presence of
the "oblivious" parameter means that the DNS server being
described is an Oblivious DNS over HTTP (DoH) service. The default
media type expected for use in Oblivious HTTP to DNS resolvers
is "application/dns-message" {{!DOH=RFC8484}}.

### Use with DDR {#ddr}

Clients can discover an oblivious DNS server configuration using
DDR, by either querying _dns.resolver.arpa to a locally configured
resolver or querying using the name of a resolver {{DDR}}.

TODO: Example

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

# Configuration Well-Known URI

Once a client has discovered that a service is available as an oblivious
target, it needs to know the key configuration before sending oblivious
requests.

This document defines a well-known URI {{!RFC8615}}, "oblivious-configs",
that allows a target to host its configurations.

TODO: Provide example URI based on SVCB record

TODO: Explain who fetches the config

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
targetting attack.

# IANA Considerations {#iana}

## SVCB Service Parameter

IANA is requested to add the following entry to the SVCB Service Parameters
registry ({{SVCB}}).

| Number  | Name           | Meaning                            | Reference       |
| ------- | -------------- | ---------------------------------- | --------------- |
| TBD     | oblivious      | Describes if a service has an oblivious target  | (This document) |

## Well-Known URI

IANA is requested to add a new entry in the "Well-Known URIs" registry {{!RFC8615}} with the following information:

URI suffix: oblivious-configs

Change controller: IETF

Specification document: This document

Status: permanent

Related information: N/A

--- back
