---
title: "Discovery of Oblivious Services via Service Binding Records"
abbrev: "Oblivious Services in SVCB"
category: info
stream: IETF

docname: draft-pauly-ohai-svcb-config-latest
area: "Security"
workgroup: "Oblivious HTTP Application Intermediation"
keyword: Internet-Draft
venue:
  group: "Oblivious HTTP Application Intermediation"
  type: "Working Group"
  mail: "ohai@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ohai/"
  github: tfpauly/draft-ohai-svcb-config

v: 3

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
Gateway Resource, as well as a mechanism to look up oblivious key configurations
using a well-known URI.

--- middle

# Introduction

Oblivious HTTP {{!OHTTP=I-D.draft-ietf-ohai-ohttp}} allows clients to encrypt
messages exchanged with an HTTP target server accessed via an Oblivious Relay
Resource (relay) and an Oblivious Gateway Resource (gateway), in such a way
that the relay cannot inspect the contents of the message and the gateway
does not discover the client's identity. In order to use Oblivious HTTP, clients
need to possess a key configuration to use to encrypt messages to the gateway.

Since Oblivious HTTP deployments will often involve very specific coordination
between clients, relays, and gateways, the key configuration can often be
shared in a bespoke fashion. However, some deployments involve clients
discovering oblivious gateways more dynamically. For example, a network may
want to advertise a DNS resolver that is accessible over Oblivious HTTP
and applies local network resolution policies via mechanisms like Discovery
of Designated Resolvers ({{!DDR=I-D.draft-ietf-add-ddr}}. Clients
can work with trusted relays to access these gateways.

This document defines a mechanism to advertise that an HTTP service supports
Oblivious HTTP using DNS records, as a parameter that can be included in SVCB
and HTTPS DNS resource records {{!SVCB=I-D.draft-ietf-dnsop-svcb-https}}.
The presence of this parameter indicates that a service can act as an oblivious
gateway; see {{Section 2 of OHTTP}} for a description of oblivious gateway.

This document also defines a well-known URI {{!RFC8615}}, "oblivious-configs",
that can be used to look up key configurations on a service that is known
act as an oblivious gateway.

This mechanism does not aid in the discovery of relays to use to access
oblivious gateways; the configuration of proxies is out of scope for this
document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# The oblivious SvcParamKey

The "oblivious" SvcParamKey ({{iana}}) is used to indicate that a service
described in an SVCB record can act as an oblivious gateway resource. Clients
can issue requests to this service through an oblivious relay once
they learn the key configuration to use to encrypt messages to the
oblivious gateway.

Both the presentation and wire format values for the "oblivious"
parameter MUST be empty.

The "oblivious" parameter can be included in the mandatory parameter
list to ensure that clients that do not support oblivious access
do not try to use the service. Services that mark oblivious
support as mandatory can, therefore, indicate that the service might
not be accessible in a non-oblivious fashion. Services that are
intended to be accessed either with an oblivious gateway or directly
SHOULD NOT mark the "oblivious" parameter as mandatory. Note that since
multiple SVCB responses can be provided for a single query, the oblivious
and non-oblivious versions of a single service can have different SVCB
records to support different names or properties.

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

For example, an HTTPS service record for svc.example.com that supports
an oblivious gateway could look like this:

~~~
svc.example.com. 7200  IN HTTPS 1 . alpn=h2,h2 oblivious
~~~

A similar record for a service that only support oblivious connectivity
could look like this:

~~~
oblivious-svc.example.com. 7200  IN HTTPS 1 . (
    mandatory=oblivious oblivious )
~~~

## Use in DNS server SVCB records

For the "dns" scheme, as defined in {{DNS-SVCB}}, the presence of
the "oblivious" parameter means that the DNS server being
described is an Oblivious DNS over HTTP (DoH) service. The default
media type expected for use in Oblivious HTTP to DNS resolvers
is "application/dns-message" {{!DOH=RFC8484}}.

In order for DNS servers to function as oblivious gateways, they need
to be accessible via an oblivious relay. Encrypted DNS servers
used with the discovery mechanisms described in this section can
either be publicly accessible, or specific to a network. In general,
only publicly accessible DNS servers will work as Oblivious DNS
servers, unless there is a coordinated deployment with an oblivious
proxy that is also hosted within a network.

### Use with DDR {#ddr}

Clients can discover an oblivious DNS server configuration using
DDR, by either querying _dns.resolver.arpa to a locally configured
resolver or querying using the name of a resolver {{DDR}}.

For example, a DoH service advertised over DDR can be annotated
as supporting oblivious resolution using the following record:

~~~
_dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
     alpn=h2 dohpath=/dns-query{?dns} oblivious )
~~~

Clients still need to perform some verification of oblivious DNS servers,
such as the TLS certificate check described in {{DDR}}. This certificate
check can be done when looking up the configuration on the resolver
using the well-known URI ({{well-known}}), which can either be done
directly, or via a proxy to avoid exposing client IP addresses.

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

# Configuration Well-Known URI {#well-known}

Clients that know a service is available as an oblivious gateway, e.g.,
either via discovery through the "oblivious" parameter in a SVCB or HTTPS
record, or by configuration, need to know the key configuration before sending
oblivious requests.

This document defines a well-known URI {{!RFC8615}}, "oblivious-configs",
that allows a gateway to host its configurations.

The URI is constructed using the TargetName in the associated ServiceMode
SVCB record.

For example, the URI for the following record:

~~~
svc.example.com. 7200  IN HTTPS 1 . alpn=h2,h2 oblivious
~~~

would be "https://svc.example.com/.well-known/oblivious-configs".

As another example, the URI for the following record:

~~~
_dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
     alpn=h2 dohpath=/dns-query{?dns} oblivious )
~~~

would be "https://doh.example.net/.well-known/oblivious-configs".

The content of this resource is expected to be "application/ohttp-keys",
as defined in {{OHTTP}}.

Before being able to use a server as an oblivious gatweay, clients need
to use this URI to fetch the configuration. They can either fetch it
directly, or do so via a proxy in order to avoid the server discovering
information about the client's identity. See {{security}} for more
discussion of avoiding key targeting attacks.

# Security and Privacy Considerations {#security}

Attackers on a network can remove SVCB information from cleartext DNS
answers that are not protected by DNSSEC {{?DNSSEC=RFC4033}}. This
can effectively downgrade clients. However, since SVCB indications
for oblivious support are just hints, a client can mitigate this by
always checking for oblivious gateway information. Use of encrypted DNS
or DNSSEC also can be used as mitigations.

When discovering designated oblivious DNS servers using this mechanism,
clients need to ensure that the designation is trusted in lieu of
being able to directly check the contents of the gateway server's TLS
certificate. See {{ddr}} for more discussion, as well as the Security
Considerations of {{?I-D.ietf-add-svcb-dns}}.

As discussed in {{OHTTP}}, client requests using Oblivious HTTP
can only be linked by recognizing the key configuration. In order to
prevent unwanted linkability and tracking, clients using any key
configuration discovery mechanism need to be concerned with attacks
that target a specific user or population with a unique key configuration.

There are several approaches clients can use to mitigate key targeting
attacks. {{?CONSISTENCY=I-D.draft-wood-key-consistency}} provides an analysis
of the options for ensuring the key configurations are consistent between
different clients. Clients SHOULD employ some technique to mitigate key
targeting attack. Oblivious gateways that are detected to use targeted
key configurations per-client MUST NOT be used.

When clients fetch a gateway's configuration using the well-known URI,
they can expose their identity in the form of an IP address if they do not
connect via a proxy or some other IP-hiding mechanism. In some circumstances,
this might not be a privacy concern, since revealing that a particular
client IP address is preparing to use an Oblivious HTTP service can be
expected. However, if a client is otherwise trying to obfuscate its IP
address or location (and not merely decouple its specific requests from its
IP address), or revealing its IP address will increase the risk of a key
targeting attack (if a gateway service is trying to differentiate traffic
across client IP addresses), a proxy or similar mechanism can be used to fetch
the gateway's configuration.

# IANA Considerations {#iana}

## SVCB Service Parameter

IANA is requested to add the following entry to the SVCB Service Parameters
registry ({{SVCB}}).

| Number  | Name           | Meaning                            | Reference       |
| ------- | -------------- | ---------------------------------- | --------------- |
| TBD     | oblivious      | Describes if a service operates an oblivious HTTP gateway  | (This document) |

## Well-Known URI

IANA is requested to add a new entry in the "Well-Known URIs" registry {{!RFC8615}} with the following information:

URI suffix: oblivious-configs

Change controller: IETF

Specification document: This document

Status: permanent

Related information: N/A

--- back
