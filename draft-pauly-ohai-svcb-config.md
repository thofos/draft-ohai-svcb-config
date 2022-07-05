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
DNS resource records to denote that a service is accessible using Oblivious
HTTP, with an indication of which Oblivious Gateway Resource to use to access
the service (aa an Oblivious Target Resource). This document also defines
mechanisms to learn more details about the related Oblivious Gateway Resource,
such as its key configuration.

--- middle

# Introduction

Oblivious HTTP {{!OHTTP=I-D.draft-ietf-ohai-ohttp}} allows clients to encrypt
messages exchanged with an Oblivious Target Resource (target). The messages
are encapsulated in encrypted messages to an Oblivious Gateway Resource
(gateway), which gates access to the target. The gateway is access via an
Oblivious Relay Resource (relay), which proxies the encapsulated messages
to hide the identity of the client. Overall, this architecture is designed
in such a way that the relay cannot inspect the contents of messages, and
the gateway and target cannot discover the client's identity.

Since Oblivious HTTP deployments will often involve very specific coordination
between clients, relays, and gateways, the key configuration can often be
shared in a bespoke fashion. However, some deployments involve clients
discovering oblivious targets and their assoicated gateways more dynamically.
For example, a network may want to advertise a DNS resolver that is accessible
over Oblivious HTTP and applies local network resolution policies via mechanisms
like Discovery of Designated Resolvers ({{!DDR=I-D.draft-ietf-add-ddr}}. Clients
can work with trusted relays to access these gateways.

This document defines a mechanism to advertise that an HTTP service supports
Oblivious HTTP using DNS records, as a parameter that can be included in SVCB
and HTTPS DNS resource records {{!SVCB=I-D.draft-ietf-dnsop-svcb-https}}.
The presence of this parameter indicates that a service can act as an oblivious
target, and indicates an oblivious gateway that can provide access to the target.

This document also defines two well-known URIs {{!RFC8615}}, which
are access on the oblivious gateway indicated in the SVCB record.

- "oblivious-configs", which can be used to look up key configurations
on a host that has been identified as an oblivious gateway using SVCB
records ({{well-known-config}}); and,

- "oblivious-gateway", which can be used to send oblivious gateway requests
to a host that has been identified as an oblivious gateway using SVCB
records ({{well-known-gateway}}).

This mechanism does not aid in the discovery of oblivious relays;
the configuration of relays is out of scope for this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# The oblivious-gateway SvcParamKey

The "oblivious-gateway" SvcParamKey ({{iana}}) is used to indicate that a
service described in an SVCB record can be accessed as an oblivious target
using the specified gateway. The service that is queried by the client hosts
one or more target resources. The gateway is a separate resource that is indicated
by the SVCB record parameter, which allows oblivious access to any target resource
hosted by the service described in the SVCB record.

In order to access the service's target resources obliviously, the client
needs to send encapsulated messages to the gateway resource using the gateway's
key configuration (which can be retrieved using the method described in
{{well-known-config}}).

The presentation format of the "oblivious-gateway" parameter is a
comma-separated list of one or more hostnames. The wire format consists
of one or more hostnames, each prefixed by its length as a single octet,
with these length-value pairs concatenated to form the SvcParamValue.
These pairs MUST exactly fill the SvcParamValue; otherwise, the SvcParamValue
is malformed.

The "oblivious-gateway" parameter can be included in the mandatory parameter
list to ensure that clients that do not support oblivious access
do not try to use the service. Services that mark the oblivious-gateway
parameter as mandatory can, therefore, indicate that the service might
not be accessible in a non-oblivious fashion. Services that are
intended to be accessed either with an oblivious gateway or directly
SHOULD NOT mark the "oblivious-gateway" parameter as mandatory. Note that since
multiple SVCB responses can be provided for a single query, the oblivious
and non-oblivious versions of a single service can have different SVCB
records to support different names or properties.

The media type to use for encapsulated requests made to a target service
depends on the scheme of the SVCB record. This document defines the
interpretation for the "https" {{SVCB}} and "dns" {{!DNS-SVCB=I-D.draft-ietf-add-svcb-dns}}
schemes. Other schemes that want to use this parameter MUST define the
interpretation and meaning of the configuration.

## Use in HTTPS service records

For the "https" scheme, which uses the HTTPS RR type instead of SVCB,
the presence of the "oblivious-gateway" parameter means that the target
being described is an Oblivious HTTP service that uses the default
"message/bhttp" media type {{OHTTP}}
{{!BINARY-HTTP=I-D.draft-ietf-httpbis-binary-message}}.

For example, an HTTPS service record for svc.example.com that supports
an oblivious gateway could look like this:

~~~
svc.example.com. 7200  IN HTTPS 1 . (
     alpn=h2 oblivious-gateway=osvc.example.com )
~~~

A similar record for a service that only support oblivious connectivity
could look like this:

~~~
svc.example.com. 7200  IN HTTPS 1 . (
    mandatory=oblivious-gateway oblivious-gateway=osvc.example.com )
~~~

## Use in DNS server SVCB records

For the "dns" scheme, as defined in {{DNS-SVCB}}, the presence of
the "oblivious-gateway" parameter means that the DNS server being
described is an Oblivious DNS over HTTP (DoH) service. The default
media type expected for use in Oblivious HTTP to DNS resolvers
is "application/dns-message" {{!DOH=RFC8484}}.

In order for DNS servers to function as oblivious targets, their
associated gateways need to be accessible via an oblivious relay.
Encrypted DNS servers used with the discovery mechanisms described
in this section can either be publicly accessible, or specific to a
network. In general, only publicly accessible DNS servers will work
as oblivious DNS servers, unless there is a coordinated deployment
with an oblivious relay that is also hosted within a network.

### Use with DDR {#ddr}

Clients can discover an oblivious DNS server configuration using
DDR, by either querying _dns.resolver.arpa to a locally configured
resolver or querying using the name of a resolver {{DDR}}.

For example, a DoH service advertised over DDR can be annotated
as supporting oblivious resolution using the following record:

~~~
_dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
     alpn=h2 dohpath=/dns-query{?dns}
     oblivious-gateway=odoh.example.net  )
~~~

Clients still need to perform some verification of oblivious DNS servers,
such as the TLS certificate check described in {{DDR}}. This certificate
check can be done when looking up the configuration on the resolver
using the well-known URI ({{well-known-config}}), which can either be done
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

# Key Configuration Well-Known URI {#well-known-config}

Clients that know a service is available as an oblivious target
via discovery through the "oblivious-gateway" parameter in a SVCB or HTTPS
record need to know the key configuration of the gateway before sending
oblivious requests.

This document defines a well-known URI {{!RFC8615}}, "oblivious-configs",
that allows a gateway to host its configurations.

The URI is constructed using the name in the "oblivious-gateway"
SVCB parameter.

For example, the configuration URI for the following record:

~~~
svc.example.com. 7200  IN HTTPS 1 . (
     alpn=h2 oblivious-gateway=osvc.example.com )
~~~

would be "https://osvc.example.com/.well-known/oblivious-configs".

As another example, the configuration URI for the following record:

~~~
_dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
     alpn=h2 dohpath=/dns-query{?dns}
     oblivious-gateway=odoh.example.net )
~~~

would be "https://odoh.example.net/.well-known/oblivious-configs".

The content of this resource is expected to be "application/ohttp-keys",
as defined in {{OHTTP}}.

Before being able send messages through an oblivious gateway, clients need
to use this URI to fetch the configuration. They can either fetch it
directly, or do so via a proxy in order to avoid the server discovering
information about the client's identity. See {{security}} for more
discussion of avoiding key targeting attacks.

# Oblivious Gateway Resource Well-Known URI {#well-known-gateway}

Oblivious gateways that are advertised via SVCB or HTTPS records
need to receive gateway requests (sent from oblivious relays) on
a particular path. While oblivious gateways in general do not
require fixed or well-known paths, since they can use ad-hoc
configurations with clients and relays, gateways discovered using
the method described in this document need to offer a well-known
path.

Offering a single, well-known URI for each discovered gateway name allows
for simpler lookup of associated key configurations, simpler communication
between clients and relays, and makes client-targeting attacks more
difficult to execute. See {{security}} for more discussion.

This document defines a well-known URI {{!RFC8615}}, "oblivious-gateway",
which an oblivious gateway uses to receive gateway requests.

The URI is constructed using the name in the "oblivious-gateway"
SVCB parameter.

For example, the oblivious request URI for the following record:

~~~
svc.example.com. 7200  IN HTTPS 1 . (
     alpn=h2 oblivious-gateway=osvc.example.com )
~~~

would be "https://osvc.example.com/.well-known/oblivious-gateway".

Request to this resource are expected to use the content type
"message/ohttp-req", and responses are expected to use "message/ohttp-res",
as defined in {{OHTTP}}.

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

Oblivious gateways that are accessed based on SVCB discovery are required
to offer a well-known oblivious gateway request path. This is done in
part to make client-targeting attacks more difficult. If the gateway request
path is communicated in the SVCB parameters, individual clients could
receive unique paths which could be used to identify them upon making
requests via a relay. While it is still possible for different clients to
receive different gateway names, this requires provisioning more gateway
names (which has overhead in DNS configuration and TLS certificate
generation), and allows relays to more easily enforce allow-lists of
known gateway names without needing to also check request paths.

When clients fetch a gateway's configuration using the well-known URI,
they can expose their identity in the form of an IP address if they do not
connect via a proxy or some other IP-hiding mechanism. Clients SHOULD
use a proxy or similar mechanism to avoid exposing client IPs to a gateway.

# IANA Considerations {#iana}

## SVCB Service Parameter

IANA is requested to add the following entry to the SVCB Service Parameters
registry ({{SVCB}}).

| Number  | Name           | Meaning                            | Reference       |
| ------- | -------------- | ---------------------------------- | --------------- |
| TBD     | oblivious-gateway | Defines an oblivious HTTP gateway to use to access this resource  | (This document) |

## Well-Known URIs

IANA is requested to add two new entries in the "Well-Known URIs" registry {{!RFC8615}}.

### oblivious-configs

URI suffix: oblivious-configs

Change controller: IETF

Specification document: This document

Status: permanent

Related information: N/A

### oblivious-gateway

URI suffix: oblivious-gateway

Change controller: IETF

Specification document: This document

Status: permanent

Related information: N/A

--- back
