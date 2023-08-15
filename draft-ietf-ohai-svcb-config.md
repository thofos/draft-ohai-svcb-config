---
title: "Discovery of Oblivious Services via Service Binding Records"
abbrev: "Oblivious Services in SVCB"
category: std
stream: IETF

docname: draft-ietf-ohai-svcb-config-latest
area: "Security"
workgroup: "Oblivious HTTP Application Intermediation"
keyword: Internet-Draft
venue:
  group: "Oblivious HTTP Application Intermediation"
  type: "Working Group"
  mail: "ohai@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ohai/"
  github: ietf-wg-ohai/draft-ohai-svcb-config

v: 3

author:
 -
    name: Tommy Pauly
    organization: Apple Inc.
    email: tpauly@apple.com
 -
    name: Tirumaleswar Reddy
    organization: Nokia
    email: kondtir@gmail.com

normative:

informative:


--- abstract

This document defines a parameter that can be included in SVCB and HTTPS
DNS resource records to denote that a service is accessible using Oblivious
HTTP, by offering an Oblivious Gateway Resource through which to access the
target. This document also defines a mechanism to learn the key configuration
of the discovered Oblivious Gateway Resource.

--- middle

# Introduction

Oblivious HTTP {{!OHTTP=I-D.draft-ietf-ohai-ohttp}} allows clients to encrypt
messages exchanged with an Oblivious Target Resource (target). The messages
are encapsulated in encrypted messages to an Oblivious Gateway Resource
(gateway), which gates access to the target. The gateway is accessed via an
Oblivious Relay Resource (relay), which proxies the encapsulated messages
to hide the identity of the client. Overall, this architecture is designed
in such a way that the relay cannot inspect the contents of messages, and
the gateway and target cannot learn the client's identity from a single
transaction.

Since Oblivious HTTP deployments typically involve very specific coordination
between clients, relays, and gateways, the key configuration is often shared
in a bespoke fashion. However, some deployments involve clients
discovering targets and their associated gateways more dynamically.
For example, a network might operate a DNS resolver that provides more optimized
or more relevant DNS answers and is accessible using Oblivious HTTP, and might
want to advertise support for Oblivious HTTP via mechanisms like Discovery of
Designated Resolvers ({{!DDR=I-D.draft-ietf-add-ddr}}). Clients can access these
gateways through trusted relays.

This document defines a way to use DNS records to advertise that an HTTP service
supports Oblivious HTTP. This advertisement is a parameter that can be included in SVCB
and HTTPS DNS resource records {{!SVCB=I-D.draft-ietf-dnsop-svcb-https}} ({{svc-param}}).
The presence of this parameter indicates that a service can act as a target and
has a gateway that can provide access to the target.

The client learns the URI to use for the gateway using a well-known
URI {{!WELLKNOWN=RFC8615}}, "ohttp-gateway", which is accessed on the
target ({{gateway-location}}). This means that for deployments that
support this kind of discovery, the gateway and target resources need to
be located on the same host.

This document also defines a way to fetch a gateway's key
configuration from the gateway ({{config-fetch}}).

This mechanism does not aid in the discovery of relays;
relay configuration is out of scope for this document. Models in which
this discovery mechanism is applicable are described in {{applicability}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Applicability {#applicability}

There are multiple models in which the discovery mechanism defined
in this document can be used.

- Upgrading regular (non-proxied) HTTP to Oblivious HTTP. In this model,
the client intends to communicate with a specific target service, and
prefers to use Oblivious HTTP if it is available. The target service
has a gateway that it offers to allow access using Oblivious
HTTP. Once the client learns about the gateway, it "upgrades"
to using Oblivious HTTP to access the target service.

- Discovering alternative Oblivious HTTP services. In this model,
the client has a default target service that it uses. For
example, this may be a public DNS resolver that is accessible over
Oblivious HTTP. The client is willing to use alternative
target services if they are discovered, which may provide more
optimized or more relevant responses.

In both deployment models, the client is configured with
a relay that it trusts for Oblivious HTTP transactions. This
relay either needs to provide generic access to gateways, or
provide a service to clients to allow them to check which gateways
are accessible.

# The ohttp SvcParamKey {#svc-param}

The "ohttp" SvcParamKey ({{iana}}) is used to indicate that a
service described in an SVCB record can be accessed as a target
using an associated gateway. The service that is queried by the client hosts
one or more target resources.

In order to access the service's target resources using Oblivious HTTP, the client
needs to send encapsulated messages to the gateway resource and the gateway's
key configuration (both of which can be retrieved using the method described in
{{config-fetch}}).

Both the presentation and wire format values for the "ohttp" parameter
MUST be empty.

Services can include the "ohttp" parameter in the mandatory parameter
list if the service is only accessible using Oblivious HTTP. Marking
the "ohttp" parameter as mandatory will cause clients that do not
understand the parameter to ignore that SVCB record.
Including the "ohttp" parameter without marking it mandatory advertises
a service that is optionally available using Oblivious HTTP. Note also
that multiple SVCB records can be provided to indicate separate
configurations.

The media type to use for encapsulated requests made to a target service
depends on the scheme of the SVCB record. This document defines the
interpretation for the "https" {{SVCB}} and "dns" {{!DNS-SVCB=I-D.draft-ietf-add-svcb-dns}}
schemes. Other schemes that want to use this parameter MUST define the
interpretation and meaning of the configuration.

## Use in HTTPS service records

For the "https" scheme, which uses the HTTPS RR type instead of SVCB,
the presence of the "ohttp" parameter means that the target
being described is an Oblivious HTTP service that is accessible using
the default "message/bhttp" media type {{OHTTP}}
{{!BINARY-HTTP=RFC9292}}.

For example, an HTTPS service record for svc.example.com that supports
a Oblivious HTTP could look like this:

~~~
svc.example.com. 7200  IN HTTPS 1 . ( alpn=h2 ohttp )
~~~

A similar record for a service that only supports Oblivious HTTP
could look like this:

~~~
svc.example.com. 7200  IN HTTPS 1 . ( mandatory=ohttp ohttp )
~~~

## Use in DNS server SVCB records

For the "dns" scheme, as defined in {{DNS-SVCB}}, the presence of
the "ohttp" parameter means that the DNS server being
described has a DNS over HTTP (DoH) {{!DOH=RFC8484}} service that can
be accessed using Oblivious HTTP. Requests to the resolver are sent to
the gateway using binary HTTP with the default "message/bhttp"
media type {{BINARY-HTTP}}, containing inner requests that use the
"application/dns-message" media type {{DOH}}.

If the "ohttp" parameter is included in an DNS server SVCB record,
the "alpn" MUST include at least one HTTP value (such as "h2" or
"h3").

In order for DoH-capable recursive resolvers to function as Oblivious HTTP targets, their
associated gateways need to be accessible via a client-trusted relay.
DoH recursive resolvers used with the discovery mechanisms described
in this section can either be publicly accessible, or specific to a
network. In general, only publicly accessible DoH recursive resolvers will work
as Oblivious HTTP targets, unless there is a coordinated deployment
with a relay to access the network-specific DoH recursive resolvers.

### Use with DDR {#ddr}

Clients can discover that a DoH recursive resolvers support Oblivious HTTP using
DDR, either by querying _dns.resolver.arpa to a locally configured
resolver or by querying using the name of a resolver {{DDR}}.

For example, a DoH service advertised over DDR can be annotated
as supporting resolution via Oblivious HTTP using the following record:

~~~
_dns.resolver.arpa  7200  IN SVCB 1 doh.example.net (
     alpn=h2 dohpath=/dns-query{?dns} ohttp )
~~~

Clients still need to perform verification of oblivious DoH servers,
specifically the TLS certificate checks described in {{Section 4.2 of DDR}}.
Since the gateway and target resources for discovered oblivious services
need to be on the same host, this means that the client needs to verify
that the certificate presented by the gateway passes the required checks.
These checks can be performed when looking up the configuration on the gateway
as described in {{config-fetch}}, which can either be done directly
or via the relay or another proxy to avoid exposing client IP addresses.

Opportunistic discovery {{DDR}}, where only the IP address is validated,
SHOULD NOT be used in general with Oblivious HTTP, since this mode
primarily exists to support resolvers that use private or local IP
addresses, which will usually not be accessible when using a
relay. If a configuration occurs where the resolver is accessible, but
cannot use certificate-based validation, the client needs to ensure
that the relay only accesses the gateway and target using
the unencrypted resolver's original IP address.

For the case of DoH recursive resolvers, clients also need to ensure that they are not
being targeted with unique DoH paths that would reveal their identity. See
{{security}} for more discussion.

### Use with DNR {#dnr}

The SvcParamKeys defined in this document also can be used with Discovery
of Network-designated Resolvers (DNR) {{!DNR=I-D.draft-ietf-add-dnr}}. In this
case, the oblivious configuration and path parameters can be included
in DHCP and Router Advertisement messages.

While DNR does not require the same kind of verification as DDR, clients
that learn about DoH recursive resolvers still need to ensure that they are not being
targeted with unique DoH paths that would reveal their identity. See {{security}}
for more discussion.

# Gateway Location {#gateway-location}

Once a client has discovered that a service supports Oblivious HTTP
via the "ohttp" parameter in a SVCB or HTTPS record, it needs to be
able to send requests via a relay to the correct gateway location.

By default, the gateway for a target is defined as a well-known
resource ({{WELLKNOWN}}) on the target, "/.well-known/ohttp-gateway".

Some servers might not want to operate the gateway on a well-known URI.
In such cases, these servers can use 3xx redirection responses
({{Section 15.4 of !HTTP=RFC9110}}) to direct clients and relays to the correct
location of the gateway. Such redirects would apply both to requests
made to fetch key configurations (as defined in {{config-fetch}}) and to
encapsulated requests made via a relay.

If a client receives a redirect when fetching the key configuration from the
well-known gateway resource, it MUST NOT communicate the redirected
gateway URI to the relay as the location of the gateway to use.
Doing so would allow the gateway to target clients by encoding
unique or client-identifying values in the redirected URI. Instead,
relays being used with dynamically discovered gateways MUST use the
well-known gateway resource and follow any redirects independently of
redirects that clients received. The relay can remember such redirects
across oblivious requests for all clients in order to avoid added latency.

# Key Configuration Fetching {#config-fetch}

Clients also need to know the key configuration of a gateway before encapsulating
and sending requests to the relay.

In order to fetch the key configuration of a gateway discovered
in the manner described in {{gateway-location}}, the client issues a GET request
to the URI of the gateway specifying the "application/ohttp-keys" ({{OHTTP}})
media type in the Accept header.

For example, if the client knows an oblivious gateway URI,
"https://svc.example.com/.well-known/ohttp-gateway", it could fetch the
key configuration with the following request:

~~~
GET /.well-known/ohttp-gateway HTTP/1.1
Host: svc.example.com
Accept: application/ohttp-keys
~~~

Gateways that coordinate with targets that advertise Oblivious HTTP
support SHOULD support GET requests for their key configuration in this
manner, unless there is another out-of-band configuration model that is
usable by clients. Gateways respond with their key configuration in the
response body, with a content type of "application/ohttp-keys".

Clients can either fetch this key configuration directly, or do so via
a proxy in order to avoid the server discovering information about the
client's identity. See {{consistency}} for more discussion of avoiding key
targeting attacks.

# Security and Privacy Considerations {#security}

Attackers on a network can remove SVCB information from cleartext DNS
answers that are not protected by DNSSEC {{?DNSSEC=RFC4033}}. This
can effectively downgrade clients. However, since SVCB indications
for Oblivious HTTP support are just hints, a client can mitigate this by
always checking for a gateway configuration ({{config-fetch}})
on the well-known gateway location ({{gateway-location}}).
Use of encrypted DNS along with DNSSEC can also be used as a mitigation.

When clients fetch a gateway's configuration ({{config-fetch}}),
they can expose their identity in the form of an IP address if they do not
connect via a proxy or some other IP-hiding mechanism. In some circumstances,
this might not be a privacy concern, since revealing that a particular
client IP address is preparing to use an Oblivious HTTP service can be
expected. However, if a client is otherwise trying to hide its IP
address or location (and not merely decouple its specific requests from its
IP address), or if revealing its IP address facilitates key targeting attacks
(if a gateway service uses IP addresses to associate specific configurations
with specific clients), a proxy or similar mechanism can be used to fetch
the gateway's configuration.

When discovering designated oblivious DoH recursive resolvers using this mechanism,
clients need to ensure that the designation is trusted in lieu of
being able to directly check the contents of the gateway server's TLS
certificate. See {{ddr}} for more discussion, as well as the Security
Considerations of {{DNS-SVCB}}.

## Key Targeting Attacks {#consistency}

As discussed in {{OHTTP}}, client requests using Oblivious HTTP
can only be linked by recognizing the key configuration. In order to
prevent unwanted linkability and tracking, clients using any key
configuration discovery mechanism need to be concerned with attacks
that target a specific user or population with a unique key configuration.

There are several approaches clients can use to mitigate key targeting
attacks. {{?CONSISTENCY=I-D.ietf-privacypass-key-consistency}} provides an overview
of the options for ensuring the key configurations are consistent between
different clients. Clients SHOULD employ some technique to mitigate key
targeting attacks, such as the option of confirming the key with a shared
proxy as described in {{CONSISTENCY}}. If a client detects that a gateway
is using per-client targeted key configuration, the client can stop using
the gateway, and potentially report the targeting attack to let other
clients avoid using this gateway in the future.

## dohpath Targeting Attacks

For oblivious DoH servers, an attacker could use unique `dohpath` values
to target or identify specific clients. This attack is very similar to
the generic OHTTP key targeting attack described above.

Clients SHOULD mitigate such attacks. This can be done with a
check for consistency, such as using a mechanism described in {{CONSISTENCY}}
to validate the `dohpath` value with another source. It can also be
done by limiting the the allowable values of `dohpath` to a single
value, such as the commonly used "/dns-query{?dns}".

# IANA Considerations {#iana}

## SVCB Service Parameter

This document adds the following entry to the SVCB Service Parameters
registry ({{SVCB}}).

| Number  | Name           | Meaning                            | Reference       |
| ------- | -------------- | ---------------------------------- | --------------- |
| 8 (Early Allocation)     | ohttp          | Denotes that a service operates an Oblivious HTTP target  | (This document) |

## Well-Known URI

IANA is requested to add one new entry in the "Well-Known URIs" registry {{WELLKNOWN}}.

URI suffix: ohttp-gateway

Change controller: IETF

Specification document: This document

Status: permanent

Related information: N/A

--- back
