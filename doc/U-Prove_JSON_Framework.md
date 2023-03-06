# U-Prove JSON Framework

This document defines a JSON-based framework for the use of the [U-Prove technology](https://www.microsoft.com/uprove). It defines formats for the U-Prove artifacts and token type profiles that can easily be deployed in web environments.

## U-Prove Technology Overview

This section summarizes the U-Prove features specified in the [U-Prove Cryptographic Specification [UPCS]](./U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf).

A U-Prove token (UPT) is a cryptographically protected container of claims (a.k.a. attributes) that is issued to a Prover (a.k.a. the client) by an Issuer (a.k.a. the Identity Provider), and presented to a Verifier (a.k.a. the Relying Party). Each UPT corresponds to a private key needed to present the token, and contains an Issuer’s signature that attests to its origin and integrity.

A UPT is conceptually similar to a X.509 certificate or a key-bound JSON Web Token (JWT), with two major differences:

1. A UPT is generated jointly by the Prover and the Issuer in an interactive issuance protocol. It contains no correlation handles identifiable by the Issuer outside the certified claim values. In particular, its public key and Issuer’s signature have been randomized by the Prover in the issuance protocol; as such, these values are never seen by the Issuer. Consequently, the Prover cannot be tracked on the basis of these values when using the UPT, even if the Issuer and the Verifiers collude (even if they are the same entity).

2. When presenting a UPT, the Prover can hide any subset of the encoded claims, without invalidating the Issuer’s signature generated on all the claims. In particular, the Prover can hide all the claims (merely proving ownership of the UPT) or disclose all of them (like presenting a signed JWT or a X.509 certificate).

As illustrated below, a Prover typically gets multiple UPTs certifying the same set of claims in one instance of the issuance protocol (multiple UPTs are obtained to preserve unlinkability between UPT presentations). To present any subset of the certified claims to a Verifier (immediately after issuance for on-demand tokens, or a later time for long-lived tokens), the Prover creates a presentation proof for a selected UPT by applying the corresponding private key to a cryptographic challenge.

Optionally, an Issuer can issue a UPT to a Prover in such a manner that the Prover cannot use the token without the assistance of a trusted Device (e.g., a smartcard, a mobile phone, or an online server). The Device can efficiently protect multiple tokens issued by any number of Issuers, and can dynamically (i.e., at token use time) enforce policies on behalf of the Issuer, Verifiers, or third parties — all without being able to compromise the Prover’s privacy and without needing to interact with the Issuer.

For more information about the U-Prove technology, see the [U-Prove Technology Overview](./U-Prove%20Technology%20Overview%20V1.1%20Revision%202.pdf).

## Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC2119](https://www.rfc-editor.org/rfc/rfc2119).

BASE64URL(X) denotes the base64url encoding of octet string representation of X, as defined in section 5 of [RFC4648](https://www.rfc-editor.org/rfc/rfc4648) (Note that the base64url encoding of the empty octet string is the empty string.) The octet string representation of mathematical values X (elliptic curve points of $Gq$ and elements of $Z_q$) are obtained as explained in section 2.2 of the [UPCS](./U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf).


## U-Prove JSON profile

This section defines a JSON profile for the U-Prove artifacts. Issuer parameters MUST use the [U-Prove Recommended Parameters Profile [UPRPP]](./U-Prove%20Recommended%20Parameters%20Profile%20V1.1%20Revision%202.pdf).

### Issuer Parameters

An Issuer generates its parameters as described in section 2.3.1 of the [UPCS](./U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf) using a group from the [UPRPP](./U-Prove%20Recommended%20Parameters%20Profile%20V1.1%20Revision%202.pdf), and encodes them as JSON Web Key objects ([RFC7517](https://www.rfc-editor.org/rfc/rfc7517)) with the following parameters:
* The key type parameter `kty` MUST be set to "UP".
* The algorithm parameter `alg` MUST be set to "UP115" corresponding to the current version of the U-Prove Cryptographic specification.
* The curve parameter `crv` corresponds to the Issuer parameters' group description and hash algorithm identifier $\texttt{UID}_H$ specified in the [UPRPP](./U-Prove%20Recommended%20Parameters%20Profile%20V1.1%20Revision%202.pdf); the following three values are supported:
  * "P-256": corresponds to the `P-256` group description (identified by OID `1.3.6.1.4.1.311.75.1.2.1`), with a $\texttt{UID}_H$ of "SHA-256".
  * "P-384": corresponds to the `P-384` group description (identified by OID `1.3.6.1.4.1.311.75.1.2.2`), with a $\texttt{UID}_H$ of "SHA-384".
  * "P-521": corresponds to the `P-521` group description (identified by OID `1.3.6.1.4.1.311.75.1.2.3`), with a $\texttt{UID}_H$ of "SHA-512".
* The key identifier parameter `kid` MUST be set to BASE64URL($\texttt{UID}_P$) value (TODO: explain how to generate it)
* The specification parameter `spec` is a JSON object containing application-specific parameters. The Issuer parameters specification field $S$ is obtained by taking the UTF8 encoding of the `spec` JSON object. The `spec` MUST contain a parameter `n` set to an integer value between 0 and 50 inclusively indicating how many attributes can be issued with these Issuer parameters. It MAY contain a parameter `expType` describing how to interpret the expiration whose possible values are `sec`, `hour`, `day`, `mon`; see the [token validity period](#token-validity-period).
* The `g0` parameters is BASE64URL($g_0$).
* The optional `e` parameter contains an array of integers (either 0 or 1) representing the Issuer parameters' $e$ values. If omitted, it is assumed that $e$ values are 1 (i.e., attributes are hashed).

The private key can be encoded directly into the JWK object by adding the `y0` parameter set to BASE64URL($y_0$) private key value; this value MUST be kept secret by the Issuer. 

It is RECOMMENDED to publish the public JWK in a JWK set (see section 5 of [RFC7517](https://www.rfc-editor.org/rfc/rfc7517)), at a well-known URL `[ISSUER_URL]/.well-known/jwks.json`, where `[ISSUER_URL]` is a unique URL identifying the Issuer.

### Issuance protocol

The issuance protocol is described in section 2.5 of the [UPCS](./U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf). The protocol inputs are application-specific; application profiles (including [the ones](#token-profiles) defined in this framework) can further define token contents. The protocol messages are JSON objects defined in the following subsections. Many U-Prove tokens MAY be issued in parallel; the number of issued tokens N is application-specific (it can be requested by the Prover, but is ultimately decided by the Issuer). It MUST be conducted over HTTPS.

#### First issuance message

The first issuance message (to issue N tokens) is a JSON object with the following properties:
* `sZ` is set to the BASE64URL($\sigma_Z$) value
* `sA` is an array containing the N BASE64URL($\sigma_A$) values
* `sB` is an array containing the N BASE64URL($\sigma_B$) values

#### Second issuance message

The second issuance message (to issue N tokens) is a JSON object with the following property:
* `sC` is an array containing the N BASE64URL($\sigma_C$) values

#### Third issuance message

The third issuance message (to issue N tokens) is a JSON object with the following property:
* `sR` is an array containing the N BASE64URL($\sigma_R$) values

### U-Prove Token

U-Prove tokens are described in section 2.3.3 of the [UPCS](./U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf); the Prover generates them at the end of the [issuance protocol](#issuance-protocol). U-Prove tokens are encoded as JSON objects with the following parameters:
* `UIDP` is set to BASE64URL($\texttt{UID}_P$)
* `h` is set to BASE64URL($h$)
* `TI` is set to BASE64URL(UTF8($TI$)), where $TI$ is a JSON object encoding application-specific token information parameters
  * The token information object MAY contain an expiration value `exp`; see the [token validity period](#token-validity-period) section
* `PI` is set to BASE64URL(UTF8($PI$)), where $PI$ is a JSON object encoding application-specific Prover information parameters
* `sZp` is set to BASE64URL($\sigma_Z'$)
* `sCp` is set to BASE64URL($\sigma_C'$)
* `sRp` is set to BASE64URL($\sigma_R'$)

The corresponding secret key value $\alpha^{-1} MUST be kept secret by the Prover.

### Presentation protocol

The Prover creates a presentation proof, described in section 2.6 of the [UPCS](./U-Prove%20Cryptographic%20Specification%20V1.1%20Revision%204.pdf), using a U-Prove token and an application-specific presentation message $m$. It is encoded as a JSON object with the following parameters:
* `a` is set to BASE64URL($a$)
* `r` is an array containing the d+1 BASE64URL($r_i$) responses for the undisclosed attributes ($r_0$ followed by the d responses for each undisclosed attributes, ordered by index number)
* `A` is an object containing key-value pairs for each disclosed attributes (the key is an attribute index $i$, the value is the attribute $A_i$) TODO: change the implementation

A U-Prove token and a presentation proof can be packaged into one presentation object with the following parameters:
* `upt`: the JSON representation of a [U-Prove token](#u-prove-token)
* `pp`: the JSON representation of a presentation proof as described above

TODO: define as a JWS?

## Security Considerations

### Token validity period

U-Prove can be either on-demand (ephemeral) or long-lived.

On-demand token are requested from the Issuer by the Prover and immediately presented to the Verifier. A Verifier MAY specify a presentation challenge to be included in the token's Prover Information field, which will insure that the token was freshly obtained by the Prover.

Long-lived token should can be used multiple time. Tokens MAY contain an expiration date to limit their validity period; the expiration date SHOULD be encoded in a manner that protects the privacy of users without introducing undesirable correlation elements. The following approach is RECOMMENDED:
* Issuer decides on a validity period type: seconds (`sec`), hours (`hour`), days (`day`), months (`mon`); and encodes it in its Issuer parameters [specification](#issuer-parameters).
* For each token, the numerical expiration date is encoded in the [token information](#u-prove-token) field, using the `exp` parameter. The `exp` value depends on the expiration type: it indicates the number of seconds (`sec`), hours (`hour`), days (`day`) or months (`mon`) since the Unix epoch (1970-01-01T00:00:00Z). Note that if `expType` is set to `sec`, then the expiration date is of the same format as JSON Web Tokens (see section 4.1.4 of [RFC7519](https://www.rfc-editor.org/rfc/rfc7519)).

## Token profiles

Token profiles constrains the U-Prove features to simplify their use for specific scenario.

### Bare U-Prove token profile

Bare tokens are U-Prove tokens without any attributes. They are simple to issue, present, and verify and do not require extra complications at the application level to define attribute disclosure logic. They can be used in a variety of use cases: for access/login tokens, to encode tickets/vouchers.
