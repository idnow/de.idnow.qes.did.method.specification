# QES DID Method Specification

# Introduction

## Background

The existing eIDAS regulation has been enabling trust in electronic transactions between different entities such as individuals, organizations and government entities across European Member States. Technical specification as part of the new proposed regulation is pending with the intent to bring this in the form of a EU Digital Identity Wallet (EUDIW) for individuals and businesses. 

However until the specification is complete, the existing eIDAS regulation and the DID standard don't work together and we believe that a bridge would beneficial as it would allow:

* Enabling trust through EU Trust List: By combining the way the eIDAS technical specification works with the DID and Verifiable Credentials specifications it allows to tie the trust back to the EU Trust List.
* Clearer Liability: Within the eIDAS regulation liability is defined and adding necessary element this DID-core specification would enable auditability and the liability bound to each entity involved.
* Meeting technical requirements of eIDAS: By updating the DID-core specification with new elements and use of specific algorithm, it would allow for compliance with existing eIDAS regulation.
* Long term storage and validation of Verifiable Credentials: In conjunction with a new DID Method specification, it enables storage in a Verifiable Credentials ecosystem [(ref)](https://www.w3.org/TR/did-core/#bib-vc-data-model) of Verifable Credential that can be validated at any point in time (even years after issuance) even beyond time where original parties involved such as a Qualified Trusted Service Provider (as defined in eIDAS regulation) go out of business.

Under eIDAS, a set of standards have been laid out with the intent to allow creation of Qualified Electronic Signature (QES) that can be trusted and used for conducting official business online and across borders between EU member state [(ref)](https://en.wikipedia.org/wiki/Qualified_electronic_signature). This specification defines a new DID method which aims to bridge the gap between the DID world and the eIDAS regulation by applying Qualified Electronic Signature.

The QES DID method specification conforms to the requirements specified in the DID specification currently published by the W3C Credentials Community Group. For more information about DIDs and DID method specifications, please see the [DID Primer](https://github.com/WebOfTrustInfo/rebooting-the-web-of-trust-fall2017/blob/master/topics-and-advance-readings/did-primer.md) and [DID Spec](https://w3c-ccg.github.io/did-spec/).

**Note 1:** As eIDAS also defines a centralized trust structure with Trust Service Providers and an EU Trust List, this DID method assumes a certain centralized structure and is not a fully decentralized approach. Nevertheless, for most regulated use cases, a fully decentralized model is not feasible or even desirable. We are aware that there might be different views on these topics.

**Note 2:** As the EUDIW technical specification is unknown at the time of writing this approach, it may be that the technical specification takes a radically different route. As such this specification should be seen as informative to foster a common understanding.

## Glossary

* **Holder:** Individual or entity owning the Verifiable Credentials issued to him/her (Ref: [Holder](https://www.w3.org/TR/vc-data-model/#dfn-holders)).
* **Verifier:** Individual or entity receiving a Verifiable Credential from the Holder in order to validate it (Ref: [Verifier](https://www.w3.org/TR/vc-data-model/#dfn-verifier)).
* **Issuer:** Individual or entity issuing a Verifiable Credential to the Holder (Ref: [Issuer](https://www.w3.org/TR/vc-data-model/#dfn-issuers)).
* **DID Registrar:** A software and/or hardware component that implements the DID create/update/deactivate functions (Ref: [identity.foundation](https://identity.foundation/did-registration/#terminology)).
* **DID Resolver:** A DID resolver is a software and/or hardware component that performs the DID resolution function by taking a DID as input and producing a conforming DID document as output. (Ref: [DID Resolver](https://www.w3.org/TR/did-core/#dfn-did-resolvers)).
***DID Registry:** Also referred as Verifiable data registry in did-core (Ref: [Verifiable data registry](https://www.w3.org/TR/did-core/#dfn-verifiable-data-registry)).
* **Qualified Electronic Seal:** A qualified electronic seal is an electronic seal that is compliant to EU Regulation No 910/2014 (eIDAS Regulation) for electronic transactions within the internal European market. It enables to verify the issuer of a document over long periods of time. Qualified electronic seals can be considered as digital equivalent to seals of legal entities on paper. According to the eIDAS regulation, a qualified electronic seal must be created by a qualified electronic device and based on a qualified certificate for electronic seal. (Ref: [Electronic Seal](https://en.wikipedia.org/wiki/Electronic_seal)). 
* **Qualified Electronic Signature (eIDAS):** A qualified electronic signature is an electronic signature that is compliant with EU Regulation No 910/2014 (eIDAS Regulation) for electronic transactions within the internal European market. It enables to verify the authorship of a declaration in electronic data exchange over long periods of time. Qualified electronic signatures can be considered as a digital equivalent to handwritten signatures. (Ref: [Qualified Electronic Signature](https://en.wikipedia.org/wiki/Qualified_electronic_signature)).
* **JAdES:** Format of eIDAS compliant AdES signatures built on JSON Web Signatures (JWS hereinafter) as specified in [IETF RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515). (Ref: [JAdES Signature format for AdES signatures](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf) (JAdES signatures hereinafter) built on JSON Web Signatures).
* **Level of Assurance (LoA):** The eIDAS term “level of assurance” refers to the degree of confidence in the claimed identity of a person – how certain a service provider can be that it is you the one using your eID to authenticate to the service, not someone else pretending to be you. In other terms, it refers to the difficulty one would have trying to use someone else’s eID to access an online service.

The three Levels of Assurance (LoA) (ref: [eIDAS Level of Assurance](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eIDAS+Levels+of+Assurance), [Regulation No 910/2014](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32014R0910)) are as follows:

* **Low:** for instance, enrolment is performed by self-registration in a web-page, without any identity verification;
* **Substantial:** for instance, enrolment is performed by providing and verifying identity information, and authentication by using a user name and a password and a one-time password sent to your mobile phone;
* **High:** for instance, enrolment is performed by registering in person in an office, and authentication by using a smartcard, like a National ID Card.

The eIDAS regulation (ref: [Regulation No 910/2014](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32014R0910)) also defines (qualified) trusted service providers:

* **Trusted Service Provider (TSP):** A trust service provider (TSP) is a natural or a legal person who provides one or more trust services (TS) either as a qualified or as a non-qualified trust service provider. (Ref: [What does TSP mean?](https://ec.europa.eu/digital-building-blocks/wikis/display/ESIGKB/What+does+QTSP+or+QTS+mean), [Regulation No 910/2014](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32014R0910)).
* **Qualified Trusted Service Provider (qTSP):** A qualified trust service provider (QTSP) is a TSP who provides one or more qualified trust services (QTS) and is granted the qualified status by the national supervisory body. The decision of the supervisory body to grant the qualified status is reflected in the corresponding national Trusted List. In this respect, QTSPs are mandatorily listed in the corresponding national Trusted List while TSP could be but are not mandatorily listed in these Trusted Lists. (Ref: [What does qTSP mean?](https://ec.europa.eu/digital-building-blocks/wikis/display/ESIGKB/What+does+QTSP+or+QTS+mean), [Regulation No 910/2014](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=CELEX:32014R0910)).

## Authors and contributors

Armin Bauer, IDnow

Sebastian Elfors, IDnow

Martin Kocan, Accenture

Thomas Moretti, Accenture

Jaroslav Saxa, Accenture

# QES DID Method Specification

## Target System(s)

This DID method applies to:
* All qualified trust service providers under the eIDAS regulation which can create qualified electronic signatures and seals.
* All verifiers that can request and verify credentials and qualified electronic signatures and seals.
* All end-users for whom the DID and DID Document is hosted by trust service providers under the eIDAS regulation.

## Method Name

The namestring that shall identify this DID method is: `qes`. 

QES is the generalized acronym for this DID method and stands for Qualified Electronic Signature which specifies the technical implementation of an eIDAS compliant signature. However depending on context such signature may have different intent/meaning and have different naming from regulation standpoint:
* Qualified Electronic Seal when the signature refers to the Issuer or Verifier. 
* Qualified Electronic Signature when the signature refers to the Holder.

A DID that uses this method MUST begin with the following prefix: `did:qes`. Per the DID specification, this string MUST be in lowercase. The remainder of the DID, after the prefix, is specified below. 

`did = "did:qes:" method-specific-id`

***Note:** The method-specific identifier “web” below is influenced by the approach taken in the DID method “did:web” where the hostname as fully qualified domain name is contained in the method specific id, but differs for example in the resolution where a well-known document path is not expected to be used.*

The method specific identifier consists of the following parts separated by semi-colon:

```
method-specific-id 	= resolution-method “:” host-name [port] “:” UUID
resolution-method 	= “web”
host-name		= *( domain-label "." ) top-label
port			= “%x3A” port-number
UUID			= “0x” 64*HEXDIG
```

* Resolution Method – currently supported methods:
    * “web” – DID Document is resolved over HTTPs.
**Note:** Resolution method is included in the method specific identifier for possibility of future extension to ledger-based solution.
* Host Name - Fully qualified domain name that is secured by a TLS/SSL certificate. The formal rules describing valid domain name syntax are described in [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035), [RFC1123](https://datatracker.ietf.org/doc/html/rfc1123), and [RFC2181](https://datatracker.ietf.org/doc/html/rfc2181). 
    * It *MUST NOT* include IP addresses. 
* Port - *MAY* be included and the colon MUST be URL-encoded to prevent a conflict with next part of the identifier. 
* UUID – Universally Unique Identifier, MUST be generated by the qualified Trust Service Provider (qTSP). As an example, UUID can be generated from the Public Key of the DID Document Authentication Key Pair by hashing with SHA-256.

**Examples:**
```
did:qes:web:example.com: d6dbf70eecf4257071aab2d8cb8b89e42b84b298ab6fef4bc07de49a6ac2ade4
did:qes:web:example.com%3A3000: d6dbf70eecf4257071aab2d8cb8b89e42b84b298ab6fef4bc07de49a6ac2ade4
```

# DID Document

DID Document for QES DID Method may / must contain the following fragments.

## Context (Mandatory)

Context for the DID Method is extended as follows:

```
"@context": [
    "https://www.w3.org/ns/did/v1",
    "http://w3id.org/security/suites/jws-2020/v1",
    "https://identity.foundation/didcomm-messaging/service-endpoint/v1",
    "http://www.example.org/did/schemas/eidas-2020/v1"  
]
```

## DID (Mandatory)

DID format has been specified in the previous chapter.

**Example:**

`"did": "<userDID>"`

## Service (Mandatory)

**Example:**
```
"service": [
     {
        "id": "<userDID>#didcomm-1",
        "type": "didcomm-messaging",
        "serviceEndpoint": "<walletBackendServiceEndPoint>",
        "accept": [
            "didcomm/v2",
            "didcomm/aip2;env=rfc587"
        ],
        "recipientKeys": [ "<userDID>#userDIDComm-Key-p256-1" ],
        "routingKeys": [ "did:example:somemediator#somekey"]
    }
]
```

## Verification Method List

Depending on the Level of Assurance (“Low, “Substantial”, “High”) expected for a specific use case the implementation of this design may omit certain Verification Methods. Indeed in the level “Low” could be met from a technical standpoint by utilizing verification methods that already exist in the DID specifications.

However in the event an issuer, a holder or a verifier would like to meet level of assurance “Substantial” or “High”, additional verification method will be necessary to issue, present or validate a eIDAS compliant signature (JAdES Signature).

Both subgroups are defined hereafter.

### Verification Methods for eIDAS “Low” or “Substantial”

#### Verification Method for DID Document Authentication

Refer to Section 5.3.1 Authentication for more information.

Each DID Document MUST contain one such Verification Method. Its Public Key may be used to generate UUID part of the DID. The DID Authentication Key Pair (DIDAuth Private/Public keys) is here generated and stored in HSM of the Trust Service Provider.

**Example:**
```
{
    "id": "<userDID>#user-DIDAuth-Key-p256-1",
    "type": "JsonWebKey2020",
    "controller": "<Userdid>#user-DIDAuth-Key-p256-1",
    "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_xzoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgKxoI4ZiajO8jPRZDldVhqFpYoo"
     }
}
```

#### Verification Method for Verifiable Credentials Issuance

The Verifiable Credential assertion key pair (VCAssert key) is used to validate the Verifiable Credential against the public key exposed by the Issuer in its DID Document.
  
Only Issuers of Verifiable Credentials need such Verification Method.

**Example:**
```
{
    "id": "<issuerDID>#issuer-VCAssert-Key-p256-1",
    "type": "JsonWebKey2020",
    "controller": "<issuerDID>#issuer-VCAssert-Key-p256-1",
    "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "L0cfsdfsrjMN1g0Ih4dsdssYAJ_xzoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmfdfdEJYi7dsdIDhgKxoI4ZiajO8jPRZDldVhqFpYoo"
    }
}
```

#### Verification Method for Verifiable Presentation

The Verifiable Presentation Key (VPAuth Key) pair is used in this section for authentication purposes (See Verification Relationships section), to authenticate ownership of the Verifiable Presentation provided by the Holder to the Verifier.

Only the Holder of Verifiable Credential expecting to provide a Verifiable Presentation derived from it, need such Verification Method, it proves ownership of the Verifiable Credential through the Verifiable Presentation proof.

**Example:**

```
{
    "id": "<userDID>#user-VPAuth-Key-p256-1",
    "type": "JsonWebKey2020",
    "controller": "<Userdid>#user-VPAuth-Key-p256-1",
    "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_xzoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgKxoI4ZiajO8jPRZDldVhqFpYoo"
    }
}
```

### Verification Methods for eIDAS LoA “High”

#### Verification Method for DID Document Proof Assertion (eIDAS)

See [W3C DID section 5.3.2 Assertion](https://www.w3.org/TR/did-core/#assertion) for more information.

In relation with the eIDAS regulation, each DID Document MUST contain one such Proof Assertion Method. It is referenced from the Proof of the DID Document as well as in the proof of the Verifiable Credential.

In order to comply with eIDAS regulation and the use of compliant proof, a new type of proof must be defined via the Verification Method.

Type is the newly defined `EidasJAdESValidation2022` (see section [JAdES Proofs](#jades-proofs)).

Verification Method does not contain any Public Key as the proofValue contains all the crypto material needed for verification.

**Example:**
```
{
    "id": "<userDID>#user-DIDDocProofAssert-JAdESValidation-1",
    "type": "EidasJAdESValidation2022",
    "controller": "<userDID>#user-JAdESAuth-1"
}
```

See section [JAdES Proofs](#jades-proofs) for more information.

#### Verification Method for Verifiable Credentials Issuance Qualified Electronic Signature (eIDAS)

In relation with the eIDAS regulation this time, only Issuers of Verifiable Credentials need such Verification Method if it is required to fulfill Level of Assurance Substantial or High (according to the eIDAS regulation).

Type is the newly defined `EidasJAdESValidation2022` (see section [JAdES Proofs](#jades-proofs)).

Verification Method does not contain any Public Key as the proofValue contains all the crypto material needed for verification.

**Example:**

```
{
   "id": "<issuerDID>#issuer-VCAssert-JAdESValidation-1",
   "type": "EidasJAdESValidation2022",
   "controller": "<issuerDID>#issuer-VCAssert-JAdESValidation-1"
}
```

See section [JAdES Proofs](#jades-proofs) for more information.

#### Verification Method for Verifiable Presentation Qualified Electronic Signature (eIDAS)

Similar to "Verification Method - Verifiable Presentation" but in relation with the eIDAS regulation this time, the Holder of a Verifiable Credential issued by a Trusted Service Provider needs such Verification Method to fulfill Level of Assurance Substantial or High by providing the means to validate a JAdES signature. 

Type is the newly defined `EidasJAdESValidation2022` (see section [JAdES Proofs](#jades-proofs)).

Verification Method does not contain any Public Key as the proofValue contains all the crypto material needed for verification, following the specification for JAdES (see section [JAdES Proofs](#jades-proofs)).

**Example:**

```
{
    "id": "<userDID>#user-VPAuth-JAdESValidation-1",
    "type": "EidasJAdESValidation2022",
    "controller": "<userDID>#user-VPAuth-JAdESValidation-1"
}
```

See section [JAdES Proofs](#jades-proofs) for more information.

## Verification Relationships

An expression of the relationship between the DID Subject and a Verification Method. For more information please refer to section [5.3 Verification Relationships of the DID Specification](https://www.w3.org/TR/did-core/#verification-relationships).

The following types are used by the DID Method:

**Authentication:** Please refer to section [5.3.1 Authentication of the DID Specification](https://www.w3.org/TR/did-core/#authentication).

*	**VPAuth-{Key}:** Used by the Holder for creating the proof signature on a Verifiable Presentation, which authenticates the Holder to a Verifier( See section Verification Method for Verifiable Presentation and Verification Method for Verifiable Presentation Qualified Electronic Signature). 
Key value depends on Verification Method being used where:
    *	**P256-1:** Refers to the authentication of the Verifiable Presentation key stored on the holder’s device secure element, thus proving ownership of Verifiable Presentation.
    *	**JAdESValidation-1:** Refers to the validation of a JAdES signature linked  to the Verifiable Presentation, it is signed by a Qualified Certificate (containing the DID Id as attribute) generated by the qTSP for the DID Subject at the time of signing and then deleted, allowing to authenticate the DID Subject against the Verifiable Presentation.
*	**DIDAuth:** Used to authenticate subject against a DID Document. See section Verification Method for DID Document Authentication

**Assertion Method:**
Please refer to section [5.3.2 Assertion of the DID Specification](https://www.w3.org/TR/did-core/#assertion).
*	**VCAssert-{Key}:** Used to assert Verifiable Credentials including assertion of JAdES Signature. See sections Verification Method for Verifiable Credentials Issuance and Verification Method for Verifiable Credentials Issuance Qualified Electronic Signature.
***Note:** Key value depends on Verification Method being used.*
    *	**P256-1:** Refers to the assertion of a Verifiable Credential against its issuer for LoA Low.
    *	**JAdESValidation-1:** Refers to the validation of a JAdES signature linked  to the Verifiable Credential, it is signed by the qTSP’s certificate, allowing to authenticate the DID Subject against the Verifiable Credential.
*	**DIDDocProofAssert:** Used to assert DID Document. DIDDocProofAssert assertion method is used by holder and verifier to verify integrity of the document and validate the entity acting as the DID Registrar that signed the DID Document (typically a qTSP). Verification Method for DID Document Proof Assertion (eIDAS)
**Note:** Key value depends on what Verification Method is being used.

**Example:**

```
"authentication": [
    "<userDID>#user-DIDAuth-Key-p256-1",
    "<userDID>#user-VPAuth-JAdESValidation-1",
    "<userDID>#user-VPAuth-Key-p256-1"
],
"assertionMethod": [
    "<userDID>#user-DIDDocProofAssert-JAdESValidation-1",
    "<issuerDID>#issuer-VCAssert-Key-p256-1",
    "<issuerDID>#issuer-VCAssert-JAdESValidation-1"
],
```

### Key Agreement List

At least one Key Agreement needs to be defined for allowing message exchange between two parties (e.g. DIDComm).

**Example:**

```
"keyAgreement": [
    {
        "id": "<userDID>#user-DIDComm-Key-p256-1",
        "type": "JsonWebKey2020",
        "controller": "<userDID>#user-DIDComm-Key-p256-1",
        "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
            "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
        }
    }
]
```

## Proof (Mandatory)

**Example:**

```
"proof": {
    "type": "EidasJAdESSignature2020",
    "created": "2020-06-22T14:11:44Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "<userDID>#user-DIDDocProofAssert-JAdESValidation-1",
    "proofValue": "BD21J4fdlnBvBA+y6D...fnC8Y="
}
```

# JAdES Proofs

New type for Verification Method: `EidasJAdESSignature2022` based on technical specification [ETSI TS 119 182-1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf).

## Verification Method

```
"verificationMethod": [
{
    "id” : <verificationMethod#EidasJAdESValidation2022>,
     "type” : "EidasJAdESValidation2022"
}]

type = “EidasJAdESValidation2022“
```

* Does not contain neither *Certificate* nor *Public Key/JWK* – JAdES Signature itself contains necessary validation material (B-LT/B-LTA).
    * **B-LT** provides requirements for the incorporation of all the material required for validating the signature in the signature document. 
    * **B-LTA** provides requirements for the incorporation of electronic time-stamps that allow validation of the signature long time after its generation.
* Within the JAdES Signature, the Advanced Certificate used to generate the signature must contain as the Subject a Pseudonym attribute representing the complete DID Identifier.

A Verifier must validate the signature itself, the certificate chain (embedded) as well as the Common Name.

## Proof

```
"proof": [
{ 
    "type” : ”EidasJAdESSignature2022", 
    "created” : "2020-11-05T19:23:24Z"
    "verificationMethod” : <verificationMethod#type:EidasJAdESValidation2022>,
    "proofPurpose” : "assertionMethod” / “authentication”,
    "proofValue” : BASE64URL(JAdES signature JWS)
} ]

type = ”EidasJAdESSignature2022”
proofValue = BASE64URL (JAdES signature JWS)
```

| **Attributes** | **Set/Determined Values** | **JWS tags** |
| ----------- | ----------- | ----------- |
| **JWS Serialization Type** | **JSON / FLATTENED_JSON** / COMPACT |   |
| **Signature Level** | B-B/ B-T / **B-LT** / **B-LTA** | &lt;sigT&gt;, &lt;sigTST&gt;, &lt;tstVD&gt;, &lt;xVals&gt;, &lt;rVals(CRL/OSCP)&gt; |
| **Signature Packaging** | **DETACHED** / ENVELOPING |  |
| **Digest Algorithm** | **SHA256** | &lt;x5t#S256&gt; |
| **Signing Certificate** | &lt;signingKey&gt;.**Certificate** | &lt;x5c&gt;, &lt;xVals&gt;, &lt;alg&gt; |
| **Certificate Chain** | &lt;signingKey&gt;.**CertificateChain** | &lt;x5c&gt;, &lt;xVals&gt; |
| **Signature Algorithm** | &lt;Certificate&gt;.**SignatureAlgorithm** | &lt;alg&gt; |

Reference: [ETSI TS 119 182](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf).

# DID Method Operations

## Read (Resolve)

Resolution of DID Document is done through the following steps:

![1  resolve-did](https://user-images.githubusercontent.com/107480753/174029383-53ad2132-8d89-4a5d-aa24-103b598d19f7.png)

**Notes:**

Generate URL from DID:
* If the DID is URL Encoded, decode the colon and the port after the colon.
* Generate an HTTPs URL to the expected location of the DID Document by prepending https://.
* Append /&lt;UUID&gt;.
* Append /did.json to complete the URL.

When performing the DNS resolution during the HTTP GET request, the client *SHOULD* utilize [RFC8484](https://datatracker.ietf.org/doc/html/rfc8484) in order to prevent tracking of the identity being resolved.

Validate DID Document Proof:
* Validate JAdES Signature.
* Validate Certificate Chain in the signature.
* Check that the Signing Certificate pseudonym equals to DID.

## Create (Register)

### Create Holder related DID Document

Creating DID and DID Document for Holders is done through the following steps:

![2  create-holder-did](https://user-images.githubusercontent.com/107480753/174041198-4613321a-0fb7-46a9-b177-9aafee1534e1.png)

**Notes:**

Each (q)TSP can implement their own method for User Registration and/or Authentication.

### Create Issuer related DID Document

Creating DID and DID Document for Issuers is done through the following steps:

![3  create-issuer-did](https://user-images.githubusercontent.com/107480753/174043105-afd2e61e-9181-407e-9ece-0f6954143c4c.png)

### Create Verifier related DID Document

Creating DID and DID Document for Verifiers is done through the following steps:

![4  create-verifier-did](https://user-images.githubusercontent.com/107480753/174043286-aa85a846-e42c-4c63-b8ad-0db5ffff72e1.png)

## Update

### Update Holder related DID Document

Updating DID Document for Holders is done through the following steps:

![5  update-holder-did](https://user-images.githubusercontent.com/107480753/174043558-c08b6f88-b52b-44f8-9612-e5eae84da566.png)

**Notes:**

Each (q)TSP can implement their own method for User Authentication.

### Update Issuer related DID Document

Updating DID Document for Issuers is done through the following steps:

![6  update-issuer-did](https://user-images.githubusercontent.com/107480753/174044495-b4a79cb5-158c-4172-ab36-579e9407687b.png)

### Update Verifier related DID Document

Updating DID Document for Verifiers is done through the following steps:

![7  update-verifier-did](https://user-images.githubusercontent.com/107480753/174044739-ab5afcc1-e048-45f3-a975-90a79d8505d2.png)

## Deactivate (Revoke)

To delete the DID document, the did.json have to be removed or have to be no longer publicly available due to any other means. It is done by the Administrator through the following steps:

![8  revoke-did](https://user-images.githubusercontent.com/107480753/174044858-3996b746-9d92-419d-a44d-2d113d3bf447.png)

## Key Rotation

Rotating DID Authentication Keys by the Administrator for Verifier and/or Issuer is done through the following steps:

![9  rotate-key](https://user-images.githubusercontent.com/107480753/174044970-a4c2f3d6-439a-4b6a-a0d4-090cf0604201.png)

# Privacy and Security considerations

## Privacy considerations

The following privacy considerations should be considered for the QES DID method:

* The DID document does not contain any Personally Identifiable Information (PII).
* The Advanced Certificate, used to generate the JAdES signature, must contain a Subject with a Pseudonym representing the DID Identifier.
* Only Verifiable Credentials can contain PII.

## Security considerations

The following security considerations should be considered for the QES DID method:

* The Issuer VCAssert certificate's key-pair is generated and stored in an HSM at the Trust Service Provider.
* The Issuer DIDDocAssert certificate's key-pair is generated and stored in an HSM at the Trust Service Provider.
* The User VPAuth certificate's key-pair for eIDAS LoA High/Substantial is generated and stored in an HSM at the Trust Service Provider.
* The User DID Authentication key-pair is generated and stored in an HSM at the Trust Service Provider.
* The User VPAuth certificate's key-pair for eIDAS LoA Low is generated and stored in the device's secure element.
* The DID Document can be marked with the LoA type to indicate its level of security.

# DID Document Example

## Holder’s DID Document

Below is an example of a Holder's DID Document:

```
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "http://w3id.org/security/suites/jws-2020/v1",
    "https://identity.foundation/didcomm-messaging/service-endpoint/v1",
    "http://www.example.org/did/schemas/eidas-2022/v1"
  ],
  "id": "qes:web:<url>:<UUID>",
  "controller": "<User.DID>#user-DIDAuth-Key-p256-1", 
  "service": [
    {
      "id": "<User.DID>#didcomm-1",
      "type": "DIDCommMessaging",
      "serviceEndpoint": "<MediatorEndPoint>",
      "accept": [
        "didcomm/v2",
        "didcomm/aip2;env=rfc587"
      ],
      "recipientKeys": [
        "<User.DID>#user-DIDComm-Key-p256-1"
      ],
      "routingKeys": [
        "<WalletProvider.mediator.DID>#didcomm-1"
      ]
    }
  ],
  "verificationMethod": [
    {
      "id": "<User.DID>#user-DIDAuth-Key-p256-1",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_xzoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgKxoI4ZiajO8jPRZDldVhqFpYoo"
      }
    },
    {
      "id": "<User.DID>#user-DIDDocProofAssert-JAdESValidation-1",
      "type": "EidasJAdESValidation2022"
    },
    {
      "id": "<User.DID>#user-VPAuth-Key-p256-1",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_xzoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgKxoI4ZiajO8jPRZDldVhqFpYoo"
      }
    },
    {
      "id": "<User.DID>#user-VPAuth-JAdESValidation-1",
      "type": "EidasJAdESValidation2022"
    }
  ],
  "authentication": [
    "<User.DID>#user-VPAuth-Key-p256-1",
    "<User.DID>#user-VPAuth-JAdESValidation-1",
    "<User.DID>#user-DIDAuth-Key-p256-1"
  ],
  "assertionMethod": [
    "<User.DID>#user-DIDDocProofAssert-JAdESValidation-1"
  ],
  "keyAgreement": [
    {
      "id": "<User.DID>#user-DIDComm-Key-p256-1",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
        "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo"
      }
    }
  ],
  "proof": {
    "type": "EidasJAdESSignature2020",
    "created": "2020-06-22T14:11:44Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "<User.DID>#user-DIDDocProofAssert-JAdESValidation-1",
    "proofValue": "BD21J4fdlnBvBA+y6D...fnC8Y="
  }
}
```

## Issuer’s DID Document

Below is an example of an Issuer's DID Document:

```
{
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "http://w3id.org/security/suites/jws-2020/v1",
      "https://identity.foundation/didcomm-messaging/service-endpoint/v1",
      "http://www.example.org/did/schemas/eidas-2022/v1"
    ],
    "id": "did:qes:web:<url>:<UUID>",
    "controller": "did:qes:web:<url>:<UUID>",
    "service": [
      {
        "id": "<Issuer.DID>",
        "type": "DIDCommMessaging",
        "serviceEndpoint": ""<Issuer.MediatorEndPoint>",
        "accept": [
          "didcomm/v2",
          "didcomm/aip2;env=rfc587"
        ],
        "recipientKeys": [
          "<Issuer.DID>#rp-DIDComm-Key-p256-1"
        ],
        "routingKeys": [
          "<Issuer.DID>#mediator-DIDComm-Key-p256-1"
        ]
      }
    ],
    "verificationMethod": [
      {
        "id": "<Issuer.DID>#rp-DIDAuth-Key-p256-1",
        "type": "JsonWebKey2020",
        "controller": "<Issuer.DID>#rp-DIDAuth-Key-p256-1",      
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "_zkhkbxcdLTy1SbqUKxrzujKtMFWcHqlhUOvcIT0ZcU",
          "y": "2uBb9gGWw3Evd_vdeTYLldsmVGBCo3I_G0Xr1CSTyj8"
        }
      },
      {
        "id": "<Issuer.DID>#rp-DIDDocProofAssert-JAdESValidation-1",
        "type": "EidasJAdESValidation2022",
        "controller": "<Issuer.DID>#rp-DIDAuth-Key-p256-1"
      },
      {
        "id": "<Issuer.DID>#issuer-VCAssert-Key-p256-1",
        "type": "JsonWebKey2020",
        "controller": "<Issuer.DID>#rp-DIDAuth-Key-p256-1",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "fHmsVqXs0Lqg-zwv-dYuTPy4uErWMrwPvaUvTseGZ-M",
          "y": "ziafiYg5NSziOvvoc2QBSFypp7zl0scoNOPcVN6FbQ4"
        }
      },
      {
        "id": "<Issuer.DID>#issuer-VCAssert-JAdESValidation-1",
        "type": "EidasJAdESValidation2022",
        "controller": "<Issuer.DID>#rp-DIDAuth-Key-p256-1"
      }
    ],
    "authentication": [
      "<Issuer.DID>#rp-DIDAuth-Key-p256-1"
    ],
    "assertionMethod": [
      "<Issuer.DID>#rp-DIDDocProofAssert-JAdESValidation-1",
      "<Issuer.DID>#issuer-VCAssert-Key-p256-1",
      "<Issuer.DID>#issuer-VCAssert-JAdESValidation-1"
    ],
    "keyAgreement": [
      {
        "id": "<Issuer.DID>#rp-DIDComm-Key-p256-1",
        "type": "JsonWebKey2020",
        "controller": "<Issuer.DID>#rp-DIDAuth-Key-p256-1",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "X6cAfuDa-zpdTBYu5k9PrVH8ggtl-yBhxnR07QJ6OiE",
          "y": "xnC9Bzat75woKLmXMSqZb7p7yHYr0wkWx-k0rb1NIbM"
        }    
      }
    ],
    "proof": {
      "type": "EidasJAdESSignature2020",
      "created": "2020-06-22T14:11:44Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "<Issuer.DID>#rp-DIDDocProofAssert-JAdESValidation-1",
      "proofValue": "BD21J4fdlnBvBA+y6D...fnC8Y="
    }
  }
```
