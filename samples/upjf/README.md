# U-Prove JSON Framework sample

This project provides a sample deployment of the [U-Prove JSON Framework](../../doc/U-Prove_JSON_Framework.md).

## Sample overview

The sample simulates a basic access scenario where a user obtains U-Prove tokens from a trusted issuer, and presents one of them at a verifier first by sending the full token and presentation proof, and in later presentations, only sending the token identifier and a fresh presentation proof (since the verifier stores the user's token for future visits). The verifier implicitly trusts the issuer (or group of issuers) in this sample.

The sample steps are:
1. The issuer generates its parameters, and makes them available at `http://localhost/.well-known/jwks.json`. The U-Prove tokens contain no selectively-disclosable attributes, and are valid for 1 year. The tokens contain one always-disclosed application-specific label, the values of which are described in the Issuer parameters' specification field. (Note that the UPJF requires then endpoint to be HTTPS, but we use HTTP for simplicity here.)
2. The user requests U-Prove tokens from the issuer (user authentication is outside the scope of this sample); up to 10 tokens are obtained in batch.
3. The user later presents one token to the verifier, by sending a POST request containing the token presentation to the verifier endpoint. The verifier validates the token, its content (the label, the expiration), and its presentation, and then stores the token. This establishes a pseudonymous relationship with the verifier based on the token identifier.
4. In a subsequent visit, the user presents the same token to the verifier, by sending a GET requests with the token's identifier and a fresh presentation. The verifier validates the presentation (no need to verify the token again).

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both. 

Build the `npm` package:
```
npm install
npm run build
```

## Sample steps

The Issuer parameters are created by running:
```
npm run setup-issuer
```

The Issuer can then be deployed by running:
```
npm run deploy-issuer
```

The Issuer parameters will be hosted at the `http://localhost/.well-known/jwks.json`.

The Verifier can be deployed by running:

```
npm run deploy-verifier
```

Finally, the Prover can retrieve tokens from the Issuer and then present one to the Verifier by running:
```
npm run prover
```
