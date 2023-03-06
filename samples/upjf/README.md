# U-Prove JSON Framework sample

This project provides a sample deployment of the [U-Prove JSON Framework](../../doc/U-Prove_JSON_Framework.md).

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
npm run deploy-servers
```

The Issuer parameters will be hosted at the deployment `url/.well-known/jwks.json`.

The Verifier can be deployed by running:

```
npm run deploy-verifier
```

Finally, the Prover can retrieve tokens from the Issuer and then present one to the Verifier by running:
```
npm run run-prover
```

