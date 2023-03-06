// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import express from 'express';
//import https from 'https';
import http from 'http';
import rateLimit from 'express-rate-limit';
import settings from './settings.json' assert {type: "json"};
import * as io from './io.js';
import * as serialization from '../../../src/serialization.js';
import got from 'got';
import * as UPJF from '../../../src/upjf.js';
import * as uprove from '../../../src/uprove.js';


// setup server
const app = express();
//const port = 443;
app.use(express.json()) // for parsing application/json
// apply a rate limiter to incoming request (as suggested by CodeQL)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})
app.use(limiter)

// issuance protocol handler
app.post(settings.PRESENTATION_SUFFIX, async (req, res) => {
    console.log('Received POST for', settings.PRESENTATION_SUFFIX, req.body);
    res.type('json');
    try {
        const presentation = req.body as io.Presentation;

        // fetch the Issuer parameters (FIXME TODO: Issuer URL must be retrieved from token, but this needs IP. Parse TI first...)
        const jwksUrl = settings.ISSUER_URL + settings.JWKS_SUFFIX;
        const jwksJson = await got(jwksUrl).json() as io.IssuerParamsJWKS;
        console.log("received Issuer JWKS", jwksJson);
        const jwk: UPJF.IssuerParamsJWK = jwksJson.keys[0]; // we assume there is one param in the key set
        const issuerParams = UPJF.decodeJWKAsIP(jwk);

        if (!presentation.upt) {
            throw "upt missing from presentation";
        }
        const upt = serialization.decodeUProveToken(issuerParams, presentation.upt)
        uprove.verifyTokenSignature(issuerParams, upt); // TODO: skip in repeat presentations
        const spec = UPJF.parseSpecification(issuerParams.S);
        const tokenInfo = UPJF.parseTokenInformation(upt.TI);
        if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
            throw "token is expired";
        }
        const message = Buffer.from(presentation.pm, 'base64');
        const pm = io.parsePresentationMessage(message);
        if (pm.vID !== settings.VERIFIER_URL) {
            throw "wrong scope: " + pm.vID;
        }
        const FIVE_MIN_IN_MS = 5 * 60 * 1000;
        if (Math.abs(parseInt(pm.ts) - Date.now()) > FIVE_MIN_IN_MS) {
            throw "invalid timestamp: " + pm.ts;
        }
        // TODO: make sure the nonce is not reused within the timeout window
        uprove.verifyPresentationProof(
            issuerParams,
            [],
            upt,
            message,
            serialization.decodePresentationProof(issuerParams, presentation.pp));
        let response = { status: "success" };
        console.log('Response', response);
        res.send(response);
    } catch (err) {
        const errString = err as string;
        console.log("Error: " + errString);
        res.send({ error: errString })
    }
});

// TODO: create a get handler, to only receive the UID_T and a presentation proof. Add a DB to remember UID_T and UPT

http.createServer(app).listen(settings.VERIFIER_PORT, () => {
    console.log("Verifier listening at: " + settings.VERIFIER_URL);
});

