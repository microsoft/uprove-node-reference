// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import express from 'express';
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
app.use(express.json()) // for parsing application/json
// apply a rate limiter to incoming request (as suggested by CodeQL)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})
app.use(limiter)

const userDB = new Map<string, serialization.UProveTokenJSON>();
const nonceDB = new Set<string>();
const FIVE_MIN_IN_MS = 5 * 60 * 1000;

async function verifyJWS(jws: string, expectToken: boolean) {
    const upJWS: UPJF.UPJWS = UPJF.parseJWS(jws);
    console.log("Received U-Prove JWS", upJWS);
    const header = upJWS.header;
    if (!header || !header.alg) { // TODO: check alg
        throw "invalid JWS header";
    }
    const message = upJWS.payload;
    const tp = upJWS.sig;
    let uptJSON:serialization.UProveTokenJSON | undefined;
    if (expectToken) {
        // token is encoded in the JWS
        if (!tp.upt) {
            throw "upt missing from JWS";
        } else {
            uptJSON = tp.upt;
        }
    } else {
        if (!tp.uidt) {
            throw "uidt missing from JWS";
        }
        // lookup uidt in our user DB
        uptJSON = userDB.get(tp.uidt);
        if (!uptJSON) {
            throw "unknown uidt: " + tp.uidt;
        }
    }
    
    if (!tp.pp) {
        throw "pp missing from JWS";
    }

    // fetch the Issuer parameters: (read the issuer url from the token information field) // TODO: only do that once, create a issuerDB
    const tokenInfo = UPJF.parseTokenInformation(Buffer.from(uptJSON.TI, 'base64'));
    const jwksUrl = tokenInfo.iss + settings.JWKS_SUFFIX;
    const jwksJson = await got(jwksUrl).json() as io.IssuerParamsJWKS;
    console.log("Retrieved Issuer JWKS", jwksJson);
    const jwk: UPJF.IssuerParamsJWK = jwksJson.keys[0]; // we assume that there is one param in the key set
    const issuerParams = UPJF.decodeJWKAsIP(jwk);

    const upt = serialization.decodeUProveToken(issuerParams, uptJSON)
    if (expectToken) {
        // we only need to verify the token the first time we see it
        uprove.verifyTokenSignature(issuerParams, upt);
    }
    const spec = UPJF.parseSpecification(issuerParams.S);
    if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
        throw "token is expired";
    }
    const pm = io.parsePresentationMessage(message);
    if (pm.vID !== settings.VERIFIER_URL) {
        throw "wrong scope: " + pm.vID;
    }
    // make sure the timestamp is close enough to the current time
    if (Math.abs(parseInt(pm.ts) - Date.now()) > FIVE_MIN_IN_MS) {
        throw "invalid timestamp: " + pm.ts;
    }
    if (nonceDB.has(pm.nce)) {
        throw "invalid nonce: " + pm.nce;
    } else {
        // remember the nonce to make sure we don't accept it again, and delete it
        // after a timeout period because the timestamp + nonce insures a unique challenge
        nonceDB.add(pm.nce);
        setTimeout(() => nonceDB.delete(pm.nce), FIVE_MIN_IN_MS);
    }
    const verificationData = uprove.verifyPresentationProof(
        issuerParams,
        [],
        upt,
        message,
        serialization.decodePresentationProof(issuerParams, tp.pp));

    if (expectToken) {
        // store the token in the user's account
        const uidt = serialization.encodeUIDT(verificationData.UIDT);
        userDB.set(uidt, uptJSON);
        console.log('Storing token with identifier', uidt);
    }
}

// verifier protocol handler
app.post(settings.PRESENTATION_SUFFIX, async (req, res) => {
    console.log('Received POST for', settings.PRESENTATION_SUFFIX, req.body);
    res.type('json');
    try {
        const reqJson = req.body as {jws: string};
        const jws:string = reqJson.jws;

        const verificationData = verifyJWS(jws, true);

        let response = { status: "success" };
        console.log('Response', response);
        res.send(response);
    } catch (err) {
        const errString = err as string;
        console.log("Error: " + errString);
        res.send({ error: errString })
    }
});

app.get(settings.PRESENTATION_SUFFIX, async (req, res) => {
    console.log('Received GET for', settings.PRESENTATION_SUFFIX, req.body);
    try {
        const queryParams = req.query;
        console.log(queryParams);
        const jws = queryParams.p as string;

        verifyJWS(jws, false);

        let response = { status: "success" };
        console.log('Response', response);
        res.send(response);
    } catch (err) {
        const errString = err as string;
        console.log("Error: " + errString);
        res.send({ error: errString })
    }
});

http.createServer(app).listen(settings.VERIFIER_PORT, () => {
    console.log("Verifier listening at: " + settings.VERIFIER_URL);
});

