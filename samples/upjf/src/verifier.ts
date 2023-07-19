// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import express from 'express';
import http from 'http';
import rateLimit from 'express-rate-limit';
import got from 'got';

import * as settings from './settings.js';
import * as io from './io.js';

import * as serialization from '../../../src/serialization.js';
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

// stores the issuer parameters, indexed by the issuer url
const issuerDB = new Map<string, UPJF.IssuerParamsJWK>();
const getIssuerParams = async (issuerUrl: string): Promise<uprove.IssuerParams> => {
    let jwk: UPJF.IssuerParamsJWK;
    // check if we have the issuer params in our DB, otherwise fetch them
    if (issuerDB.has(issuerUrl)) {
        jwk = issuerDB.get(issuerUrl)!;
    } else {
        const jwksUrl = issuerUrl + settings.JWKS_SUFFIX;
        const jwksJson = await got(jwksUrl).json() as io.IssuerParamsJWKS;
        console.log("Retrieved Issuer JWKS", jwksJson);
        jwk = jwksJson.keys[0]; // we assume (in this sample) that there is one param in the key set
        issuerDB.set(issuerUrl, jwk);
    }
    return UPJF.decodeJWKAsIP(jwk);
}

// stores the user tokens for repeat visits, indexed by the base64url-encoded UIDT
const userDB = new Map<string, serialization.UProveTokenJSON>();

// stores the previously seen nonces (for 5 minutes)
const nonceDB = new Set<string>();
const FIVE_MIN_IN_MS = 5 * 60 * 1000;

async function verifyJWS(jws: string, expectToken: boolean) {
    const upJWS: UPJF.UPJWS = UPJF.parseJWS(jws);
    console.log("Received U-Prove JWS", upJWS);
    const header = upJWS.header;
    // check the header alg (we'll check it matches the issuer params later)
    if (!header || !header.alg || !Object.values(UPJF.UPAlg).includes(header.alg)) {
        throw "invalid header alg: " + header.alg;
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

    // fetch the Issuer parameters: (read the issuer url from the token information field)
    const tokenInfo = UPJF.parseTokenInformation(serialization.fromBase64Url(uptJSON.TI));
    const issuerParams = await getIssuerParams(tokenInfo.iss);
    // check that JWS alg matches the issuer params's group
    if ((issuerParams.descGq == uprove.ECGroup.P256 && header.alg !== UPJF.UPAlg.UP256) ||
        (issuerParams.descGq == uprove.ECGroup.P384 && header.alg !== UPJF.UPAlg.UP384) ||
        (issuerParams.descGq == uprove.ECGroup.P521 && header.alg !== UPJF.UPAlg.UP521))
    {
        throw `header alg ${header.alg} doesn't match the Issuer params' group ${issuerParams.descGq}`;
    }
    const upt = serialization.decodeUProveToken(issuerParams, uptJSON)
    if (expectToken) {
        // we only need to verify the token the first time we see it
        uprove.verifyTokenSignature(issuerParams, upt);
    }
    const spec = UPJF.parseSpecification(issuerParams.S);
    // check if token is expired
    if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
        throw "token is expired";
    }
    // check the token label
    const tokenLabel = (spec.lblType as Record<number, string>)[tokenInfo.lbl as number];
    // <application specific logic goes here>
    console.log("Token label:", tokenLabel);

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
    const verificationData = await uprove.verifyPresentationProof(
        issuerParams,
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

        void await verifyJWS(jws, true);

        const response = { status: "success" };
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

        const response = { status: "success" };
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
