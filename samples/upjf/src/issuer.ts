// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import express from 'express';
//import https from 'https';
import http from 'http';
import rateLimit from 'express-rate-limit';
import fs from 'fs';
import settings from './settings.json';
import * as crypto from "crypto";
import * as UPJF from '../../../src/upjf.js';
import * as uprove from '../../../src/uprove.js';
import * as serialization from '../../../src/serialization.js';

// some issuer settings
const MAX_TOKEN_COUNT = 10; // maximum number of tokens to issue in parallel
const ISSUER_PARAMS_PATH = "public" + settings.IP_SUFFIX; // created by the setup script
const PRIVATE_KEY_PATH = "private/ip.key" // created by the setup script

export interface IssuerParamsJWKS {
    keys: UPJF.IssuerParamsJWK[]
}

// read the issuer parameters
const jwksString = fs.readFileSync(ISSUER_PARAMS_PATH, 'utf8');
const jwk: UPJF.IssuerParamsJWK = (JSON.parse(jwksString) as IssuerParamsJWKS).keys[0]; // we assume there is one param in the key set
const issuerParams = UPJF.decodeJWKAsIP(jwk);
console.log("Issuer parameters loaded from: " + ISSUER_PARAMS_PATH);

// read the private key
const privateString = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
const privateKey = UPJF.decodeBase64UrlAsPrivateKey(issuerParams, privateString);
console.log("Issuer private key loaded from: " + PRIVATE_KEY_PATH);

// create the issuer key and params object
const issuerKeyAndParams: uprove.IssuerKeyAndParams = {
    ip: issuerParams,
    y0: privateKey
}

// setup server
const app = express();
//const port = 443;
app.use(express.json()) // for parsing application/json
app.use(express.static('./public')) // public files

// apply a rate limiter to incoming request (as suggested by CodeQL)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
})
app.use(limiter)

// initial token request from client (Prover)
interface TokenRequestMessage {
    n: number
}

// second issuance message from client (Prover)
interface SecondIssuanceMessage {
    sID: string,
    msg: serialization.SecondIssuanceMessageJSON
}

// session database
const sessionDB = new Map<string, uprove.Issuer>();

// issuance protocol handler
app.post('/issue', async (req, res) => {
    console.log('Received POST for', '/issue', req.body);
    res.type('json');
    try {
        let response;
        if ('sID' in req.body) {
            // 2nd issuance message
            const msg = req.body as SecondIssuanceMessage;

            // check if we have an issuance session with this ID
            const issuer = sessionDB.get(msg.sID);
            if (issuer) {
                // issuer creates the third message
                try {
                    const message3 = serialization.encodeThirdIssuanceMessage(
                        issuer.createThirdMessage(
                            serialization.decodeSecondIssuanceMessage(issuerKeyAndParams.ip, msg.msg)));
                } catch (err) {
                    response = { err: "issuance error" };
                }
            } else {
                response = {
                    err: "Invalid session ID: " + msg.sID // TODO: better error?
                };
            }
        } else {
            // initial token request
            // NOTE: user authentication is outside the scope of this sample, we assume
            //       the user is authorized to obtain tokens
            const msg = req.body as TokenRequestMessage;
            let n = 1;
            if (msg.n) {
                // issue the requested number of tokens (up to our max count)
                // NOTE: this is application-specific; tokens might have some value (access ticket, e-coin, etc.)
                //       in which case the number of issued tokens would be measured/controlled by the issuer 
                n = msg.n <= MAX_TOKEN_COUNT ? msg.n : MAX_TOKEN_COUNT; // TODO: make sure it's an uint
            }
            // create a random session ID to recognize the user session on the second call
            const sessionID = crypto.randomBytes(32).toString('base64');

            // create the token information object; this will be included in every token and will be visible
            // to Verifiers
            const TiJson = {
                iss: settings.ISSUER_URL,
                exp: 1000 // expiration date
            };
            const TI = Buffer.from(JSON.stringify(TiJson));

            const issuer = new uprove.Issuer(issuerKeyAndParams, [], TI, n);
            const message1 = serialization.encodeFirstIssuanceMessage(issuer.createFirstMessage());

            response = {
                sID: sessionID,
                msg: message1
            };

            // store the issuance session object
            sessionDB.set(sessionID, issuer);
        }
        console.log(response);
        res.send(response);
    } catch (err) {
        const errString = err as string;
        console.log("Error: " + errString);
        res.send({ error: errString });
    }
});

// const options = {
//     key: fs.readFileSync('/path/to/key.pem'),
//     cert: fs.readFileSync('/path/to/cert.pem'),
//   };

// https.createServer(options, app).listen(port, () => {
//     console.log(`Server listening on port ${port}`);
// });


http.createServer(app).listen(settings.ISSUER_PORT, () => {
    console.log("Issuer listening at: " + settings.ISSUER_URL);
});
