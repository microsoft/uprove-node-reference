// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import got from 'got';
import * as crypto from 'crypto';

import * as io from './io.js';
import * as settings from './settings.js';

import * as UPJF from '../../../src/upjf.js';
import * as uprove from '../../../src/uprove.js';
import * as serialization from '../../../src/serialization.js';

void (async () => {
    try {
        //
        // Setup (done once per Issuer)
        //

        // first fetch the Issuer parameters
        const jwksUrl = settings.ISSUER_URL + settings.JWKS_SUFFIX;
        const issuanceUrl = settings.ISSUER_URL + settings.ISSUANCE_SUFFIX;
        const jwksJson = await got(jwksUrl).json() as io.IssuerParamsJWKS;
        console.log("received Issuer JWKS", jwksJson);
        const jwk: UPJF.IssuerParamsJWK = jwksJson.keys[0]; // we assume there is one param set in the key set
        const issuerParams = UPJF.decodeJWKAsIP(jwk);

        //
        // Token issuance (can be repeated when the Prover runs out of tokens)
        //
        
        // send token issuance request to Issuer
        const requestedNumberOfTokens = 5;
        const request: io.TokenRequestMessage = {
            n: requestedNumberOfTokens
        }

        // parse 1st issuance message
        const firstMsg: io.FirstIssuanceMessage = await got.post(issuanceUrl, { json: request }).json();
        console.log("received 1st issuance message", firstMsg);
        const msg1 = serialization.decodeFirstIssuanceMessage(issuerParams, firstMsg.msg);
        const actualNumberOfTokens = msg1.sA.length;
        const TI: Uint8Array = Buffer.from(firstMsg.TI, "base64");
        const prover = new uprove.Prover(issuerParams, [], TI, new Uint8Array(), actualNumberOfTokens);

        // prover creates the second message
        const msg2 = prover.createSecondMessage(msg1);
        const secondMessage: io.SecondIssuanceMessage = {
            sID: firstMsg.sID,
            msg: serialization.encodeSecondIssuanceMessage(msg2)
        }
        console.log("2nd issuance message", secondMessage);

        // send 2nd issuance message
        const thirdMsg: io.ThirdIssuanceMessage = await got.post(issuanceUrl, { json: secondMessage }).json();
        console.log("received 3rd issuance message", thirdMsg);
        if (firstMsg.sID !== thirdMsg.sID) {
            throw "session ID mismatch";
        }

        // parse 3rd issuance message
        const msg3 = serialization.decodeThirdIssuanceMessage(issuerParams, thirdMsg.msg);
        // create the U-Prove tokens
        const uproveKeysAndTokens = prover.createTokens(msg3);

        //
        // Register token with Verifier by presenting it
        //

        // present one token to the Verifier
        let message = io.encodePresentationMessage({
            vID: settings.VERIFIER_URL,
            nce: crypto.randomBytes(16).toString('base64'),
            ts: Date.now().toString()
        });
      
        const uproveToken = serialization.encodeUProveToken(uproveKeysAndTokens[0].upt);
        let presentationData = uprove.generatePresentationProof(issuerParams, [], uproveKeysAndTokens[0], message, []);
        let proof = serialization.encodePresentationProof(presentationData.pp);
        let tp:serialization.TokenPresentation = {
            upt: uproveToken,
            pp: proof
        }
        let jws = UPJF.createJWS(UPJF.descGqToUPAlg(issuerParams.descGq), message, tp);
        console.log("JWS", jws);
        const verifierUrl = settings.VERIFIER_URL + settings.PRESENTATION_SUFFIX;
        console.log("posting to " + verifierUrl);
        let response = await got.post(verifierUrl, { json: {jws: jws} }).json();
        console.log("verifier response", response);

        //
        // Later, present same token to Verifier, without sending the token again
        //

        // present the same token to the Verifier
        message = io.encodePresentationMessage({
            vID: settings.VERIFIER_URL,
            nce: crypto.randomBytes(16).toString('base64'),
            ts: Date.now().toString()
        });
        presentationData = uprove.generatePresentationProof(issuerParams, [], uproveKeysAndTokens[0], message, []);
        proof = serialization.encodePresentationProof(presentationData.pp);
        // this time we only send the token identifier UIDT instead of the full token
        tp = {
            uidt: serialization.encodeUIDT(presentationData.UIDT),
            pp: proof
        }
        jws = UPJF.createJWS(UPJF.descGqToUPAlg(issuerParams.descGq), message, tp);
        console.log("JWS", jws);
        console.log("getting from " + verifierUrl);
        response = await got(verifierUrl, { searchParams: {p: jws} }).json();
        console.log("verifier response", response);
        
    } catch (err) {
        console.log(err);
    }
})();