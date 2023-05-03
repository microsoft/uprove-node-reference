// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import got from 'got';
import * as crypto from 'crypto';

import * as io from './io.js';
import * as settings from './settings.js';

import * as UPJF from '../../../src/upjf.js';
import * as uprove from '../../../src/uprove.js';
import * as serialization from '../../../src/serialization.js';

interface KeyAndToken {
    key: string,
    token: serialization.UProveTokenJSON
}

void (async () => {
    try {
        const tokenStore: KeyAndToken[] = [];

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
        const spec = UPJF.parseSpecification(issuerParams.S);

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
        const tokenInfo = UPJF.parseTokenInformation(TI);
        // check the the issuer URL is correct
        if (tokenInfo.iss !== settings.ISSUER_URL) {
            throw "invalid issuer URL: " + tokenInfo.iss;
        }
        // check that the token is not already expired
        if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
            throw "token is expired";
        }
        // check that the lbl value is contained in the specification (protects the user against "tagging attacks")
        if (!spec.lblType[tokenInfo.lbl]) {
            throw "invalid lbl value: " + tokenInfo.lbl;
        }
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
        // create and store the U-Prove tokens
        const uproveKeysAndTokens = prover.createTokens(msg3);
        uproveKeysAndTokens.forEach((upkt) => {
            tokenStore.push({
                key: UPJF.encodePrivateKeyAsBase64Url(upkt.alphaInverse),
                token: serialization.encodeUProveToken(upkt.upt)
            });
        });

        //
        // Register token with Verifier by presenting it
        //

        // create presentation message
        let message = io.encodePresentationMessage({
            vID: settings.VERIFIER_URL,
            nce: crypto.randomBytes(16).toString('base64'),
            ts: Date.now().toString()
        });
      
        // get token from the store
        console.log("presenting token", tokenStore[0]);
        let upkt:uprove.UProveKeyAndToken = {
            alphaInverse: UPJF.decodeBase64UrlAsPrivateKey(issuerParams, tokenStore[0].key),
            upt: serialization.decodeUProveToken(issuerParams, tokenStore[0].token)
        }

        // create presentation proof
        const uproveToken = serialization.encodeUProveToken(upkt.upt);
        let presentationData = uprove.generatePresentationProof(issuerParams, [], upkt, message, []);
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

        // create presentation message
        message = io.encodePresentationMessage({
            vID: settings.VERIFIER_URL,
            nce: crypto.randomBytes(16).toString('base64'),
            ts: Date.now().toString()
        });

        // get the same token from the store
        upkt = {
            alphaInverse: UPJF.decodeBase64UrlAsPrivateKey(issuerParams, tokenStore[0].key),
            upt: serialization.decodeUProveToken(issuerParams, tokenStore[0].token)
        }

        // create presentation proof
        presentationData = uprove.generatePresentationProof(issuerParams, [], upkt, message, []);
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