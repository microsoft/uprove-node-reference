// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as uprove from '../src/uprove.js';
import { randomBytes } from 'crypto';

// generate a random number between 1 and n
const randomNonZeroUint = (n: number) => Math.floor(Math.random() * n) + 1;

// iterate over all params sets
for (const ecGroup of Object.values(uprove.ECGroup)) {
    // iterate over different values of n: no attributes, one attribute, and average 5 and 10
    // (note: max 50 tested in ecparams.test.ts)
    for (const n of [0, 1, 5, 10]) {
        const caseName = `group:${ecGroup}, n:${n}`;
        let ikap: uprove.IssuerKeyAndParams;
        let ip: uprove.IssuerParams;
        test(`issuer params generation: ${caseName}`, () => {
            ikap = uprove.createIssuerKeyAndParams(
                ecGroup as uprove.ECGroup,
                n,
                undefined, // will default to an array of Byte(1), i.e., hash the attributes
                Buffer.from(`Specification: ${caseName}`, 'utf-8'));
            // check that the issuer params are valid
            ip = ikap.ip;
            ip.verify();
        });
        test(`invalid issuer params: ${caseName}`, () => {
            const originalS = ip.S;
            ip.S = Buffer.from('invalid S', 'utf-8');
            expect(ip.verify).toThrow();
            ip.S = originalS;
        });

        // test issuance
        let attributes: Uint8Array[];
        let upkt: uprove.UProveKeyAndToken;
        let upt: uprove.UProveToken;
        let numberOfTokens = randomNonZeroUint(3);
        test(`issuance: ${caseName}, numberOfTokens: ${numberOfTokens}`, () => {
            // generate random attributes, token info and prover info fields of random size
            attributes = Array(n).fill(null).map(v => randomBytes(randomNonZeroUint(20)));
            let TI = randomBytes(randomNonZeroUint(20));
            let PI = randomBytes(randomNonZeroUint(20));

            // run issuance protocol
            const issuer = new uprove.Issuer(ikap, attributes, TI, numberOfTokens);
            const prover = new uprove.Prover(ip, attributes, TI, PI, numberOfTokens);
            const message1 = issuer.createFirstMessage();
            const message2 = prover.createSecondMessage(message1);
            const message3 = issuer.createThirdMessage(message2);
            const tokens = prover.createTokens(message3);
            expect(tokens.length).toBe(numberOfTokens);
            // test validity of tokens
            tokens.forEach(token => uprove.verifyTokenSignature(ip, token.upt));
            
            // save first token for next tests
            upkt = tokens[0];
            upt = upkt.upt;
        });

        test(`invalid token: ${caseName}`, () => {
            // change the Prover info field
            const originalPI = upt.PI;
            upt.PI = Buffer.from('invalid PI', 'utf-8');
            expect(() => uprove.verifyTokenSignature(ip, upt)).toThrow();
            upt.PI = originalPI;
        });

        // test presentation
        let presentationMessage = randomBytes(randomNonZeroUint(20));
        let proofData: uprove.PresentationProofData;
        test(`presentation: ${caseName}`, () => {
            // randomly select which attributes to disclose
            const disclosedIndices = Array(n).fill(0).map((v,i,a) => i+1).filter(v => {return Math.random() > 0.5;});
            proofData = uprove.generatePresentationProof(ip, disclosedIndices, upkt, presentationMessage, attributes);
            uprove.verifyPresentationProof(ip, upt, presentationMessage, proofData.pp);
        });

        test(`invalid presentation: ${caseName}`, () => {
            // change the presentation message
            presentationMessage = Buffer.from('invalid presentation message', 'utf-8');
            expect(() => uprove.verifyPresentationProof(ip, upt, presentationMessage, proofData.pp)).toThrow();
        });
    }
}
