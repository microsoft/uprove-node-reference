// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Byte } from '../src/hash';
import * as uprove from '../src/uprove';

try {
    console.log("U-Prove issuance and presentation sample");

    // create the Issuer key and parameters
    const issuerKeyAndParams = uprove.createIssuerKeyAndParams(uprove.ECGroup.P256, 4, [new Byte(1), new Byte(1), new Byte(0), new Byte(1)], Buffer.from('Sample Specification', 'utf-8'));
    // the Issuer shares its parameters with the Prover and Verifier
    const issuerParams = issuerKeyAndParams.ip;
    issuerParams.verify();

    // issue some U-Prove tokens containing 4 attributes: name, d.o.b, over21, state
    const attributes: Uint8Array[] = [
        Buffer.from("Alice Crypto", "utf-8"), // hashed attribute
        Buffer.from("10/21/1976", "utf-8"), // hashed attribute
        new Uint8Array([1]), // directly-encoded attribute
        Buffer.from("WA", "utf-8"), // hashed attribute
    ];

    // token information contains always-disclosed data 
    const TI = Buffer.from("Sample U-Prove Token", "utf-8");

    // prover information contains always-disclosed data, unknown to the issuer
    const PI = new Uint8Array();

    // number of tokens to issue in batch
    const numberOfTokens = 1;
    
    // setup participants
    const issuer = new uprove.Issuer(issuerKeyAndParams, attributes, TI, numberOfTokens);
    const prover = new uprove.Prover(issuerParams, attributes, TI, PI, numberOfTokens);

    // issuer creates the first message
    const message1 = issuer.createFirstMessage();
    
    // prover creates the second message
    const message2 = prover.createSecondMessage(message1);
    
    // issuer creates the third message
    const message3 = issuer.createThirdMessage(message2);
    
    // prover creates the U-Prove tokens
    const uproveKeysAndTokens = prover.createTokens(message3);

    // prover presents one U-Prove token
    const presentationMessage = Buffer.from("Presentation message", "utf-8");
    const disclosedAttributesArray: number[] = [1,3];
    const proof = uprove.generatePresentationProof(issuerParams, disclosedAttributesArray, uproveKeysAndTokens[0], presentationMessage, attributes);
    const uproveToken = uproveKeysAndTokens[0].upt;
    
    // verifier validates the presentation proof
    uprove.verifyPresentationProof(issuerParams, disclosedAttributesArray, uproveToken, presentationMessage, proof);

    console.log("Success");
} 
catch (e) {
    console.log(e);
}