// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Byte } from '../src/hash';
import * as uprove from '../src/uprove';
import * as serialization from '../src/serialialization';

try {
    console.log("U-Prove issuance and presentation sample");

    // issuer creates its key and parameters
    const issuerKeyAndParams = uprove.createIssuerKeyAndParams(uprove.ECGroup.P256, 4, [new Byte(1), new Byte(1), new Byte(0), new Byte(1)], Buffer.from('Sample Specification', 'utf-8'));
    // the issuer shares its parameters with the Prover and Verifier
    const serializedIP = serialization.encodeIssuerParams(issuerKeyAndParams.ip);
    console.log("Issuer Parameters", serializedIP);
    // send serializedIP to Prover

    // prover validates the issuer parameters
    const issuerParams = serialization.decodeIssuerParams(serializedIP);
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
    const numberOfTokens = 3;
    
    // setup participants
    const issuer = new uprove.Issuer(issuerKeyAndParams, attributes, TI, numberOfTokens);
    const prover = new uprove.Prover(issuerParams, attributes, TI, PI, numberOfTokens);

    // issuer creates the first message
    const message1 = serialization. encodeFirstIssuanceMessage(
        issuer.createFirstMessage());
    console.log("First issuance message", message1);

    // prover creates the second message
    const message2 = serialization.encodeSecondIssuanceMessage(
        prover.createSecondMessage(
            serialization.decodeFirstIssuanceMessage(issuerParams, message1)));
    console.log("Second issuance message", message2);

    // issuer creates the third message
    const message3 = serialization.encodeThirdIssuanceMessage(
        issuer.createThirdMessage(
            serialization.decodeSecondIssuanceMessage(issuerParams, message2)));
    console.log("Third issuance message", message3);

    // prover creates the U-Prove tokens
    const uproveKeysAndTokens = prover.createTokens(
        serialization.decodeThirdIssuanceMessage(issuerParams, message3));
    const uproveToken = serialization.encodeUProveToken(uproveKeysAndTokens[0].upt);
    console.log("U-Prove Token", uproveToken);

    // prover presents one U-Prove token
    const presentationMessage = Buffer.from("Presentation message", "utf-8");
    const disclosedAttributesArray: number[] = [1,3];
    const proof = serialization.encodePresentationProof(
        uprove.generatePresentationProof(issuerParams, disclosedAttributesArray, uproveKeysAndTokens[0], presentationMessage, attributes));
    console.log("Presentation Proof", proof);
    
    // verifier validates the presentation proof
    uprove.verifyPresentationProof(
        issuerParams,
        disclosedAttributesArray,
        serialization.decodeUProveToken(issuerParams, uproveToken),
        presentationMessage,
        serialization.decodePresentationProof(issuerParams, proof));

    console.log("Success");
} 
catch (e) {
    console.log(e);
}