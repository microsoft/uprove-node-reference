// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as crypto from 'crypto';
import { Byte } from '../src/hash.js';
import * as uprove from '../src/uprove.js';
import * as UPJF from '../src/upjf.js';
import * as serialization from '../src/serialization.js';

const genericSample = () => {
    console.log("Generic U-Prove issuance and presentation sample");

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
        uprove.generatePresentationProof(issuerParams, disclosedAttributesArray, uproveKeysAndTokens[0], presentationMessage, attributes).pp);
    console.log("Presentation Proof", proof);
    
    // verifier validates the presentation proof
    uprove.verifyPresentationProof(
        issuerParams,
        serialization.decodeUProveToken(issuerParams, uproveToken),
        presentationMessage,
        serialization.decodePresentationProof(issuerParams, proof));
    console.log("Success");
}

interface UPJFIssuerSetupData {
    ikp: uprove.IssuerKeyAndParams,
    jwk: UPJF.IssuerParamsJWK,
    issuerUrl: string
}

interface UPJFIssuerSpecification {
    n: number,
    expType: UPJF.ExpirationType,
    attrTypes?: string[]
}

const UPJFIssuerSetup = (descGq: uprove.ECGroup, attributes: string[] = []): UPJFIssuerSetupData => {
    // The issuer parameters specification
    const spec:UPJFIssuerSpecification = {
        n: attributes.length,
        expType: UPJF.ExpirationType.day,
    }
    // add the attribute field names to the specification
    if (attributes.length > 0) {
        spec.attrTypes = attributes;
    }
    // Issuer creates its parameters set, and encodes them as a JWK
    const ikp = UPJF.createIssuerKeyAndParamsUPJF(descGq, spec, undefined);
    const jwk = UPJF.encodeIPAsJWK(ikp.ip);
    console.log(jwk);

    // Issuer publishes the JWK at its well-known URL: [IssuerURL]/.well-known/jwks.json
    const issuerURL = "https://issuer";

    return {
        ikp: ikp,
        jwk: jwk,
        issuerUrl: issuerURL
    };
}

// performs the issuance of a batch of U-Prove tokens
const UPJFTokenIssuance = (id: UPJFIssuerSetupData, ip: uprove.IssuerParams, attributes: Uint8Array[] = []): uprove.UProveKeyAndToken[] => {

    // token information contains always-disclosed data
    const spec = UPJF.parseSpecification(ip.S);
    const TI = UPJF.encodeTokenInformation({
        iss: id.issuerUrl,
        exp: UPJF.getExp(spec.expType, 100) // 100 days
    })

    // number of tokens to issue in batch
    const numberOfTokens = 5;

    // setup participants
    const issuer = new uprove.Issuer(id.ikp, attributes, TI, numberOfTokens);
    const prover = new uprove.Prover(ip, attributes, TI, new Uint8Array(), numberOfTokens);

    // issuer creates the first message
    const message1 = serialization. encodeFirstIssuanceMessage(
        issuer.createFirstMessage());
    console.log("First issuance message", message1);

    // prover creates the second message
    const message2 = serialization.encodeSecondIssuanceMessage(
        prover.createSecondMessage(
            serialization.decodeFirstIssuanceMessage(ip, message1)));
    console.log("Second issuance message", message2);

    // issuer creates the third message
    const message3 = serialization.encodeThirdIssuanceMessage(
        issuer.createThirdMessage(
            serialization.decodeSecondIssuanceMessage(ip, message2)));
    console.log("Third issuance message", message3);

    // prover creates the U-Prove Access tokens
    const uproveKeysAndTokens = prover.createTokens(
        serialization.decodeThirdIssuanceMessage(ip, message3));

    return uproveKeysAndTokens;
}

// This sample shows how to use the U-Prove JSON Framework (UPJF) to issue and present U-Prove tokens
const JSONFrameworkSample = () => {
    console.log("U-Prove JSON Framework sample");

    // Issuer creates its Issuer parameters
    const issuerSetup = UPJFIssuerSetup(uprove.ECGroup.P256, ["name", "email", "over-21"]);

    // Prover and Verifier retrieve the JWK from the well-known URL, and parse and verify the Issuer params
    const ip = UPJF.decodeJWKAsIP(issuerSetup.jwk);
    ip.verify();

    // Prover requests Bare U-Prove tokens from the Issuer
    const attributes = ["Joe Example", "joe@example.com", "true"].map(a => Buffer.from(a, "utf-8"));
    const uproveKeysAndTokens = UPJFTokenIssuance(issuerSetup, ip, attributes);

    // To later present a token to the Verifier, the Prover obtains a challenge from the Verifier
    // and creates a presentation proof disclosing the over-21 attribute (index 3)
    const over21Index = 3;
    const presentationChallenge = crypto.randomBytes(16);
    const uproveToken = serialization.encodeUProveToken(uproveKeysAndTokens[0].upt);
    console.log("U-Prove Token", uproveToken);
    const proof = serialization.encodePresentationProof(
        uprove.generatePresentationProof(ip, [over21Index], uproveKeysAndTokens[0], presentationChallenge, attributes).pp);
    console.log("Presentation Proof", proof);

    let tp:serialization.TokenPresentation = {
        upt: uproveToken,
        pp: proof
    }
    let jws = UPJF.createJWS(UPJF.descGqToUPAlg(ip.descGq), presentationChallenge, tp);
    console.log("JWS", jws);

    // The Verifier validates the token and presentation proof
    const parsedJWS = UPJF.parseJWS(jws);
    const upt = serialization.decodeUProveToken(ip, parsedJWS.sig.upt as serialization.UProveTokenJSON)
    uprove.verifyTokenSignature(ip, upt);
    const spec = UPJF.parseSpecification(ip.S);
    const tokenInfo = UPJF.parseTokenInformation(upt.TI);
    if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
        throw "token is expired";
    }
    uprove.verifyPresentationProof(
        ip,
        upt,
        presentationChallenge,
        serialization.decodePresentationProof(ip, parsedJWS.sig.pp));

    console.log("Success");
}

// This sample illustrates how Bare tokens can be used to create privacy-protecting access tokens.
const accessTokenSample = () => {
    console.log("Access token sample");

    // Issuer creates its Issuer parameters
    const issuerSetup = UPJFIssuerSetup(uprove.ECGroup.P256);

    // Prover and Verifier retrieve the JWK from the well-known URL, and parse and verify the Issuer params
    const ip = UPJF.decodeJWKAsIP(issuerSetup.jwk);
    ip.verify();

    // Prover requests Bare U-Prove tokens from the Issuer
    const uproveKeysAndTokens = UPJFTokenIssuance(issuerSetup, ip);

    // To later present an access token to the Verifier, the Prover obtains a challenge from the Verifier
    // and creates a presentation proof
    const presentationChallenge = crypto.randomBytes(16);
    const uproveToken = serialization.encodeUProveToken(uproveKeysAndTokens[0].upt);
    console.log("U-Prove Token", uproveToken);
    const proof = serialization.encodePresentationProof(
        uprove.generatePresentationProof(ip, [], uproveKeysAndTokens[0], presentationChallenge, []).pp);
    console.log("Presentation Proof", proof);

    // The Verifier validates the token and presentation proof
    const upt = serialization.decodeUProveToken(ip, uproveToken)
    uprove.verifyTokenSignature(ip, upt);
    const spec = UPJF.parseSpecification(ip.S);
    const tokenInfo = UPJF.parseTokenInformation(upt.TI);
    if (UPJF.isExpired(spec.expType, tokenInfo.exp)) {
        throw "token is expired";
    }
    uprove.verifyPresentationProof(
        ip,
        upt,
        presentationChallenge,
        serialization.decodePresentationProof(ip, proof));

    console.log("Success");
}

export interface SignedMessage {
    ts: string, // timestamp, in ms
    msg: Uint8Array // signed message
}

const signingSample = () => {
    console.log("Signing sample");

    // Issuer creates its Issuer parameters
    const issuerSetup = UPJFIssuerSetup(uprove.ECGroup.P256);

    // Prover and Verifier retrieve the JWK from the well-known URL, and parse and verify the Issuer params
    const ip = UPJF.decodeJWKAsIP(issuerSetup.jwk);
    ip.verify();

    // Prover requests Bare U-Prove tokens from the Issuer
    const uproveKeysAndTokens = UPJFTokenIssuance(issuerSetup, ip);

    // The Prover can later use a token to sign some arbitrary message
    const signedMessageBytes = Buffer.from(JSON.stringify({
        ts: Date.now().toString(),
        msg: Buffer.from("Signed message")}), 'utf8');

    const uproveToken = serialization.encodeUProveToken(uproveKeysAndTokens[0].upt);
    console.log("U-Prove Token", uproveToken);
    const proof = serialization.encodePresentationProof(
        uprove.generatePresentationProof(ip, [], uproveKeysAndTokens[0], signedMessageBytes, []).pp); // TODO: create sig API
    console.log("Presentation Proof", proof);

    // The Verifier can later validate the token and signature
    const signedMessage: SignedMessage = JSON.parse(Buffer.from(signedMessageBytes).toString()) as SignedMessage;
    const upt = serialization.decodeUProveToken(ip, uproveToken)
    uprove.verifyTokenSignature(ip, upt);
    const spec = UPJF.parseSpecification(ip.S);
    const tokenInfo = UPJF.parseTokenInformation(upt.TI);
    if (UPJF.isExpired(spec.expType, tokenInfo.exp, UPJF.msToTypedTime(spec.expType, parseInt(signedMessage.ts)))) {
        throw "token is expired";
    }
    uprove.verifyPresentationProof(
        ip,
        upt,
        signedMessageBytes,
        serialization.decodePresentationProof(ip, proof));

    console.log("Success");
}

try {
    const printLine = () => console.log("\n------------------------------------------------------------\n");

    // U-Prove samples
    genericSample();
    printLine();
    JSONFrameworkSample();
    printLine();

    // Bare token profile samples (tokens with no attributes)
    accessTokenSample();
    printLine();
    signingSample();
    printLine();
} 
catch (e) {
    console.log(e);
}