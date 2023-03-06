// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Byte } from "../src/hash.js";
import * as uprove from "../src/uprove.js";

const n = 50;

// issue tokens with 50 attributes to test all available generators
function testECParams(descGq: uprove.ECGroup) {
    const ikap = uprove.createIssuerKeyAndParams(descGq, n, new Array(n).fill(new Byte(0)), Buffer.from('Specification', 'utf-8'));
    const ip = ikap.ip;
    ip.verify();
    const attributes = new Array(n).fill(new Uint8Array()).map((a,i,arr)=>new Uint8Array([i+1])); // directly encode A_i = i
    const TI = Buffer.from("Token Information", "utf-8");
    const PI = Buffer.from("Prover Information", "utf-8");
    const numberOfTokens = 1;
    const issuer = new uprove.Issuer(ikap, attributes, TI, numberOfTokens);
    const prover = new uprove.Prover(ip, attributes, TI, PI, numberOfTokens);
    const message1 = issuer.createFirstMessage();
    const message2 = prover.createSecondMessage(message1);
    const message3 = issuer.createThirdMessage(message2);
    const upkt = prover.createTokens(message3)[0];
    uprove.verifyTokenSignature(ip, upkt.upt);
}

test("EC params P256", async () => {
    testECParams(uprove.ECGroup.P256);
});

test("EC params P384", async () => {
    testECParams(uprove.ECGroup.P384);
});

test("EC params P521", async () => {
    testECParams(uprove.ECGroup.P521);
});
