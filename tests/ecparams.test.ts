// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Byte } from "../src/hash.js";
import * as uprove from "../src/uprove.js";
import { stringToBytes } from "../src/utils.js";

const n = 50;

// issue tokens with 50 attributes to test all available generators
async function testECParams(descGq: uprove.ECGroup) {
    const ikap = await uprove.createIssuerKeyAndParams(descGq, n, new Array(n).fill(new Byte(0)), stringToBytes('Specification'));
    const ip = ikap.ip;
    ip.verify();
    const attributes = new Array(n).fill(new Uint8Array()).map((a,i,arr)=>new Uint8Array([i+1])); // directly encode A_i = i
    const TI = stringToBytes("Token Information");
    const PI = stringToBytes("Prover Information");
    const numberOfTokens = 1;
    const issuer = await uprove.Issuer.create(ikap, attributes, TI, numberOfTokens);
    const prover = await uprove.Prover.create(ip, attributes, TI, PI, numberOfTokens);
    const message1 = issuer.createFirstMessage();
    const message2 = await prover.createSecondMessage(message1);
    const message3 = issuer.createThirdMessage(message2);
    const upkt = prover.createTokens(message3)[0];
    await uprove.verifyTokenSignature(ip, upkt.upt);
}

test("EC params P256", async () => {
    await testECParams(uprove.ECGroup.P256);
});

test("EC params P384", async () => {
    await testECParams(uprove.ECGroup.P384);
});

test("EC params P521", async () => {
    await testECParams(uprove.ECGroup.P521);
});
