// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import EC_D0 from '../doc/testvectors/testvectors_EC_D0_lite_doc.json' //assert {type: "json"};
import EC_D2 from '../doc/testvectors/testvectors_EC_D2_lite_doc.json' //assert {type: "json"};
import EC_D5 from '../doc/testvectors/testvectors_EC_D5_lite_doc.json' //assert {type: "json"};
import * as uprove from '../src/uprove.js';
import { Byte } from '../src/hash.js';
import { arrayEqual, hexToBytes } from '../src/utils.js';

interface TestVectors {
    UIDh: string,
    UIDp: string,
    GroupName: string,
    y0: string,
    g0_x: string,
    g0_y: string,
    e1: string,
    e2: string,
    e3: string,
    e4: string,
    e5: string,
    S: string,
    A1: string,
    A2: string,
    A3: string,
    A4: string,
    A5: string,
    TI: string,
    PI: string,
    x1: string,
    x2: string,
    x3: string,
    x4: string,
    x5: string,
    P: string,
    xt: string,
    gamma_x: string,
    gamma_y: string,
    sigmaZ_x: string,
    sigmaZ_y: string,
    w: string,
    sigmaA_x: string,
    sigmaA_y: string,
    sigmaB_x: string,
    sigmaB_y: string,
    alpha: string,
    beta1: string,
    beta2: string,
    h_x: string,
    h_y: string,
    alphaInverse: string,
    sigmaZPrime_x: string,
    sigmaZPrime_y: string,
    sigmaAPrime_x: string,
    sigmaAPrime_y: string,
    sigmaBPrime_x: string,
    sigmaBPrime_y: string,
    sigmaCPrime: string,
    sigmaC: string,
    sigmaR: string,
    sigmaRPrime: string,
    D: string,
    U: string,
    m: string,
    md: string,
    w0: string,
    w1?: string,
    w2?: string,
    w3?: string,
    w4?: string,
    w5?: string,
    a: string,
    UIDt: string,
    cp: string,
    c: string,
    r0: string,
    r1?: string,
    r2?: string,
    r3?: string,
    r4?: string,
    r5?: string
}

function parseEArray(tv: TestVectors) {
    return [
        new Byte(hexToBytes(tv.e1)[0]),
        new Byte(hexToBytes(tv.e2)[0]),
        new Byte(hexToBytes(tv.e3)[0]),
        new Byte(hexToBytes(tv.e4)[0]),
        new Byte(hexToBytes(tv.e5)[0])
    ]
}

function encodePoint(xHex: string, yHex: string) {
    if (xHex.length % 2 == 1) {
        xHex = '0' + xHex;
    }
    if (yHex.length % 2 == 1) {
        yHex = '0' + yHex;
    }
    return '04' + xHex + yHex;
}

async function run(tv: TestVectors) {
    const n = 5;
    const e = parseEArray(tv);
    const ikp = await uprove.createIssuerKeyAndParams(
        uprove.ECGroup.P256,
        5,
        e,
        hexToBytes(tv.S),
        {
            y0: hexToBytes(tv.y0),
            g0: hexToBytes(encodePoint(tv.g0_x, tv.g0_y)),
        },
        hexToBytes(tv.UIDp));
    const ip = ikp.ip;
    const Gq = ip.Gq;
    const Zq = Gq.Zq;
    const A = [hexToBytes(tv.A1), hexToBytes(tv.A2), hexToBytes(tv.A3), hexToBytes(tv.A4), hexToBytes(tv.A5)];
    const TI = hexToBytes(tv.TI);
    const PI = hexToBytes(tv.PI);

    // check the xi and xt
    A.forEach(async (Ai, i) => {
        const xi = Zq.getElement(hexToBytes((tv as unknown as Record<string, string>)["x" + (i + 1)]));
        const computedXi = await uprove.computeXi(i + 1, ip, Ai);
        expect(xi.equals(computedXi)).toBeTruthy();
    });
    const xt = Zq.getElement(hexToBytes(tv.xt));
    const computedXt = await uprove.computeXt(ip, TI);
    expect(xt.equals(computedXt)).toBeTruthy();

    // NOTE: skipping validation of issuance since we don't have a way
    // to inject randomness in the RNG. TODO: implement that.

    // verifier validates the presentation proof
    const upt: uprove.UProveToken = {
        UIDP: ip.UIDP,
        h: Gq.getElement(hexToBytes(encodePoint(tv.h_x, tv.h_y))),
        TI: TI,
        PI: PI,
        sZp: Gq.getElement(hexToBytes(encodePoint(tv.sigmaZPrime_x, tv.sigmaZPrime_y))),
        sCp: Zq.getElement(hexToBytes(tv.sigmaCPrime)),
        sRp: Zq.getElement(hexToBytes(tv.sigmaRPrime))
    }

    const D: number[] = tv.D.split(',').filter(i => i != '').map(i => parseInt(i));
    const USet = new Set<number>(Array.from({ length: n }, (e, i) => i + 1));
    D.forEach(i => USet.delete(i));
    const U = Array.from(USet).sort((a, b) => a - b);

    const rInU: string[] = U.map(i => (tv as unknown as Record<string, string>)["r" + i]);
    const r = [Zq.getElement(hexToBytes(tv.r0)), ...rInU.map(r => Zq.getElement(hexToBytes(r)))];

    const disclosedA: { [key: number]: Uint8Array } = {};
    for (const d of D) {
        disclosedA[d] = A[d - 1];
    }
    const proof: uprove.PresentationProof = {
        A: disclosedA,
        a: hexToBytes(tv.a),
        r: r
    }
    const verificationData = await uprove.verifyPresentationProof(ip, upt, hexToBytes(tv.m), proof, hexToBytes(tv.md));
    arrayEqual(verificationData.UIDT, hexToBytes(tv.UIDt));

}

test("Test vectors EC D0 lite", async () => {
    run(EC_D0);
});

test("Test vectors EC D2 lite", async () => {
    run(EC_D2);
});

test("Test vectors EC D5 lite", async () => {
    run(EC_D5);
});
