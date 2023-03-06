// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { getEcGroup } from "../src/ecparams.js";
import { Group } from "../src/math.js";
import { ECGroup } from "../src/uprove.js";

function testGroup(descGq: ECGroup) {
    const Gq = new Group(descGq);
    const Zq = Gq.Zq;

    // get random elements from recommended params
    const n = 10;
    const group = getEcGroup(descGq);
    const generators = group.g.slice(0, n);

    ////////////
    // test hash
    ////////////

    const hash = Gq.getHash();
    const digest = Gq.updateHash(hash);

    //////////
    // test Zq
    //////////
    expect(Zq.add(Zq.ZERO, Zq.ZERO).equals(Zq.ZERO)).toBeTruthy();
    expect(Zq.add(Zq.ZERO, Zq.ONE).equals(Zq.ONE)).toBeTruthy();
    expect(Zq.add(Zq.ONE, Zq.ZERO).equals(Zq.ONE)).toBeTruthy();
    const r = Zq.getRandomElement(true);
    const negR = Zq.negate(r);
    expect(Zq.add(r, negR).equals(Zq.ZERO)).toBeTruthy();
    const invR = Zq.invert(r);
    expect(Zq.mul(r, invR).equals(Zq.ONE)).toBeTruthy();

    //////////
    // test Gq
    //////////

    // test identity
    const I = Gq.getIdentity();
    const g = generators[0];
    expect(Gq.mul(g, I).equals(g)).toBeTruthy();
    expect(Gq.mul(I, g).equals(g)).toBeTruthy();
    
    // test modExp
    expect(Gq.modExp(g, Zq.ZERO).equals(I)).toBeTruthy();
    expect(Gq.modExp(g, Zq.ONE).equals(g)).toBeTruthy();
    expect(Gq.modExp(g, Zq.add(Zq.ONE, Zq.ONE)).equals(Gq.mul(g,g))).toBeTruthy();

    // test mul
    const invG = Gq.modExp(g, Zq.negate(Zq.ONE)); 
    expect(Gq.mul(g, invG).equals(I)).toBeTruthy();

    // test multi mod exp
    const e = Zq.getRandomElements(n);
    const h1 = Gq.multiModExp(generators, e);
    let h2 = Gq.getIdentity();
    for (let i=0; i<n; i++) {
        h2 = Gq.mul(h2, Gq.modExp(generators[i], e[i]));
    }
    expect(h1.equals(h2)).toBeTruthy();
}

test("Group P256", async () => {
    testGroup(ECGroup.P256);
});

test("Group P384", async () => {
    testGroup(ECGroup.P384);
});

test("Group P521", async () => {
    testGroup(ECGroup.P521);
});
