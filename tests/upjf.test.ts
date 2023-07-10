// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { ECGroup } from "../src/uprove.js";
import * as UPJF from "../src/upjf.js";
import { arrayEqual } from "../src/utils.js";

test("UPJF issuer setup", async () => {
    // generate issuer params
    const ikp = await UPJF.createIssuerKeyAndParamsUPJF(ECGroup.P256, { n: 0, expType: UPJF.ExpirationType.sec}, undefined);
    // serialize values
    const jwk = UPJF.encodeIPAsJWK(ikp.ip);
    const key = UPJF.encodePrivateKeyAsBase64Url(ikp.y0)
    // deserialize values
    const ip = await UPJF.decodeJWKAsIP(jwk);
    ip.verify();
    const y0 = UPJF.decodeBase64UrlAsPrivateKey(ip, key);

    expect(ikp.y0.equals(y0)).toBeTruthy();
    expect(arrayEqual(await ikp.ip.P, await ip.P)).toBeTruthy();
});

test("UPJF expiration", async () => {
    const expS = UPJF.getExp(UPJF.ExpirationType.sec,  10); // 10 sec expiration
    expect(UPJF.isExpired(UPJF.ExpirationType.sec, expS)).toBeFalsy();
    const nowS = Date.now() / 1000;
    expect(UPJF.isExpired(UPJF.ExpirationType.sec, expS, nowS + 100)).toBeTruthy();

    // check that `now` is used as default time
    const expH = UPJF.getExp(UPJF.ExpirationType.hour, 0);
    const expHnow = UPJF.getExp(UPJF.ExpirationType.hour, 0, Math.ceil(nowS / (60 * 60)));
    expect(expH === expHnow).toBeTruthy();

    // check other calls
    const expD = UPJF.getExp(UPJF.ExpirationType.day,  0);
    const expW = UPJF.getExp(UPJF.ExpirationType.week, 0);
    const expY = UPJF.getExp(UPJF.ExpirationType.year, 0);
});