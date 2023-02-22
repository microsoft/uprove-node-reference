// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { getEcGroup } from "./ecparams";
import { Byte, groupToHash } from "./hash";
import { createIssuerKeyAndParams, ECGroup, IssuerKeyAndParams, IssuerKeyPair, IssuerParams } from "./uprove"

// Implements the U-Prove JSON Framework (UPJF)

const toBase64Url = (a: Uint8Array) => Buffer.from(a).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); // FIXME: isn't base64url encoding supported?
const fromBase64Url = (b64: string): Uint8Array => Buffer.from(b64, 'base64');

export enum ExpirationType { hour, day, week, month, year }

export interface Specification {
    n: number,
//    expType: ExpirationType FIXME
}

// Issuer Parameters functions

export function createIssuerKeyAndParamsUPJF(descGq: ECGroup, specification: Specification, issKeyPair?: IssuerKeyPair | undefined): IssuerKeyAndParams {
    const n = specification.n;
    if (n < 0 || n > 50) throw `${n} is not a valid value for n, must between 0 and 50 inclusively`;
    return createIssuerKeyAndParams(descGq, n, undefined, Buffer.from(JSON.stringify(specification)), issKeyPair, undefined);
}

export interface IssuerParamsJWK {
    kty: "UP";
    alg: "UP115";
    crv: string;
    kid: string;
    g0: string;
    e?: number[];
    S: string;
    spec?: Specification; // maybe that should stay encoded to make sure it won't change
}

// TODO: rewrite
export function encodeIPAsJWK(ip: IssuerParams): IssuerParamsJWK {
    let jwk: IssuerParamsJWK = {
        kty: "UP",
        alg: "UP115",
        crv: ip.descGq,
        kid: toBase64Url(ip.UIDP),
        g0: toBase64Url(ip.g[0].getBytes()),
        S: toBase64Url(ip.S)
        // spec: {
        //     n: ip.e.length
        // }
    };
    return jwk; // FIXME collapse
}

export function decodeJWKAsIP(jwk: IssuerParamsJWK): IssuerParams {
    if (jwk.kty !== "UP") {
        throw `${jwk.kty} is not a valid key type, "UP" expected`;
    } 
    if (jwk.alg !== "UP115") {
        throw `${jwk.alg} is not a valid algorithm, "UP115" expected`;
    } 
    const SBytes = fromBase64Url(jwk.S);
    const spec = JSON.parse(SBytes.toString());
    const n = spec.n;
    const descGq:ECGroup = jwk.crv as ECGroup;
    // switch (ipJSON.groupOID) {
    //     case ECGroup.P256: descGq = ECGroup.P256; break;
    //     case ECGroup.P384: descGq = ECGroup.P384; break;
    //     case ECGroup.P521: descGq = ECGroup.P521; break;
    // }
    const groupParams = getEcGroup(descGq);
    const Gq = groupParams.Gq;
    const Zq = Gq.Zq;
    // g = [g0, g1, ... gn, gt]
    const g = groupParams.g.slice(0, n); // keep only n generators
    g.unshift(Gq.getElement(fromBase64Url(jwk.g0)));
    g.push(groupParams.gt);
    const e = jwk.e ? jwk.e : new Array(n).fill(1); 

    return new IssuerParams(
        fromBase64Url(jwk.kid),
        descGq,
        groupToHash(descGq),
        g,
        e.map(e => new Byte(e)),
        SBytes
    )
}
