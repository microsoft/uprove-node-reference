// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Implements the U-Prove JSON Framework (UPJF)

import { getEcGroup } from "./ecparams.js";
import { Byte, groupToHash } from "./hash.js";
import { FieldZqElement } from "./math.js";
import { TokenPresentation } from "./serialization.js";
import { createIssuerKeyAndParams, ECGroup, IssuerKeyAndParams, IssuerKeyPair, IssuerParams } from "./uprove.js"
import { checkUnsignedInt } from "./utils.js";

const toBase64Url = (a: Uint8Array) => Buffer.from(a).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); // FIXME: isn't base64url encoding supported?
const fromBase64Url = (b64: string): Uint8Array => Buffer.from(b64, 'base64');

// expiration functions
export enum ExpirationType { sec, hour, day, week, year }

const MS_PER_SECOND = 1000;
const MS_PER_HOUR = MS_PER_SECOND * 60 * 60;
const MS_PER_DAY = MS_PER_HOUR * 24;
const MS_PER_WEEK = MS_PER_DAY * 7;
const MS_PER_YEAR = MS_PER_WEEK * 52;


export function msToTypedTime(type:ExpirationType, t:number): number {
    let typedT;
    switch (type) {
        case ExpirationType.sec:  typedT = t / MS_PER_SECOND; break;
        case ExpirationType.hour: typedT = t / MS_PER_HOUR;   break;
        case ExpirationType.day:  typedT = t / MS_PER_DAY;    break;
        case ExpirationType.week: typedT = t / MS_PER_WEEK;   break;
        case ExpirationType.year: typedT = t / MS_PER_YEAR;   break;
    }
    return typedT;
}
/**
 * Gets the expiration date given an expiration type, value, and start time.
 * @param {ExpirationType} type - expiration type
 * @param {number} t - non-negative integer, number of typed units to add to epoch 
 * @param {number} start - typed start time; defaults to the current time
 * @returns the expiration date, adding `t` units from the `start` time of a given `type`
 */
export function getExp(type:ExpirationType, t:number, start:number|undefined = undefined): number {
    checkUnsignedInt(t);
    if (start) {
        checkUnsignedInt(start);
    } else {
        // round up current time to next value depending on expiration type
        start = Math.ceil(msToTypedTime(type, Date.now()));
    }
    return start + t;
}

/**
 * Checks if the typed target date is after the expiration
 * @param {ExpirationType} type - expiration type 
 * @param {number} exp - typed expiration date
 * @param {number} target - typed target date for comparison; defaults to the current time
 * @returns `true` if the target date is expired, `false` otherwise
 */
export function isExpired(type: ExpirationType, exp: number, target:number|undefined = undefined): boolean {
    if (!target) {
        target = msToTypedTime(type, Date.now());
    }
    return target > exp;
}

// Issuer Parameters functions
export interface Specification {
    n: number,
    expType: ExpirationType
}

export function parseSpecification(S: Uint8Array): Specification {
    const spec = JSON.parse(S.toString()) as Specification;
    return spec;
}

export function createIssuerKeyAndParamsUPJF(descGq: ECGroup, specification: Specification, issKeyPair?: IssuerKeyPair | undefined): IssuerKeyAndParams {
    const n = specification.n;
    checkUnsignedInt(n);
    if (n < 0 || n > 50) throw `${n} is not a valid value for n, must between 0 and 50 inclusively`;
    return createIssuerKeyAndParams(descGq, n, undefined, Buffer.from(JSON.stringify(specification)), issKeyPair, undefined);
}

export enum UPAlg {
    UP256 = "UP256",
    UP384 = "UP384",
    UP521 = "UP521"
}

export interface IssuerParamsJWK {
    kty: "UP";
    alg: UPAlg;
    kid: string;
    g0: string;
    e?: number[];
    S: string;
}

export function encodePrivateKeyAsBase64Url(y0: FieldZqElement): string {
    return toBase64Url(y0.getBytes());
}

export function decodeBase64UrlAsPrivateKey(ip: IssuerParams, b64: string): FieldZqElement {
    return ip.Gq.Zq.getElement(fromBase64Url(b64));
}

export function descGqToUPAlg(descGq:ECGroup): UPAlg {
    switch (descGq) {
        case ECGroup.P256: return UPAlg.UP256;
        case ECGroup.P384: return UPAlg.UP384;
        case ECGroup.P521: return UPAlg.UP521;
    }
}

export function encodeIPAsJWK(ip: IssuerParams): IssuerParamsJWK {
    return {
        kty: "UP",
        alg: descGqToUPAlg(ip.descGq),
        kid: toBase64Url(ip.UIDP),
        g0: toBase64Url(ip.g[0].getBytes()),
        S: toBase64Url(ip.S)
    };
}

export function decodeJWKAsIP(jwk: IssuerParamsJWK): IssuerParams {
    if (jwk.kty !== "UP") {
        throw `${jwk.kty} is not a valid key type, "UP" expected`;
    } 
    let descGq:ECGroup;
    switch (jwk.alg) {
        case UPAlg.UP256: descGq = ECGroup.P256; break;
        case UPAlg.UP384: descGq = ECGroup.P384; break;
        case UPAlg.UP521: descGq = ECGroup.P521; break;
        default: throw `${jwk.alg} is not a valid algorithm`;
    }
    const SBytes = fromBase64Url(jwk.S);
    const spec = JSON.parse(SBytes.toString());
    const n = spec.n;
    const groupParams = getEcGroup(descGq);
    const Gq = groupParams.Gq;
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

export interface TokenInformation {
    iss: string,
    exp: number
}

export function parseTokenInformation(TI: Uint8Array): TokenInformation {
    const tokenInformation = JSON.parse(TI.toString()) as TokenInformation;
    return tokenInformation;
}

export function encodeTokenInformation(TI: TokenInformation): Uint8Array {
    return Buffer.from(JSON.stringify(TI));
}

export interface UPJWSHeader {
    alg: UPAlg
}

export interface UPJWS {
    header: UPJWSHeader,
    payload: Uint8Array,
    sig: TokenPresentation
}

export function createJWS(alg: UPAlg, m: Uint8Array, tp: TokenPresentation): string {
    const header = toBase64Url(Buffer.from(JSON.stringify({ alg: alg })));
    const payload = toBase64Url(m);
    const sig = toBase64Url(Buffer.from(JSON.stringify( tp ))); 
    return header + "." + payload + "." + sig;
}

export function parseJWS(jws: string): UPJWS {
    const parts = jws.split(".");
    if (!parts || parts.length != 3) {
        throw "can't parse jws into 3 parts";
    }
    try {
        const upJws: UPJWS = {
            header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as UPJWSHeader,
            payload: Buffer.from(parts[1], 'base64url'),
            sig: JSON.parse(Buffer.from(parts[2], 'base64url').toString('utf8')) as TokenPresentation
        }
        return upJws;
    } catch (err) {
        throw "can't parse jws" + err;
    }
}
