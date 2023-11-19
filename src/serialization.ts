// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This file defines a JSON serialization format for the U-Prove artifacts

import {ECGroup, FirstIssuanceMessage, IssuerParams, PresentationProof, SecondIssuanceMessage, ThirdIssuanceMessage, UProveToken} from './uprove.js';
import { getEcGroup } from './ecparams.js';
import { Byte } from './hash.js';
import { base64urlToBytes, bytesToBase64url } from './utils.js';

export { base64urlToBytes as fromBase64Url, bytesToBase64url as toBase64Url }

export interface IssuerParamsJSON {
    UIDP: string;
    dGq: string;
    UIDH: string;
    g0: string;
    e: number[];
    S: string;
}

export function encodeIssuerParams(ip: IssuerParams): IssuerParamsJSON {
    return {
        UIDP: bytesToBase64url(ip.UIDP),
        dGq: ip.descGq,
        UIDH: ip.UIDH,
        g0: bytesToBase64url(ip.g[0].getBytes()),
        e: ip.e.map(e => e.b[0]),
        S: bytesToBase64url(ip.S)
    }
}

export async function decodeIssuerParams(ipJSON: IssuerParamsJSON): Promise<IssuerParams> {
    const n = ipJSON.e.length;
    let descGq = ECGroup.P256;
    switch (ipJSON.dGq) {
        case ECGroup.P256: descGq = ECGroup.P256; break;
        case ECGroup.P384: descGq = ECGroup.P384; break;
        case ECGroup.P521: descGq = ECGroup.P521; break;
    }
    const groupParams = getEcGroup(descGq);
    const Gq = groupParams.Gq;
    // g = [g0, g1, ... gn, gt]
    const g = groupParams.g.slice(0, n); // keep only n generators
    g.unshift(Gq.getElement(base64urlToBytes(ipJSON.g0)));
    g.push(groupParams.gt);

    return await IssuerParams.create(
        base64urlToBytes(ipJSON.UIDP),
        descGq,
        ipJSON.UIDH,
        g,
        ipJSON.e.map(e => new Byte(e)),
        base64urlToBytes(ipJSON.S)
    )
}

export interface UProveTokenJSON {
    UIDP: string,
    h: string,
    TI: string,
    PI: string,
    sZp: string,
    sCp: string,
    sRp: string
}

export function encodeUProveToken(upt: UProveToken): UProveTokenJSON {
    return {
        UIDP: bytesToBase64url(upt.UIDP),
        h: bytesToBase64url(upt.h.getBytes()),
        TI: bytesToBase64url(upt.TI),
        PI: bytesToBase64url(upt.PI),
        sZp: bytesToBase64url(upt.sZp.getBytes()),
        sCp: bytesToBase64url(upt.sCp.getBytes()),
        sRp: bytesToBase64url(upt.sRp.getBytes())
    }
}

export function decodeUProveToken(ip: IssuerParams, uptJSON: UProveTokenJSON): UProveToken {
    const Gq = ip.Gq;
    const Zq = Gq.Zq;
    return {
        UIDP: base64urlToBytes(uptJSON.UIDP),
        h: Gq.getElement(base64urlToBytes(uptJSON.h)),
        TI: base64urlToBytes(uptJSON.TI),
        PI: base64urlToBytes(uptJSON.PI),
        sZp: Gq.getElement(base64urlToBytes(uptJSON.sZp)),
        sCp: Zq.getElement(base64urlToBytes(uptJSON.sCp)),
        sRp: Zq.getElement(base64urlToBytes(uptJSON.sRp))
    }
}

export interface FirstIssuanceMessageJSON {
    sZ: string,
    sA: string[],
    sB: string[]
}

export function encodeFirstIssuanceMessage(m1: FirstIssuanceMessage): FirstIssuanceMessageJSON {
    return {
        sZ: bytesToBase64url(m1.sZ.getBytes()),
        sA: m1.sA.map(sigmaA => bytesToBase64url(sigmaA.getBytes())),
        sB: m1.sB.map(sigmaB => bytesToBase64url(sigmaB.getBytes())),
    }
}

export function decodeFirstIssuanceMessage(ip: IssuerParams, m1JSON: FirstIssuanceMessageJSON): FirstIssuanceMessage {
    const Gq = ip.Gq;
    return {
        sZ: Gq.getElement(base64urlToBytes(m1JSON.sZ)),
        sA: m1JSON.sA.map(sigmaA => Gq.getElement(base64urlToBytes(sigmaA))),
        sB: m1JSON.sB.map(sigmaB => Gq.getElement(base64urlToBytes(sigmaB)))
    }
}

export interface SecondIssuanceMessageJSON {
    sC: string[]
}

export function encodeSecondIssuanceMessage(m2: SecondIssuanceMessage): SecondIssuanceMessageJSON {
    return {
        sC: m2.sC.map(sigmaC => bytesToBase64url(sigmaC.getBytes()))
    }
}

export function decodeSecondIssuanceMessage(ip: IssuerParams, m2JSON: SecondIssuanceMessageJSON): SecondIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sC: m2JSON.sC.map(sigmaC => Zq.getElement(base64urlToBytes(sigmaC)))
    }
}

export interface ThirdIssuanceMessageJSON {
    sR: string[]
}

export function encodeThirdIssuanceMessage(m3: ThirdIssuanceMessage): ThirdIssuanceMessageJSON {
    return {
        sR: m3.sR.map(sigmaR => bytesToBase64url(sigmaR.getBytes()))
    }
}

export function decodeThirdIssuanceMessage(ip: IssuerParams, m3JSON: ThirdIssuanceMessageJSON): ThirdIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sR: m3JSON.sR.map(sigmaR => Zq.getElement(base64urlToBytes(sigmaR)))
    }
}

export interface PresentationProofJSON {
    A?: {
        [index: number]: string;
    }
    a: string,
    r: string[]
}

export function encodePresentationProof(pp: PresentationProof): PresentationProofJSON {
    const ppJSON:PresentationProofJSON =
    {
        a: bytesToBase64url(pp.a),
        r: pp.r.map(r => bytesToBase64url(r.getBytes()))
    }
    if (pp.A && Object.keys(pp.A).length  > 0) {
        ppJSON.A =  Object.entries(pp.A).reduce((acc, [i, Ai]) => {
            acc[Number(i)] = bytesToBase64url(Ai);
            return acc;
          }, {} as { [index: number]: string });
    }
    return ppJSON;
}

export function decodePresentationProof(ip: IssuerParams, ppJSON: PresentationProofJSON): PresentationProof {
    const Zq = ip.Gq.Zq;
    const pp: PresentationProof = {
        a: base64urlToBytes(ppJSON.a),
        r: ppJSON.r.map(r => Zq.getElement(base64urlToBytes(r)))
    }
    if (ppJSON.A) {
        pp.A = Object.entries(ppJSON.A).reduce((acc, [i, Ai]) => {
            acc[Number(i)] = base64urlToBytes(Ai);
            return acc;
            }, {} as { [index: number]: Uint8Array });
    }
    return pp;
}

export function encodeUIDT(UIDT: Uint8Array): string {
    return bytesToBase64url(UIDT);
}

export function decodeUIDT(UIDT: string): Uint8Array {
    return base64urlToBytes(UIDT);
}

// presentation
export interface TokenPresentation {
    upt?: UProveTokenJSON,
    uidt?: string,
    pp: PresentationProofJSON
}
