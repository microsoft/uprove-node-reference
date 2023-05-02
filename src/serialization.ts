// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This file defines a JSON serialization format for the U-Prove artifacts

import {ECGroup, FirstIssuanceMessage, IssuerParams, PresentationProof, SecondIssuanceMessage, ThirdIssuanceMessage, UProveToken} from './uprove.js';
import { getEcGroup } from './ecparams.js';
import { Byte } from './hash.js';

const toB64 = (a: Uint8Array) => Buffer.from(a).toString('base64');
const fromB64 = (b64: string): Uint8Array => Buffer.from(b64, 'base64');

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
        UIDP: toB64(ip.UIDP),
        dGq: ip.descGq,
        UIDH: ip.UIDH,
        g0: toB64(ip.g[0].getBytes()),
        e: ip.e.map(e => e.b[0]),
        S: toB64(ip.S)
    }
}

export function decodeIssuerParams(ipJSON: IssuerParamsJSON): IssuerParams {
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
    g.unshift(Gq.getElement(fromB64(ipJSON.g0)));
    g.push(groupParams.gt);

    return new IssuerParams(
        fromB64(ipJSON.UIDP),
        descGq,
        ipJSON.UIDH,
        g,
        ipJSON.e.map(e => new Byte(e)),
        fromB64(ipJSON.S)
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
        UIDP: toB64(upt.UIDP),
        h: toB64(upt.h.getBytes()),
        TI: toB64(upt.TI),
        PI: toB64(upt.PI),
        sZp: toB64(upt.sZp.getBytes()),
        sCp: toB64(upt.sCp.getBytes()),
        sRp: toB64(upt.sRp.getBytes())
    }
}

export function decodeUProveToken(ip: IssuerParams, uptJSON: UProveTokenJSON): UProveToken {
    const Gq = ip.Gq;
    const Zq = Gq.Zq;
    return {
        UIDP: fromB64(uptJSON.UIDP),
        h: Gq.getElement(fromB64(uptJSON.h)),
        TI: fromB64(uptJSON.TI),
        PI: fromB64(uptJSON.PI),
        sZp: Gq.getElement(fromB64(uptJSON.sZp)),
        sCp: Zq.getElement(fromB64(uptJSON.sCp)),
        sRp: Zq.getElement(fromB64(uptJSON.sRp))
    }
}

export interface FirstIssuanceMessageJSON {
    sZ: string,
    sA: string[],
    sB: string[]
}

export function encodeFirstIssuanceMessage(m1: FirstIssuanceMessage): FirstIssuanceMessageJSON {
    return {
        sZ: toB64(m1.sZ.getBytes()),
        sA: m1.sA.map(sigmaA => toB64(sigmaA.getBytes())),
        sB: m1.sB.map(sigmaB => toB64(sigmaB.getBytes())),
    }
}

export function decodeFirstIssuanceMessage(ip: IssuerParams, m1JSON: FirstIssuanceMessageJSON): FirstIssuanceMessage {
    const Gq = ip.Gq;
    return {
        sZ: Gq.getElement(fromB64(m1JSON.sZ)),
        sA: m1JSON.sA.map(sigmaA => Gq.getElement(fromB64(sigmaA))),
        sB: m1JSON.sB.map(sigmaB => Gq.getElement(fromB64(sigmaB)))
    }
}

export interface SecondIssuanceMessageJSON {
    sC: string[]
}

export function encodeSecondIssuanceMessage(m2: SecondIssuanceMessage): SecondIssuanceMessageJSON {
    return {
        sC: m2.sC.map(sigmaC => toB64(sigmaC.getBytes()))
    }
}

export function decodeSecondIssuanceMessage(ip: IssuerParams, m2JSON: SecondIssuanceMessageJSON): SecondIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sC: m2JSON.sC.map(sigmaC => Zq.getElement(fromB64(sigmaC)))
    }
}

export interface ThirdIssuanceMessageJSON {
    sR: string[]
}

export function encodeThirdIssuanceMessage(m3: ThirdIssuanceMessage): ThirdIssuanceMessageJSON {
    return {
        sR: m3.sR.map(sigmaR => toB64(sigmaR.getBytes()))
    }
}

export function decodeThirdIssuanceMessage(ip: IssuerParams, m3JSON: ThirdIssuanceMessageJSON): ThirdIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sR: m3JSON.sR.map(sigmaR => Zq.getElement(fromB64(sigmaR)))
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
    let ppJSON:PresentationProofJSON =
    {
        a: toB64(pp.a),
        r: pp.r.map(r => toB64(r.getBytes()))
    }
    if (pp.A && Object.keys(pp.A).length  > 0) {
        ppJSON.A =  Object.entries(pp.A).reduce((acc, [i, Ai]) => {
            acc[Number(i)] = toB64(Ai);
            return acc;
          }, {} as { [index: number]: string });
    }
    return ppJSON;
}

export function decodePresentationProof(ip: IssuerParams, ppJSON: PresentationProofJSON): PresentationProof {
    const Zq = ip.Gq.Zq;
    let pp: PresentationProof = {
        a: fromB64(ppJSON.a),
        r: ppJSON.r.map(r => Zq.getElement(fromB64(r)))
    }
    if (ppJSON.A) {
        pp.A = Object.entries(ppJSON.A).reduce((acc, [i, Ai]) => {
            acc[Number(i)] = fromB64(Ai);
            return acc;
            }, {} as { [index: number]: Uint8Array });
    }
    return pp;
}

export function encodeUIDT(UIDT: Uint8Array): string {
    return toB64(UIDT);
}

export function decodeUIDT(UIDT: string): Uint8Array {
    return fromB64(UIDT);
}

// presentation
export interface TokenPresentation {
    upt?: UProveTokenJSON,
    uidt?: string,
    pp: PresentationProofJSON
}
