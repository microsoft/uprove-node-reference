// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This file defines a JSON serialization format for the U-Prove artifacts

import {ECGroup, FirstIssuanceMessage, IssuerParams, PresentationProof, SecondIssuanceMessage, ThirdIssuanceMessage, UProveToken} from './uprove.js';
import { getEcGroup } from './ecparams.js';
import { Byte } from './hash.js';

export const toBase64Url = (a: Uint8Array) => Buffer.from(a).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); // FIXME: isn't base64url encoding supported?
export const fromBase64Url = (b64: string): Uint8Array => Buffer.from(b64, 'base64');

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
        UIDP: toBase64Url(ip.UIDP),
        dGq: ip.descGq,
        UIDH: ip.UIDH,
        g0: toBase64Url(ip.g[0].getBytes()),
        e: ip.e.map(e => e.b[0]),
        S: toBase64Url(ip.S)
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
    g.unshift(Gq.getElement(fromBase64Url(ipJSON.g0)));
    g.push(groupParams.gt);

    return new IssuerParams(
        fromBase64Url(ipJSON.UIDP),
        descGq,
        ipJSON.UIDH,
        g,
        ipJSON.e.map(e => new Byte(e)),
        fromBase64Url(ipJSON.S)
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
        UIDP: toBase64Url(upt.UIDP),
        h: toBase64Url(upt.h.getBytes()),
        TI: toBase64Url(upt.TI),
        PI: toBase64Url(upt.PI),
        sZp: toBase64Url(upt.sZp.getBytes()),
        sCp: toBase64Url(upt.sCp.getBytes()),
        sRp: toBase64Url(upt.sRp.getBytes())
    }
}

export function decodeUProveToken(ip: IssuerParams, uptJSON: UProveTokenJSON): UProveToken {
    const Gq = ip.Gq;
    const Zq = Gq.Zq;
    return {
        UIDP: fromBase64Url(uptJSON.UIDP),
        h: Gq.getElement(fromBase64Url(uptJSON.h)),
        TI: fromBase64Url(uptJSON.TI),
        PI: fromBase64Url(uptJSON.PI),
        sZp: Gq.getElement(fromBase64Url(uptJSON.sZp)),
        sCp: Zq.getElement(fromBase64Url(uptJSON.sCp)),
        sRp: Zq.getElement(fromBase64Url(uptJSON.sRp))
    }
}

export interface FirstIssuanceMessageJSON {
    sZ: string,
    sA: string[],
    sB: string[]
}

export function encodeFirstIssuanceMessage(m1: FirstIssuanceMessage): FirstIssuanceMessageJSON {
    return {
        sZ: toBase64Url(m1.sZ.getBytes()),
        sA: m1.sA.map(sigmaA => toBase64Url(sigmaA.getBytes())),
        sB: m1.sB.map(sigmaB => toBase64Url(sigmaB.getBytes())),
    }
}

export function decodeFirstIssuanceMessage(ip: IssuerParams, m1JSON: FirstIssuanceMessageJSON): FirstIssuanceMessage {
    const Gq = ip.Gq;
    return {
        sZ: Gq.getElement(fromBase64Url(m1JSON.sZ)),
        sA: m1JSON.sA.map(sigmaA => Gq.getElement(fromBase64Url(sigmaA))),
        sB: m1JSON.sB.map(sigmaB => Gq.getElement(fromBase64Url(sigmaB)))
    }
}

export interface SecondIssuanceMessageJSON {
    sC: string[]
}

export function encodeSecondIssuanceMessage(m2: SecondIssuanceMessage): SecondIssuanceMessageJSON {
    return {
        sC: m2.sC.map(sigmaC => toBase64Url(sigmaC.getBytes()))
    }
}

export function decodeSecondIssuanceMessage(ip: IssuerParams, m2JSON: SecondIssuanceMessageJSON): SecondIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sC: m2JSON.sC.map(sigmaC => Zq.getElement(fromBase64Url(sigmaC)))
    }
}

export interface ThirdIssuanceMessageJSON {
    sR: string[]
}

export function encodeThirdIssuanceMessage(m3: ThirdIssuanceMessage): ThirdIssuanceMessageJSON {
    return {
        sR: m3.sR.map(sigmaR => toBase64Url(sigmaR.getBytes()))
    }
}

export function decodeThirdIssuanceMessage(ip: IssuerParams, m3JSON: ThirdIssuanceMessageJSON): ThirdIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sR: m3JSON.sR.map(sigmaR => Zq.getElement(fromBase64Url(sigmaR)))
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
        a: toBase64Url(pp.a),
        r: pp.r.map(r => toBase64Url(r.getBytes()))
    }
    if (pp.A && Object.keys(pp.A).length  > 0) {
        ppJSON.A =  Object.entries(pp.A).reduce((acc, [i, Ai]) => {
            acc[Number(i)] = toBase64Url(Ai);
            return acc;
          }, {} as { [index: number]: string });
    }
    return ppJSON;
}

export function decodePresentationProof(ip: IssuerParams, ppJSON: PresentationProofJSON): PresentationProof {
    const Zq = ip.Gq.Zq;
    let pp: PresentationProof = {
        a: fromBase64Url(ppJSON.a),
        r: ppJSON.r.map(r => Zq.getElement(fromBase64Url(r)))
    }
    if (ppJSON.A) {
        pp.A = Object.entries(ppJSON.A).reduce((acc, [i, Ai]) => {
            acc[Number(i)] = fromBase64Url(Ai);
            return acc;
            }, {} as { [index: number]: Uint8Array });
    }
    return pp;
}

export function encodeUIDT(UIDT: Uint8Array): string {
    return toBase64Url(UIDT);
}

export function dncodeUIDT(UIDT: string): Uint8Array {
    return fromBase64Url(UIDT);
}

// presentation
export interface TokenPresentation {
    upt?: UProveTokenJSON,
    uidt?: string,
    pp: PresentationProofJSON
}
