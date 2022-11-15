// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// This file defines a JSON serialization format for the U-Prove artifacts

import {ECGroup, FirstIssuanceMessage, IssuerParams, PresentationProof, SecondIssuanceMessage, ThirdIssuanceMessage, UProveToken} from '../src/uprove';
import { getEcGroup } from './ecparams';
import { Byte } from './hash';

const toB64 = (a: Uint8Array) => Buffer.from(a).toString('base64');
const fromB64 = (b64: string): Uint8Array => Buffer.from(b64, 'base64');

export interface IssuerParamsJSON {
    UIDP: string;
    groupOID: string;
    UIDH: string;
    g0: string;
    e: number[];
    S: string;
}

export function encodeIssuerParams(ip: IssuerParams): IssuerParamsJSON {
    return {
        UIDP: toB64(ip.UIDP),
        groupOID: ip.descGq,
        UIDH: ip.UIDH,
        g0: toB64(ip.g[0].getBytes()),
        e: ip.e.map(e => e.b[0]),
        S: toB64(ip.S)
    }
}

export function decodeIssuerParams(ipJSON: IssuerParamsJSON): IssuerParams {
    const n = ipJSON.e.length;
    let descGq = ECGroup.P256;
    switch (ipJSON.groupOID) {
        case ECGroup.P256: descGq = ECGroup.P256; break;
        case ECGroup.P384: descGq = ECGroup.P384; break;
        case ECGroup.P521: descGq = ECGroup.P521; break;
    }
    const groupParams = getEcGroup(descGq);
    const Gq = groupParams.Gq;
    const Zq = Gq.Zq;
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
    sigmaZPrime: string,
    sigmaCPrime: string,
    sigmaRPrime: string
}

export function encodeUProveToken(upt: UProveToken): UProveTokenJSON {
    return {
        UIDP: toB64(upt.UIDP),
        h: toB64(upt.h.getBytes()),
        TI: toB64(upt.TI),
        PI: toB64(upt.PI),
        sigmaZPrime: toB64(upt.sigmaZPrime.getBytes()),
        sigmaCPrime: toB64(upt.sigmaCPrime.getBytes()),
        sigmaRPrime: toB64(upt.sigmaRPrime.getBytes())
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
        sigmaZPrime: Gq.getElement(fromB64(uptJSON.sigmaZPrime)),
        sigmaCPrime: Zq.getElement(fromB64(uptJSON.sigmaCPrime)),
        sigmaRPrime: Zq.getElement(fromB64(uptJSON.sigmaRPrime))
    }
}

export interface FirstIssuanceMessageJSON {
    sigmaZ: string,
    sigmaA: string[],
    sigmaB: string[]
}

export function encodeFirstIssuanceMessage(m1: FirstIssuanceMessage): FirstIssuanceMessageJSON {
    return {
        sigmaZ: toB64(m1.sigmaZ.getBytes()),
        sigmaA: m1.sigmaA.map(sigmaA => toB64(sigmaA.getBytes())),
        sigmaB: m1.sigmaB.map(sigmaB => toB64(sigmaB.getBytes())),
    }
}

export function decodeFirstIssuanceMessage(ip: IssuerParams, m1JSON: FirstIssuanceMessageJSON): FirstIssuanceMessage {
    const Gq = ip.Gq;
    return {
        sigmaZ: Gq.getElement(fromB64(m1JSON.sigmaZ)),
        sigmaA: m1JSON.sigmaA.map(sigmaA => Gq.getElement(fromB64(sigmaA))),
        sigmaB: m1JSON.sigmaB.map(sigmaB => Gq.getElement(fromB64(sigmaB)))
    }
}

export interface SecondIssuanceMessageJSON {
    sigmaC: string[]
}

export function encodeSecondIssuanceMessage(m2: SecondIssuanceMessage): SecondIssuanceMessageJSON {
    return {
        sigmaC: m2.sigmaC.map(sigmaC => toB64(sigmaC.getBytes()))
    }
}

export function decodeSecondIssuanceMessage(ip: IssuerParams, m2JSON: SecondIssuanceMessageJSON): SecondIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sigmaC: m2JSON.sigmaC.map(sigmaC => Zq.getElement(fromB64(sigmaC)))
    }
}

export interface ThirdIssuanceMessageJSON {
    sigmaR: string[]
}

export function encodeThirdIssuanceMessage(m3: ThirdIssuanceMessage): ThirdIssuanceMessageJSON {
    return {
        sigmaR: m3.sigmaR.map(sigmaR => toB64(sigmaR.getBytes()))
    }
}

export function decodeThirdIssuanceMessage(ip: IssuerParams, m3JSON: ThirdIssuanceMessageJSON): ThirdIssuanceMessage {
    const Zq = ip.Gq.Zq;
    return {
        sigmaR: m3JSON.sigmaR.map(sigmaR => Zq.getElement(fromB64(sigmaR)))
    }
}

export interface PresentationProofJSON {
    disclosedA: string[],
    a: string,
    r: string[]
}

export function encodePresentationProof(pp: PresentationProof): PresentationProofJSON {
    return {
        disclosedA: pp.disclosedA.map(A => toB64(A)),
        a: toB64(pp.a),
        r: pp.r.map(r => toB64(r.getBytes()))
    }
}

export function decodePresentationProof(ip: IssuerParams, ppJSON: PresentationProofJSON): PresentationProof {
    const Zq = ip.Gq.Zq;
    return {
        disclosedA: ppJSON.disclosedA.map(A => fromB64(A)),
        a: fromB64(ppJSON.a),
        r: ppJSON.r.map(r => Zq.getElement(fromB64(r)))
    }
}