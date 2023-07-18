import { FirstIssuanceMessage, IssuerParams, PresentationProof, SecondIssuanceMessage, ThirdIssuanceMessage, UProveToken } from './uprove.js';
import { base64urlToBytes, bytesToBase64url } from './utils.js';
export { base64urlToBytes as fromBase64Url, bytesToBase64url as toBase64Url };
export interface IssuerParamsJSON {
    UIDP: string;
    dGq: string;
    UIDH: string;
    g0: string;
    e: number[];
    S: string;
}
export declare function encodeIssuerParams(ip: IssuerParams): IssuerParamsJSON;
export declare function decodeIssuerParams(ipJSON: IssuerParamsJSON): Promise<IssuerParams>;
export interface UProveTokenJSON {
    UIDP: string;
    h: string;
    TI: string;
    PI: string;
    sZp: string;
    sCp: string;
    sRp: string;
}
export declare function encodeUProveToken(upt: UProveToken): UProveTokenJSON;
export declare function decodeUProveToken(ip: IssuerParams, uptJSON: UProveTokenJSON): UProveToken;
export interface FirstIssuanceMessageJSON {
    sZ: string;
    sA: string[];
    sB: string[];
}
export declare function encodeFirstIssuanceMessage(m1: FirstIssuanceMessage): FirstIssuanceMessageJSON;
export declare function decodeFirstIssuanceMessage(ip: IssuerParams, m1JSON: FirstIssuanceMessageJSON): FirstIssuanceMessage;
export interface SecondIssuanceMessageJSON {
    sC: string[];
}
export declare function encodeSecondIssuanceMessage(m2: SecondIssuanceMessage): SecondIssuanceMessageJSON;
export declare function decodeSecondIssuanceMessage(ip: IssuerParams, m2JSON: SecondIssuanceMessageJSON): SecondIssuanceMessage;
export interface ThirdIssuanceMessageJSON {
    sR: string[];
}
export declare function encodeThirdIssuanceMessage(m3: ThirdIssuanceMessage): ThirdIssuanceMessageJSON;
export declare function decodeThirdIssuanceMessage(ip: IssuerParams, m3JSON: ThirdIssuanceMessageJSON): ThirdIssuanceMessage;
export interface PresentationProofJSON {
    A?: {
        [index: number]: string;
    };
    a: string;
    r: string[];
}
export declare function encodePresentationProof(pp: PresentationProof): PresentationProofJSON;
export declare function decodePresentationProof(ip: IssuerParams, ppJSON: PresentationProofJSON): PresentationProof;
export declare function encodeUIDT(UIDT: Uint8Array): string;
export declare function decodeUIDT(UIDT: string): Uint8Array;
export interface TokenPresentation {
    upt?: UProveTokenJSON;
    uidt?: string;
    pp: PresentationProofJSON;
}
