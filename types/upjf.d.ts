import { FieldZqElement } from "./math.js";
import { TokenPresentation } from "./serialization.js";
import { ECGroup, IssuerKeyAndParams, IssuerKeyPair, IssuerParams } from "./uprove.js";
export declare enum ExpirationType {
    sec = "sec",
    hour = "hour",
    day = "day",
    week = "week",
    year = "year"
}
export declare function msToTypedTime(type: ExpirationType, t: number): number;
/**
 * Gets the expiration date given an expiration type, value, and start time.
 * @param {ExpirationType} type - expiration type
 * @param {number} t - non-negative integer, number of typed units to add to epoch
 * @param {number} start - typed start time; defaults to the current time
 * @returns the expiration date, adding `t` units from the `start` time of a given `type`
 */
export declare function getExp(type: ExpirationType, t: number, start?: number | undefined): number;
/**
 * Checks if the typed target date is after the expiration
 * @param {ExpirationType} type - expiration type
 * @param {number} exp - typed expiration date
 * @param {number} target - typed target date for comparison; defaults to the current time
 * @returns `true` if the target date is expired, `false` otherwise
 */
export declare function isExpired(type: ExpirationType, exp: number, target?: number | undefined): boolean;
export interface Specification {
    n: number;
    expType: ExpirationType;
    [key: string]: unknown;
}
export declare function parseSpecification(S: Uint8Array): Specification;
export declare function createIssuerKeyAndParamsUPJF(descGq: ECGroup, specification: Specification, issKeyPair?: IssuerKeyPair | undefined): Promise<IssuerKeyAndParams>;
export declare enum UPAlg {
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
    spec: string;
}
export declare function encodePrivateKeyAsBase64Url(key: FieldZqElement): string;
export declare function decodeBase64UrlAsPrivateKey(ip: IssuerParams, b64: string): FieldZqElement;
export declare function descGqToUPAlg(descGq: ECGroup): UPAlg;
export declare function encodeIPAsJWK(ip: IssuerParams): IssuerParamsJWK;
export declare function decodeJWKAsIP(jwk: IssuerParamsJWK): Promise<IssuerParams>;
export interface TokenInformation {
    iss: string;
    exp: number;
    [key: string]: unknown;
}
export declare function parseTokenInformation(TI: Uint8Array): TokenInformation;
export declare function encodeTokenInformation(TI: TokenInformation): Uint8Array;
export interface UPJWSHeader {
    alg: UPAlg;
    [key: string]: unknown;
}
export interface UPJWS {
    header: UPJWSHeader;
    payload: Uint8Array;
    sig: TokenPresentation;
}
export declare function createJWS(alg: UPAlg, m: Uint8Array, tp: TokenPresentation): string;
export declare function parseJWS(jws: string): UPJWS;
