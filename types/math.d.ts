import { Digits, EllipticCurvePointFp } from "@microsoft/msrcrypto/scripts/cryptoECC.js";
import { IntegerGroupElement } from "@microsoft/msrcrypto/scripts/cryptoMath.js";
import "@microsoft/msrcrypto/scripts/curves_NIST.js";
import { ECGroup } from "./uprove.js";
import { Hash } from "./hash.js";
export declare class FieldZqElement {
    scalar: IntegerGroupElement;
    constructor(scalar: IntegerGroupElement);
    getBytes(): Uint8Array;
    equals(e: FieldZqElement): boolean;
}
export declare class FieldZq {
    ZERO: FieldZqElement;
    ONE: FieldZqElement;
    private Zq;
    private q;
    private elementLength;
    constructor(q: Digits);
    getElement(encoded: Uint8Array): FieldZqElement;
    getRandomElement(nonZero?: boolean): FieldZqElement;
    getRandomElements(n: number, nonZero?: boolean): FieldZqElement[];
    add(a: FieldZqElement, b: FieldZqElement): FieldZqElement;
    mul(a: FieldZqElement, b: FieldZqElement): FieldZqElement;
    negate(a: FieldZqElement): FieldZqElement;
    invert(a: FieldZqElement): FieldZqElement;
}
export declare class GroupElement {
    point: EllipticCurvePointFp;
    constructor(point: EllipticCurvePointFp);
    getBytes(): Uint8Array;
    equals(e: GroupElement): boolean;
}
export declare class Group {
    private curve;
    private descGq;
    Zq: FieldZq;
    g: GroupElement;
    private ecOperator;
    constructor(descGq: ECGroup);
    getHash(): Hash;
    updateHash(H: Hash): void;
    parsePoint(x: Digits, y: Digits): GroupElement;
    getElement(encoded: Uint8Array): GroupElement;
    getIdentity(): GroupElement;
    mul(a: GroupElement, b: GroupElement): GroupElement;
    modExp(g: GroupElement, e: FieldZqElement): GroupElement;
    multiModExp(g: GroupElement[], e: FieldZqElement[]): GroupElement;
    isValid(g: GroupElement): boolean;
}
