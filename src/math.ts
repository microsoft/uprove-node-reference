// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import cryptoECC, { Digits, EllipticCurvePointFp, WeierstrassCurve} from "@microsoft/msrcrypto/scripts/cryptoECC.js";
import cryptoMath, { IntegerGroupElement, IntegerGroup } from "@microsoft/msrcrypto/scripts/cryptoMath.js";
import "@microsoft/msrcrypto/scripts/curves_NIST.js";
import { ECGroup } from "./uprove";
import { Hash } from "./hash";
import * as crypto from "crypto";

export class FieldZqElement {
    public scalar: IntegerGroupElement;
    constructor(scalar: IntegerGroupElement) {
        this.scalar = scalar;
    }

    getBytes(): Uint8Array {
        const bytes = cryptoMath.digitsToBytes(this.scalar.m_digits)
        return new Uint8Array(bytes);
    }

    equals(e: FieldZqElement): boolean {
        return this.scalar.equals(e.scalar);
    }
}

export class FieldZq {
    public ZERO: FieldZqElement;
    public ONE: FieldZqElement;
    private Zq: IntegerGroup;
    private q: Digits;
    private elementLength: number;
    
    constructor(q: Digits) {
        this.q = q;
        const qBytes = cryptoMath.digitsToBytes(q);
        this.elementLength = qBytes.length;
        this.Zq = new cryptoMath.IntegerGroup(qBytes);
        this.ZERO = new FieldZqElement(this.Zq.createElementFromInteger(0));
        this.ONE = new FieldZqElement(this.Zq.createElementFromInteger(1));
    }

    getElement(encoded: Uint8Array): FieldZqElement {
        let digits = cryptoMath.bytesToDigits(Array.from(encoded));
        // Check size of the new element
        let result = cryptoMath.intToDigits(0);
        while (cryptoMath.compareDigits(digits, this.q) >= 0) {
            // too big, reduce (will only call once)
            cryptoMath.subtract(digits, this.q, result); // could I replace result with digits? TODO
            digits = result;
        }
        return new FieldZqElement(this.Zq.createElementFromDigits(digits));
    }

    getRandomElement(nonZero: boolean = false): FieldZqElement {
        let done = false;
        let randZq: Digits = cryptoMath.Zero;
        while (!done) {
            const ranBytes = crypto.randomBytes(this.elementLength);
            randZq = cryptoMath.bytesToDigits(Array.from(ranBytes));
            if (cryptoMath.compareDigits(randZq, this.q) < 0) {
                done = true;
            }
            if (nonZero && cryptoMath.isZero(randZq)) {
                done = false;
            }
        }
        return new FieldZqElement(this.Zq.createElementFromDigits(randZq));
    }

    getRandomElements(n: number, nonZero: boolean = false): FieldZqElement[] {
        const r: FieldZqElement[] = [];
        for (let i=0; i<n; i++) {
            r.push(this.getRandomElement(nonZero));
        }
        return r;
    }

    add(a: FieldZqElement, b:FieldZqElement): FieldZqElement {
        let sum = this.Zq.createElementFromInteger(0);
        this.Zq.add(a.scalar, b.scalar, sum);
        return new FieldZqElement(sum);
    }

    mul(a: FieldZqElement, b:FieldZqElement): FieldZqElement {
        let product = this.Zq.createElementFromInteger(0);
        this.Zq.multiply(a.scalar, b.scalar, product);
        return new FieldZqElement(product);
    }

    negate(a: FieldZqElement): FieldZqElement {
        let minusA = this.Zq.createElementFromInteger(0);
        this.Zq.subtract(this.Zq.createElementFromInteger(0), a.scalar, minusA);
        return new FieldZqElement(minusA);
    }

    invert(a: FieldZqElement): FieldZqElement {
        let aInverse = this.Zq.createElementFromInteger(0);
        this.Zq.inverse(a.scalar, aInverse);
        return new FieldZqElement(aInverse);
    }
}

export class GroupElement {
    public point: EllipticCurvePointFp;

    constructor(point: EllipticCurvePointFp) {
        this.point = point;
    }

    getBytes(): Uint8Array {
        const encoded = cryptoECC.sec1EncodingFp().encodePoint(this.point);
        return new Uint8Array(encoded);
    }

    equals(e: GroupElement): boolean {
        return this.point.equals(e.point);
    }
};

// the underlying cryptoMath lib expects points to be on the same curve object (===)
// so we instantiate them once
enum CurveNames {P256 = "P-256", P384 = "P-384", P521 = "P-521"}
const P256Curve = cryptoECC.createCurve(CurveNames.P256) as WeierstrassCurve;
const P384Curve = cryptoECC.createCurve(CurveNames.P384) as WeierstrassCurve;
const P521Curve = cryptoECC.createCurve(CurveNames.P521) as WeierstrassCurve;

export class Group {
    private curve : WeierstrassCurve;
    private descGq;
    public Zq: FieldZq;
    public g: GroupElement; // generator
    private ecOperator;

    constructor(descGq: ECGroup) {
        if (descGq == ECGroup.P256) {
            this.curve = P256Curve;
        } else if (descGq == ECGroup.P384) {
            this.curve = P384Curve
        } else if (descGq == ECGroup.P521) {
            this.curve = P521Curve;
        } else {
            throw 'invalid group description';
        }
        this.ecOperator = cryptoECC.EllipticCurveOperatorFp(this.curve);
        this.Zq = new FieldZq(this.curve.order);
        this.g = new GroupElement(this.curve.generator);
        this.descGq = descGq;
    }

    getHash(): Hash {
        return new Hash(this.descGq);
    }

    // update a hash with this group's description (see Section 2.1)
    updateHash(H: Hash) {
        // H(p,a,b,g,q,1)
        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.p)));
        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.a)));
        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.b)));
        H.update(this.g/*new GroupElement(this.curve.generator).getBytes()*/);
        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.order)));
        H.update(new Uint8Array([1]));
    }

    parsePoint(x: Digits, y: Digits): GroupElement {
        const point = new cryptoECC.EllipticCurvePointFp(
            this.curve,
            false,
            cryptoMath.bytesToDigits(x),
            cryptoMath.bytesToDigits(y)
        );
        return new GroupElement(point);
    }

    getElement(encoded: Uint8Array): GroupElement {
        return new GroupElement(cryptoECC.sec1EncodingFp().decodePoint(Array.from(encoded), this.curve));
    }

    getIdentity(): GroupElement {
        return new GroupElement(this.curve.createPointAtInfinity());
    }

    // return a.b = point + point
    mul(a: GroupElement, b: GroupElement): GroupElement {
        const pointA = a.point;
        const pointB = (pointA === b.point) ? b.point.clone() : b.point; // a and b can't be the same

        // result must be in Jacobian, Montgomery form for the mixed add
        let temp = this.curve.allocatePointStorage();
        this.ecOperator.convertToMontgomeryForm(temp);
        this.ecOperator.convertToJacobianForm(temp);

        // "a" must be in Jacobian, Montgomery form 
        if (!pointA.isInMontgomeryForm) this.ecOperator.convertToMontgomeryForm(pointA);
        if (pointA.isAffine) this.ecOperator.convertToJacobianForm(pointA);

        // "b" must be in Affine, Montgomery form
        if (!pointB.isAffine) this.ecOperator.convertToAffineForm(pointB);
        if (!pointB.isInMontgomeryForm) this.ecOperator.convertToMontgomeryForm(pointB);

        // perform the mixed add
        this.ecOperator.mixedAdd(pointA, pointB, temp);

        // now convert everyone back to Affine, Standard form
        this.ecOperator.convertToAffineForm(pointA);
        this.ecOperator.convertToStandardForm(pointA);
        // b already in affine form
        this.ecOperator.convertToStandardForm(pointB);
        this.ecOperator.convertToAffineForm(temp);
        this.ecOperator.convertToStandardForm(temp);

        return new GroupElement(temp);
    }

    // return g^e = [scalar] point.
    modExp(g: GroupElement, e: FieldZqElement): GroupElement {
        let result = this.curve.allocatePointStorage();

        // point must be in Affine, Montgomery form
        if (!g.point.isAffine) this.ecOperator.convertToAffineForm(g.point);
        if (!g.point.isInMontgomeryForm) this.ecOperator.convertToMontgomeryForm(g.point);

        // scalar multiplication
        this.ecOperator.scalarMultiply(e.scalar.m_digits, g.point, result);

        // convert everyone back to Affine, Standard form
        if (!g.point.isAffine) this.ecOperator.convertToAffineForm(g.point);
        if (g.point.isInMontgomeryForm) this.ecOperator.convertToStandardForm(g.point);
        if (!result.isAffine) this.ecOperator.convertToAffineForm(result);
        if (result.isInMontgomeryForm) this.ecOperator.convertToStandardForm(result);
        return new GroupElement(result);
    }

    // return g[0]^e[0] ... g[n]^e[n]
    multiModExp(g: GroupElement[], e: FieldZqElement[]): GroupElement {
        if (g.length !== e.length) {
            throw `g and e length mismatch`;
        }
        let result = this.getIdentity();
        for (let i = 0; i < g.length; i++) {
            let temp = this.modExp(g[i], e[i]);
            result = this.mul(result, temp);
        }
        return result;
    }

    isValid(g: GroupElement): boolean {
        return this.ecOperator.validatePoint(g.point);
    }
}
