declare class EllipticCurveBase {
    public p: Digits
    public a: Digits
    public order: Digits
    public gx: Digits
    public gy: Digits
    public allocatePointStorage(): EllipticCurvePointFp
    public createPointAtInfinity(): EllipticCurvePointFp
}

declare class EllipticCurveFpB extends EllipticCurveBase {
    public b: Digits
}

declare class EllipticCurveFpD extends EllipticCurveBase {
    public d: Digits
}

type EllipticCurveFp = EllipticCurveFpB | EllipticCurveFpD;

type Digit = number;
type Digits = Array<Digit>;

type Byte = number;
type Bytes = Array<Byte>;

type EncodedCurve = Array<number>;

declare class EllipticCurvePointFp {
    public curve: EllipticCurveFp;
    public isInfinity: boolean;
    public x: Digits;
    public y: Digits;
    public z: Digits;
    public isInMontgomeryForm: boolean;
    public isInfinity: boolean;
    public isAffine: boolean;
    constructor(curve: EllipticCurveFp, isInfinity: boolean, x: Digits, y: Digits, z?: Digits, isInMontgomeryForm: boolean = false)
    public equals(point: EllipticCurvePointFp): boolean
    public copyTo(source: EllipticCurvePointFp, destination: EllipticCurvePointFp): void
    public clone(): EllipticCurvePointFp
}

class WeierstrassCurve extends EllipticCurveFpB {
    public type: number
    public name: string
    public generator: EllipticCurvePointFp
}

class TedCurve extends EllipticCurveFpD {
    type: number
    name: string
    rbits: number
    generator: EllipticCurvePointFp
}

function createCurve(curveName: string): WeierstrassCurve | TedCurve
function sec1EncodingFp(): {
    encodePoint(point: EllipticCurvePointFp): EncodedCurve,
    decodePoint(encoded: EncodedCurve, curve: EllipticCurveFp)
}
function ModularSquareRootSolver(modulus: Digits): {
    squareRoot(digits: Digits): Digits,
    jacobiSymbol(digits: Digits): number
}
function EllipticCurveOperatorFp(curve: EllipticCurveFp) : {
    convertToMontgomeryForm(point : EllipticCurvePointFp) : void,
    convertToStandardForm(point : EllipticCurvePointFp) : void,
    convertToAffineForm(point : EllipticCurvePointFp) : void,
    convertToJacobianForm(point : EllipticCurvePointFp) : void,
    scalarMultiply(k : Digits, point : EllipticCurvePointFp, outputPoint : EllipticCurvePointFp, multiplyBy4? : boolean) : void,
    mixedAdd(jacobianPoint: EllipticCurvePointFp, affinePoint: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp)  : void,
    mixedDoubleAdd(jacobianPoint: EllipticCurvePointFp, affinePoint: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp) : void,
    double(point: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp) : void,
    negate(point: EllipticCurvePointFp, outputPoint: EllipticCurvePointFp) : void,
    validatePoint(point: EllipticCurvePointFp) : boolean,
}

export const cryptoECC = {
    createCurve,
    sec1EncodingFp,
    validatePoint,
    EllipticCurvePointFp,
    EllipticCurveOperatorFp,
    ModularSquareRootSolver
}

// cryptoMath ---------------------------------------------------------------------------------

interface ComputeContext {
    m: Digits,
    mPrime: number,
    m0: number,
    mu: number,
    rModM: Digits,
    rSquaredModm: Digits,
    rCubedModm: Digits,
    temp1: Digits,
    temp2: Digits
}

interface IMontgomeryMultiplier {
    m: Digits,
    mPrime: number,
    m0: number,
    mu: number,
    rModM: Digits,
    rSquaredModm: Digits,
    rCubedModm: Digits,
    temp1: temp1,
    temp2: temp2,
    one: [1],
    s: number,
    ctx: ComputeContext,
    convertToMontgomeryForm: (digits: Digits) => Digits,
    convertToStandardForm: (digits: Digits) => Digits,
    montgomeryMultiply: (multiplicand: Digits, multiplier: Digits, result: Digits, ctx?: ComputeContext) => void,
    modExp: (base: Digits, exponent: Digits, result: Digits, skipSideChannel: boolean) => Digits,
    reduce: (digits: Digits, result: Digits) => void
}

interface IIntegerGroup {
    m_modulus: Digits;
    m_digitWidth: number;
    montmul: IMontgomeryMultiplier,
    createElementFromInteger: (interger: number) => IIntegerGroupElement,
    createElementFromBytes: (bytes: Bytes) => IIntegerGroupElement,
    createModElementFromBytes: (bytes: Bytes) => IIntegerGroupElement,
    createElementFromDigits: (digits: Digits) => IIntegerGroupElement,
    equals: (group: IIntegerGroup) => boolean,
    add: (addend1: IIntegerGroupElement, addend2: IIntegerGroupElement, sum: IIntegerGroupElement) => void,
    subtract: (leftElement: IIntegerGroupElement, rightElement: IIntegerGroupElement, outputElement: IIntegerGroupElement) => void,
    multiply: (multiplicand: IIntegerGroupElement, multiplier: IIntegerGroupElement, product: IIntegerGroupElement) => IIntegerGroupElement,
    inverse: (element: IIntegerGroupElement, outputElement: IIntegerGroupElement) => void,
    modexp: (valueElement: IIntegerGroupElement, exponent: IIntegerGroupElement, outputElement: IIntegerGroupElement) => IIntegerGroupElement
}

interface IIntegerGroupElement {
    m_digits: digits,
    m_group: group,
    equals: (element: IIntegerGroupElement) => boolean
}

interface ICryptoMath {
    DIGIT_BITS: number,
    DIGIT_NUM_BYTES: number,
    DIGIT_MASK: number,
    DIGIT_BASE: number,
    DIGIT_MAX: number,
    Zero: [0],
    One: [1],
    normalizeDigitArray: (digits: Digits, length?: number, pad?: boolean) => Digits,
    bytesToDigits: (bytes: Bytes) => Digits,
    stringToDigits: (text: string) => Digits,
    digitsToString: (digits: Digits) => string,
    intToDigits: (integer: number) => Digits,
    digitsToBytes: (digits: Digits) => Bytes,
    isZero: (array: Array<Byte | Digit>) => boolean,
    isEven: (array: Array<Byte | Digit>) => boolean,
    shiftRight: (source: Digits, destination: Digits, bits: number = 1, length?: number) => Digits,
    shiftLeft: (source: Digits, destination: Digits, bits: number = 1, length?: number) => Digits,
    compareDigits: (left: Digits, right: Digits) => number,
    highestSetBit: (bytes: Bytes) => number,
    fixedWindowRecode: (digits: Digits, windowSize: number, t: number) => Digits,
    IntegerGroup: (modulus: Digits) => IIntegerGroup,
    add: (addend1: Digits, addend2: Digits, sum: Digits) => Digit,
    subtract: (minuend: Digits, subtrahend: Digits, difference: Digits) => Digit,
    multiply: (a: Digits, b: Digits | Digit, p: Digits) => Digits,
    divRem: (dividend: Digits, divisor: Digits, quotient: Digits, remainder: Digits, temp1?: Digits, temp2?: Digits) => void,
    reduce: (number: Digits, modulus: Digits, remainder: Digits, temp1?: Digits, temp2?: Digits) => Digits,
    modInv: (a: Digits, n: Digits, aInv?: Digits, pad: boolean = true) => Digits,
    modInvCT: (a: Digits, n: Digits, aInv?: Digits) => Digits,
    modExp: (base: Digits, exponent: Digits, modulus: Digits, result?: Digits) => Digits,
    modMul: (multiplicand: Digits, multiplier: Digits | Digit, modulus: Digits, product?: Digits, temp1?: Digits, temp2?: Digits) => Digits,
    MontgomeryMultiplier: (modulus: Digits, context: ComputeContext) => IMontgomeryMultiplier
}

export const cryptoMath : ICryptoMath;