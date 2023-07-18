import { Byte } from './hash.js';
import { GroupElement, Group, FieldZqElement } from './math.js';
export declare enum ECGroup {
    P256 = "P-256",
    P384 = "P-384",
    P521 = "P-521"
}
/**
 * IssuerParams
 *
 * @export
 * @class IssuerParams
 */
export declare class IssuerParams {
    UIDP: Uint8Array;
    descGq: ECGroup;
    UIDH: string;
    g: GroupElement[];
    e: Byte[];
    S: Uint8Array;
    Gq: Group;
    P: Uint8Array;
    /**
     * Private constructor that Creates an instance of IssuerParams.
     * Use IssuerParams.create() factory to create a new IssuerParams instance.
     * @param {Uint8Array} UIDP
     * @param {ECGroup} descGq
     * @param {string} UIDH
     * @param {GroupElement[]} g
     * @param {Byte[]} e
     * @param {Uint8Array} S
     * @param {Group} Gq
     * @param {Uint8Array} P
     * @memberof IssuerParams
     * @private
     * @constructor
     */
    private constructor();
    /**
     * Static factory method to create a new instance of IssuerParams
     *
     * @example ```
     * const params = await IssuerParams(...)
     * ```
     * @param {Uint8Array} UIDP
     * @param {ECGroup} descGq
     * @param {string} UIDH
     * @param {GroupElement[]} g
     * @param {Byte[]} e
     * @param {Uint8Array} S
     * @return {*}  {Promise<IssuerParams>}
     * @memberof IssuerParams
     * @public
     * @static
     * @async
    */
    static create(UIDP: Uint8Array, descGq: ECGroup, UIDH: string, g: GroupElement[], e: Byte[], S: Uint8Array): Promise<IssuerParams>;
    verify(): void;
}
export interface IssuerKeyPair {
    y0: Uint8Array;
    g0: Uint8Array;
}
export declare function createIssuerKeyAndParams(descGq: ECGroup, n: number, e?: Byte[] | undefined, S?: Uint8Array, issKeyPair?: IssuerKeyPair | undefined, UIDP?: Uint8Array | undefined): Promise<IssuerKeyAndParams>;
export interface IssuerKeyAndParams {
    ip: IssuerParams;
    y0: FieldZqElement;
}
export interface UProveToken {
    UIDP: Uint8Array;
    h: GroupElement;
    TI: Uint8Array;
    PI: Uint8Array;
    sZp: GroupElement;
    sCp: FieldZqElement;
    sRp: FieldZqElement;
}
export interface UProveKeyAndToken {
    upt: UProveToken;
    alphaInverse: FieldZqElement;
}
export declare function computeXt(ip: IssuerParams, TI: Uint8Array): Promise<FieldZqElement>;
export declare function computeXi(i: number, ip: IssuerParams, Ai: Uint8Array): Promise<FieldZqElement>;
export declare function verifyTokenSignature(ip: IssuerParams, upt: UProveToken): Promise<void>;
export interface FirstIssuanceMessage {
    sZ: GroupElement;
    sA: GroupElement[];
    sB: GroupElement[];
}
export interface SecondIssuanceMessage {
    sC: FieldZqElement[];
}
export interface ThirdIssuanceMessage {
    sR: FieldZqElement[];
}
export declare class IssuanceParticipant {
    protected n: number;
    constructor(n: number);
    protected computeGamma(A: Uint8Array[], ip: IssuerParams, TI: Uint8Array): Promise<GroupElement>;
}
export declare class Prover extends IssuanceParticipant {
    private ip;
    private alpha;
    private beta1;
    private beta2;
    private h;
    private t1;
    private t2;
    private TI;
    private PI;
    private sigmaZPrime;
    private sigmaAPrime;
    private sigmaBPrime;
    private sigmaCPrime;
    private constructor();
    /**
     * Static Factory for creating instances of Prover
     *
     * @static
     * @param {IssuerParams} ip
     * @param {Uint8Array[]} A
     * @param {Uint8Array} TI
     * @param {Uint8Array} PI
     * @param {number} n
     * @return {*}  {Promise<Prover>}
     * @memberof Prover
     */
    static create(ip: IssuerParams, A: Uint8Array[], TI: Uint8Array, PI: Uint8Array, n: number): Promise<Prover>;
    createSecondMessage(msg1: FirstIssuanceMessage): Promise<SecondIssuanceMessage>;
    createTokens(msg3: ThirdIssuanceMessage, skipValidation?: boolean): UProveKeyAndToken[];
}
export declare class Issuer extends IssuanceParticipant {
    private ikp;
    private Gq;
    private y0;
    private w;
    private gamma;
    private sigmaZ;
    private sigmaA;
    private sigmaB;
    private constructor();
    static create(ikp: IssuerKeyAndParams, A: Uint8Array[], TI: Uint8Array, n: number): Promise<Issuer>;
    createFirstMessage(): FirstIssuanceMessage;
    createThirdMessage(msg2: SecondIssuanceMessage): ThirdIssuanceMessage;
}
export interface PresentationProof {
    A?: {
        [index: number]: Uint8Array;
    };
    a: Uint8Array;
    r: FieldZqElement[];
}
export interface PresentationProofData {
    UIDT: Uint8Array;
    pp: PresentationProof;
}
export declare function generatePresentationProof(ip: IssuerParams, D: number[], upkt: UProveKeyAndToken, m: Uint8Array, A: Uint8Array[], md?: Uint8Array): Promise<PresentationProofData>;
export interface VerificationData {
    UIDT: Uint8Array;
}
export declare function verifyPresentationProof(ip: IssuerParams, upt: UProveToken, m: Uint8Array, pp: PresentationProof, md?: Uint8Array): Promise<VerificationData>;
