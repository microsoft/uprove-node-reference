// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { getEcGroup } from './ecparams.js';
import { Byte, groupToHash, Hash } from './hash.js';
import { GroupElement, Group, FieldZqElement } from './math.js';
import { arrayEqual, checkUnsignedInt } from './utils.js';

export enum ECGroup {
    P256 = "P-256", //"1.3.6.1.4.1.311.75.1.2.1",
    P384 = "P-384", //"1.3.6.1.4.1.311.75.1.2.2",
    P521 = "P-521" //"1.3.6.1.4.1.311.75.1.2.3"
}

/**
 * IssuerParams
 *
 * @export
 * @class IssuerParams
 */
export class IssuerParams {

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
    private constructor(
        public UIDP: Uint8Array,
        public descGq: ECGroup,
        public UIDH: string,
        public g: GroupElement[],
        public e: Byte[],
        public S: Uint8Array,
        public Gq: Group,
        public P: Uint8Array
    ) { }

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
    public static async create(UIDP: Uint8Array, descGq: ECGroup, UIDH: string, g: GroupElement[], e: Byte[], S: Uint8Array): Promise<IssuerParams> {
        const Gq = new Group(descGq);
        const hash = Gq.getHash();
        hash.update(UIDP);
        Gq.updateHash(hash);
        hash.update(g);
        hash.update(e);
        hash.update(S);
        const P = await hash.digest()
        return new IssuerParams(UIDP, descGq, UIDH, g, e, S, Gq, P);
    }

    // c.f. spec section 2.3.1
    public verify() {
        // no need to verify Gq and the generators, since only the recommended ones are supported

        // verify g0
        if (this.g[0].equals(this.Gq.getIdentity()) ||
            !this.Gq.isValid(this.g[0])) {
            throw 'invalid g0';
        }
    }
}

export interface IssuerKeyPair {
    y0: Uint8Array,
    g0: Uint8Array
}

// Create Issuer parameters. If UIDP is empty, it will be set to the hash of the other variables
// c.f. spec section 2.3.1
export async function createIssuerKeyAndParams(descGq: ECGroup, n: number, e: Byte[] | undefined = undefined, S: Uint8Array = new Uint8Array(), issKeyPair?: IssuerKeyPair | undefined, UIDP?: Uint8Array | undefined): Promise<IssuerKeyAndParams> {
    if (n < 0 || n > 50) {
        throw "n must be between 0 and 50";
    }
    if (!e) {
        e = new Array(n).fill(new Byte(1));
    }
    if (e.length != n) {
        throw "wrong length for e: " + e.length;
    }
    const groupParams = getEcGroup(descGq);
    const Gq = groupParams.Gq;
    const Zq = Gq.Zq;

    // generate the Issuer key pair
    let y0: FieldZqElement;
    let g0: GroupElement;
    if (issKeyPair == undefined) {
        y0 = Zq.getRandomElement(true);
        g0 = groupParams.Gq.modExp(Gq.g, y0);
    } else {
        y0 = Zq.getElement(issKeyPair.y0);
        g0 = Gq.getElement(issKeyPair.g0);
    }

    // g = [g0, g1, ... gn, gt]
    const g = groupParams.g.slice(0, n); // keep only n generators
    g.unshift(g0);
    g.push(groupParams.gt);

    if (!UIDP) {
        // UIDP not define, let's set it to the hash of the other fields
        const hash = new Hash(descGq);
        hash.update(g);
        hash.update(e);
        hash.update(S);
        UIDP = await hash.digest();
    }

    return {
        ip: await IssuerParams.create(UIDP, descGq, groupToHash(descGq), g, e, S),
        y0: y0
    }
}

export interface IssuerKeyAndParams {
    ip: IssuerParams,
    y0: FieldZqElement // private key
}

export interface UProveToken {
    UIDP: Uint8Array,
    h: GroupElement,
    TI: Uint8Array,
    PI: Uint8Array,
    sZp: GroupElement,
    sCp: FieldZqElement,
    sRp: FieldZqElement
}

export interface UProveKeyAndToken {
    upt: UProveToken,
    alphaInverse: FieldZqElement
}

// c.f. spec section 2.3.5
export async function computeXt(ip: IssuerParams, TI: Uint8Array): Promise<FieldZqElement> {
    const H = ip.Gq.getHash();
    H.update(new Byte(1));
    // const p = await ip.P;
    H.update(ip.P);
    H.update(TI);
    return ip.Gq.Zq.getElement(await H.digest());
}

// c.f. spec section 2.3.5
export async function computeXi(i: number, ip: IssuerParams, Ai: Uint8Array): Promise<FieldZqElement> {
    const e_i = ip.e[i - 1].b[0]; // e_i is 0-based
    if (e_i === 1) {
        const H = ip.Gq.getHash();
        return ip.Gq.Zq.getElement(await H.digest(Ai));
    } else if (e_i === 0) {
        // verify that 0 <= A < q
        const x = ip.Gq.Zq.getElement(Ai);
        return x;
    } else {
        throw `invalid e[i] index: ${i}`;
    }
}

// c.f. spec section 2.3.6
export async function verifyTokenSignature(ip: IssuerParams, upt: UProveToken) {
    const Gq = ip.Gq;
    const Zq = Gq.Zq;
    if (upt.h.equals(Gq.getIdentity())) {
        throw `invalid token`;
    }
    const H = Gq.getHash();
    H.update(upt.h);
    H.update(upt.PI);
    H.update(upt.sZp);

    const exponents = [upt.sRp, Zq.negate(upt.sCp)];
    H.update(Gq.multiModExp([Gq.g, ip.g[0]], exponents));
    H.update(Gq.multiModExp([upt.h, upt.sZp], exponents));
    const value = Zq.getElement(await H.digest());
    if (!upt.sCp.equals(value)) {
        throw `invalid token`;
    }
}

// c.f. spec section 2.3.7
async function computeTokenId(Gq: Group, upt: UProveToken): Promise<Uint8Array> {
    const H = Gq.getHash();
    H.update(upt.h);
    H.update(upt.sZp);
    H.update(upt.sCp);
    H.update(upt.sRp);
    return await H.digest();
}

interface ChallengeData {
    UIDT: Uint8Array,
    c: FieldZqElement
}

async function computePresentationChallenge(Gq: Group, upt: UProveToken, a: Uint8Array, D: number[], xInD: FieldZqElement[], m: Uint8Array, md: Uint8Array): Promise<ChallengeData> {
    const UIDT = await computeTokenId(Gq, upt);
    let H = Gq.getHash();
    H.update(UIDT);
    H.update(a);
    H.update(D);
    H.update(xInD);
    H.update([]); // <C>
    H.update([]); // {cTilda in C}
    H.update([]); // {aTilda in C}
    H.update(0); // p
    H.update(null); // ap
    H.update(null); // Ps
    H.update(m);
    const cp = await H.digest();
    H = Gq.getHash();
    H.update([cp, md]);
    return {
        UIDT: UIDT,
        c: Gq.Zq.getElement(await H.digest())
    }
}

// Issuance messages
export interface FirstIssuanceMessage {
    sZ: GroupElement,
    sA: GroupElement[],
    sB: GroupElement[]
}

export interface SecondIssuanceMessage {
    sC: FieldZqElement[]
}

export interface ThirdIssuanceMessage {
    sR: FieldZqElement[]
}

export class IssuanceParticipant {
    protected n: number;
    constructor(n: number) {
        checkUnsignedInt(n);
        this.n = n;
    }

    protected async computeGamma(A: Uint8Array[], ip: IssuerParams, TI: Uint8Array): Promise<GroupElement> {
        const Gq = ip.Gq;
        const x = await Promise.all(A.map(async (a, i) => computeXi(i + 1, ip, a)));
        x.unshift(Gq.Zq.ONE);
        const xt = await computeXt(ip, TI);
        x.push(xt);
        const gamma = Gq.multiModExp(ip.g, x);
        return gamma;
    }
}

export class Prover extends IssuanceParticipant {
    private ip: IssuerParams;
    private alpha: FieldZqElement[];
    private beta1: FieldZqElement[];
    private beta2: FieldZqElement[];
    private h: GroupElement[] = [];
    private t1: GroupElement[] = [];
    private t2: GroupElement[] = [];
    private TI: Uint8Array;
    private PI: Uint8Array;
    private sigmaZPrime: GroupElement[] = [];
    private sigmaAPrime: GroupElement[] = [];
    private sigmaBPrime: GroupElement[] = [];
    private sigmaCPrime: FieldZqElement[] = [];

    private constructor(ip: IssuerParams, TI: Uint8Array, PI: Uint8Array, n: number) {
        super(n);
        this.ip = ip;
        const Gq = ip.Gq;
        const Zq = Gq.Zq;
        this.TI = TI;
        this.PI = PI;
        // pre-computation (NOTE: could move this out to its own function)
        this.alpha = Zq.getRandomElements(n, true);
        this.beta1 = Zq.getRandomElements(n);
        this.beta2 = Zq.getRandomElements(n);
    }

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
    public static async create(ip: IssuerParams, A: Uint8Array[], TI: Uint8Array, PI: Uint8Array, n: number): Promise<Prover> {
        const prover = new Prover(ip, TI, PI, n);
        const gamma = await prover.computeGamma(A, ip, TI);
        const Gq = prover.ip.Gq;
        const t1Base = [ip.g[0], Gq.g];
        for (let i = 0; i < n; i++) {
            prover.h.push(Gq.modExp(gamma, prover.alpha[i]));
            prover.t1.push(Gq.multiModExp(t1Base, [prover.beta1[i], prover.beta2[i]]));
            prover.t2.push(Gq.modExp(prover.h[i], prover.beta2[i]));
        }
        return prover;
    }

    public async createSecondMessage(msg1: FirstIssuanceMessage): Promise<SecondIssuanceMessage> {
        // second message
        if (this.n != msg1.sA.length ||
            this.n != msg1.sB.length) {
            throw `invalid first message`;
        }
        const sigmaC: FieldZqElement[] = [];
        const Gq = this.ip.Gq;
        const Zq = Gq.Zq;
        for (let i=0; i<this.n; i++) {
            this.sigmaZPrime.push(Gq.modExp(msg1.sZ, this.alpha[i]));
            this.sigmaAPrime.push(Gq.mul(this.t1[i], msg1.sA[i]));
            this.sigmaBPrime.push(Gq.multiModExp([this.sigmaZPrime[i], this.t2[i], msg1.sB[i]],[this.beta1[i], Zq.ONE, this.alpha[i]]));
            const H = Gq.getHash();
            H.update(this.h[i]);
            H.update(this.PI);
            H.update(this.sigmaZPrime[i]);
            H.update(this.sigmaAPrime[i]);
            H.update(this.sigmaBPrime[i]);
            this.sigmaCPrime.push(Zq.getElement(await H.digest()));
            sigmaC.push(Zq.add(this.sigmaCPrime[i], this.beta1[i]));
        }

        return {sC: sigmaC};
    }

    public createTokens(msg3: ThirdIssuanceMessage, skipValidation = false): UProveKeyAndToken[] {
        // U-Prove token generation
        if (this.n != msg3.sR.length) {
            throw `invalid third message`;
        }
        const Gq = this.ip.Gq;
        const Zq = Gq.Zq;
        const uptk: UProveKeyAndToken[] = [];
        for (let i=0; i<this.n; i++) {
            const sigmaRPrime = Zq.add(msg3.sR[i], this.beta2[i]);
            if (!skipValidation) {
                const lhs = Gq.mul(this.sigmaAPrime[i], this.sigmaBPrime[i]);
                const rhs = Gq.multiModExp(
                    [Gq.mul(Gq.g, this.h[i]),  Gq.mul(this.ip.g[0], this.sigmaZPrime[i])],
                    [sigmaRPrime, Zq.negate(this.sigmaCPrime[i])]);
                if (!lhs.equals(rhs)) {
                    throw `invalid token ${i}`;
                }
            }
            uptk.push({
                upt: {
                    UIDP: this.ip.UIDP,
                    h: this.h[i],
                    TI: this.TI,
                    PI: this.PI,
                    sZp: this.sigmaZPrime[i],
                    sCp: this.sigmaCPrime[i],
                    sRp: sigmaRPrime
                },
                alphaInverse: Zq.invert(this.alpha[i])
            })
        }

        return uptk;
    }
}

export class Issuer extends IssuanceParticipant {
    private Gq: Group;
    private y0: FieldZqElement;
    private w: FieldZqElement[] = [];
    private gamma: GroupElement = {} as GroupElement;
    private sigmaZ: GroupElement = {} as GroupElement;
    private sigmaA: GroupElement[] = []
    private sigmaB: GroupElement[] = []

    private constructor(private ikp: IssuerKeyAndParams, n: number) {
        super(n);
        this.Gq = ikp.ip.Gq;
        this.y0 = ikp.y0;
    }

    public static async create(ikp: IssuerKeyAndParams, A: Uint8Array[], TI: Uint8Array, n: number): Promise<Issuer> {

        const issuer = new Issuer(ikp, n);

        const Gq = issuer.Gq;
        const Zq = Gq.Zq;

        issuer.gamma = await issuer.computeGamma(A, ikp.ip, TI);
        issuer.sigmaZ = Gq.modExp(issuer.gamma, issuer.y0);

        // pre-computation (NOTE: could move this out to its own function)
        issuer.w = Zq.getRandomElements(n);
        issuer.sigmaA = issuer.w.map(w_i => Gq.modExp(Gq.g, w_i));
        issuer.sigmaB = issuer.w.map(w_i => Gq.modExp(issuer.gamma as GroupElement, w_i));

        return issuer;
    }

    public createFirstMessage(): FirstIssuanceMessage {
        return {
            sZ: this.sigmaZ,
            sA: this.sigmaA,
            sB: this.sigmaB
        }
    }

    public createThirdMessage(msg2: SecondIssuanceMessage): ThirdIssuanceMessage {
        if (this.n != msg2.sC.length) {
            throw `invalid second message`;
        }
        const Zq = this.Gq.Zq;
        const sigmaR = this.w.map((w_i, i) => 
            Zq.add(Zq.mul(msg2.sC[i], this.y0), w_i)
        );
        return {
            sR: sigmaR
        };
    }
}

export interface PresentationProof {
    A?: {
        [index: number]: Uint8Array;
    }
    a: Uint8Array,
    r: FieldZqElement[]
}

export interface PresentationProofData {
    UIDT: Uint8Array,
    pp: PresentationProof
}

function sanitizeD(D: number[]): number[] {
    checkUnsignedInt(D);
    const SetD = new Set<number>(D);
    D = Array.from(SetD).sort((a, b) => a - b);
    return D;
}

export async function generatePresentationProof(ip: IssuerParams, D: number[], upkt: UProveKeyAndToken, m: Uint8Array, A: Uint8Array[], md: Uint8Array = new Uint8Array()): Promise<PresentationProofData> {
    const n = A.length;
    D = sanitizeD(D);
    const USet = new Set<number>(Array.from({ length: n }, (e, i) => i + 1));
    D.forEach(v => USet.delete(v));
    const U: number[] = Array.from(USet).sort((a, b) => a - b);

    const Gq = ip.Gq;
    const Zq = Gq.Zq;
    const x = await Promise.all(A.map((a, i) => computeXi(i + 1, ip, a)));
    const w0 = Zq.getRandomElement();
    const w = Zq.getRandomElements(n - D.length);

    const H = Gq.getHash();
    const a = await H.digest(Gq.multiModExp(
        [upkt.upt.h, ...ip.g.slice(1, n + 1).filter((g, i) => U.includes(i + 1))],
        [w0, ...w]));

    const challengeData = await computePresentationChallenge(Gq, upkt.upt, a, D, x.filter((x, i) => D.includes(i + 1)), m, md);
    const negC = Zq.negate(challengeData.c); a

    const r = [Zq.add(Zq.mul(challengeData.c, upkt.alphaInverse), w0)]
    for (let i = 0; i < U.length; i++) {
        r.push(Zq.add(Zq.mul(negC, x[U[i] - 1]), w[i]));
    }

    const disclosedA: { [key: number]: Uint8Array } = {};
    for (const d of D) {
        disclosedA[d] = A[d - 1];
    }
    return {
        UIDT: challengeData.UIDT,
        pp: {
            A: disclosedA,
            a: a,
            r: r
        }
    }
}

export interface VerificationData {
    UIDT: Uint8Array
}

export async function verifyPresentationProof(ip: IssuerParams, upt: UProveToken, m: Uint8Array, pp: PresentationProof, md: Uint8Array = new Uint8Array()): Promise<VerificationData> {
    const Gq = ip.Gq;
    const Zq = Gq.Zq;

    // U-Prove token verification
    verifyTokenSignature(ip, upt);

    // presentation proof verification
    const xt = await computeXt(ip, upt.TI);
    let D: number[] = [];
    let x: FieldZqElement[] = [];
    const px: Promise<FieldZqElement>[] = [];
    if (pp.A) {
        Object.entries(pp.A).forEach(([iStr, Ai]) => {
            const i = Number(iStr);
            D.push(i);
            px.push(computeXi(i, ip, Ai));
        });
        x = await Promise.all(px);
        // sort the values in case they were out of order in pp.A
        D = D.sort((a, b) => a - b);
        x = D.map(i => x[D.indexOf(i)]);
    }
    const challengeData = await computePresentationChallenge(Gq, upt, pp.a, D, x, m, md);
    const t = ip.g.length - 1;
    const base0 = Gq.multiModExp(
        [ip.g[0], ...ip.g.filter((g, i) => D.includes(i)), ip.g[t]],
        [Zq.ONE, ...x, xt]);
    const hashInput = Gq.multiModExp(
        [base0, upt.h, ...ip.g.slice(1, t).filter((g, i) => !D.includes(i + 1))],
        [Zq.negate(challengeData.c), pp.r[0], ...pp.r.slice(1)]
    )
    if (!arrayEqual(pp.a, await Gq.getHash().digest(hashInput))) {
        throw `invalid presentation proof`;
    }
    return {
        UIDT: challengeData.UIDT
    }
}