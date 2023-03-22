// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// implements the U-Prove hash formatting
import * as crypto from 'crypto';
import { GroupElement, FieldZqElement } from './math.js';
import { ECGroup } from './uprove.js';

export const groupToHash = (g: ECGroup) => { 
    switch(g) {
        case ECGroup.P256: return 'sha256';
        case ECGroup.P384: return 'sha384';
        case ECGroup.P521: return 'sha512';
        default: throw 'invalid group';
    }
 };

export class Byte {
    b: Uint8Array;
    constructor(b: number) {
        if (0 < b && b > 255) throw 'invalid byte value' + b;
        this.b = new Uint8Array([b]);
    }
}

export type HashInput = Byte | null | number | Uint8Array | GroupElement | FieldZqElement | ECGroup ;

// c.f. spec section 2.2
export class Hash {
    private hash: crypto.Hash;
    private descGq: ECGroup;

    constructor(descGq: ECGroup) {
        const hashAlg = groupToHash(descGq);
        this.hash = crypto.createHash(hashAlg);
        this.descGq = descGq;
    }

    private getIntArray(n: number) {
        return new Uint8Array([
            (n >> 24),
            (n >> 16),
            (n >> 8),
            n
        ]);
    }

    updateInternal(data: Uint8Array) {
        this.hash.update(data);
    }

    update(data: HashInput | HashInput[]) {
        if (Array.isArray(data)) {
            this.update(data.length);
            data.forEach(v => this.update(v));
        } else if (data instanceof Byte) {
            this.updateInternal(data.b);
        } else if (data === null) {
            this.updateInternal(this.getIntArray(0));
        } else if (typeof data === 'number') {
            this.updateInternal(this.getIntArray(data));
        } else if (data instanceof Uint8Array) {
            this.updateInternal(this.getIntArray(data.length));
            this.updateInternal(data);
        } else if (data instanceof GroupElement) {
            this.update(data.getBytes());
        } else if (data instanceof FieldZqElement) {
            this.update(data.getBytes());
        } else {
            throw "invalid input";
        }
    }

    digest(data: HashInput | HashInput[] | undefined = undefined): Uint8Array {
        if (data || data === null) {
            this.update(data);
        }
        return this.hash.digest();
    }
}