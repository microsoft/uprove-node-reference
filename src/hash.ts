// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// implements the U-Prove hash formatting
import { GroupElement, FieldZqElement } from './math.js';
import { ECGroup } from './uprove.js';
import { webcrypto as crypto } from 'crypto';

export const groupToHash = (g: ECGroup) => {
    switch (g) {
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

export type HashInput = Byte | null | number | Uint8Array | GroupElement | FieldZqElement | ECGroup;

// c.f. spec section 2.2
export class Hash {
    private hash = new Uint8Array(0);
    private descGq: ECGroup;

    constructor(descGq: ECGroup) {
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
        const temp = new Uint8Array(this.hash.length + data.length);
        temp.set(this.hash);
        temp.set(data, this.hash.length);
        this.hash = temp;
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

    async digest(data: HashInput | HashInput[] | undefined = undefined): Promise<Uint8Array> {
        if (data || data === null) {
            this.update(data);
        }

        return crypto.subtle.digest({ name: groupToHash(this.descGq).replace('sha', 'sha-') }, this.hash)
            .then(arrayBuffer => {
                return new Uint8Array(arrayBuffer);
            })
    }
}