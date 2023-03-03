// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

export function hexToBytes (hex: string): Uint8Array {
    if (hex.startsWith('0x')) {
        hex = hex.substring(2, hex.length);
    } 
    if (hex.length % 2 == 1) {
        // odd-length string, prepend 0
        hex = '0' + hex;
    }
    return new Uint8Array(Buffer.from(hex, 'hex'));
}

export function bytesToHex (bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('hex');
}

export function checkUnsignedInt(n: number | number[]) {
    if (!Array.isArray(n)) {
        n = [n];
    }
    n.forEach(n => {
        if (!Number.isInteger(n) || n < 0) {
            throw `invalid integer ${n}`;
        }    
    })
}

export function arrayEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a === b) return true;
    if (a == null || b == null) return false;
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; ++i) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}