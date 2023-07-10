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
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

export function bytesToHex (bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
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
    for (let i = 0; i < a.length; ++i) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

export function base64urlToBytes(b64: string): Uint8Array {
    return Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}

export function bytesToBase64url(a: Uint8Array): string {
    return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function stringToBytes(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

export function bytesToString(a: Uint8Array): string {
    return new TextDecoder().decode(a);
}
