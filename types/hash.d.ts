import { GroupElement, FieldZqElement } from './math.js';
import { ECGroup } from './uprove.js';
export declare const groupToHash: (g: ECGroup) => "sha256" | "sha384" | "sha512";
export declare class Byte {
    b: Uint8Array;
    constructor(b: number);
}
export type HashInput = Byte | null | number | Uint8Array | GroupElement | FieldZqElement | ECGroup;
export declare class Hash {
    private hash;
    private descGq;
    constructor(descGq: ECGroup);
    private getIntArray;
    updateInternal(data: Uint8Array): void;
    update(data: HashInput | HashInput[]): void;
    digest(data?: HashInput | HashInput[] | undefined): Promise<Uint8Array>;
}
