// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import {Byte, groupToHash, Hash} from '../src/hash.js';
import testvectors from '../doc/testvectors/testvectors_hashing.json' assert {type: "json"};
import { ECGroup } from '../src/uprove.js';
import * as utils from '../src/utils.js';
import { Group } from '../src/math.js';

test("Check hash alg from P256 group", async () => {
    expect(testvectors.UIDh).toBe(groupToHash(ECGroup.P256));
});

test("Check hash API", async () => {
    let hash;
    const input1 = utils.stringToBytes("foo");
    const input2 = utils.stringToBytes("bar");
    
    hash = new Hash(ECGroup.P256);
    hash.update(input1);
    hash.update(input2);
    const digest1 = await hash.digest();
    
    hash = new Hash(ECGroup.P256);
    hash.update(input1);
    const digest2 = await hash.digest(input2);

    expect(utils.bytesToHex(digest1)).toBe(utils.bytesToHex(digest2));
});

const byteInput = new Byte(utils.hexToBytes(testvectors.hash_byte_input)[0]);
test("Hash byte", async () => {
    const hash = new Hash(ECGroup.P256);
    const digest = await hash.digest(byteInput);
    expect(utils.bytesToHex(digest)).toBe(testvectors.hash_byte_digest);
});

const octetStringInput = utils.hexToBytes(testvectors.hash_octectstring_input);
test("Hash octect string", async () => {
    const hash = new Hash(ECGroup.P256);
    const digest = await hash.digest(octetStringInput);
    expect(utils.bytesToHex(digest)).toBe(testvectors.hash_octectstring_digest);
});

test("Hash null", async () => {
    const hash = new Hash(ECGroup.P256);
    const digest = await hash.digest(null);
    expect(utils.bytesToHex(digest)).toBe(testvectors.hash_null_digest);
});

test("Hash list", async () => {
    const hash = new Hash(ECGroup.P256);
    const digest = await hash.digest([ byteInput, octetStringInput, null ]);
    expect(utils.bytesToHex(digest)).toBe(testvectors.hash_list_digest);
});

test("Hash group EC (1.3.6.1.4.1.311.75.1.2.1)", async () => {
    const hash = new Hash(ECGroup.P256);
    const Gq = new Group(ECGroup.P256);
    Gq.updateHash(hash);
    const digest = await hash.digest();
    const hexDigest = utils.bytesToHex(digest);
    expect(hexDigest).toBe(testvectors.hash_group_EC_digest);
});
