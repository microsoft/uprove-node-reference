// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Command } from 'commander';
import * as UPJF from '../../../src/upjf.js';
import { ECGroup } from '../../../src/uprove.js';
import fs from 'fs';
import settings from './settings.json' assert {type: "json"};
import process from 'process';
import { IssuerParamsJWKS } from './io.js';


interface Options {
    curve: string;
    jwksPath: string;
    privatePath: string;
}

// process options
const program = new Command();
program.option('-k, --jwksPath <jwksPath>', "path to the output JWKS file to create", "public" + settings.JWKS_SUFFIX);
program.option('-p, --privatePath <privatePath>', "path to the output private key file", "private/ip.key");
program.option('-c, --curve <curve>', "recommended curve to use", "P256");
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        // create a new JWKS
        const jwks: IssuerParamsJWKS = { keys: [] };

        const descGq = ECGroup.P256 // TODO: use the curve option
        const ikp = UPJF.createIssuerKeyAndParamsUPJF(descGq, { n: 0, expType: UPJF.ExpirationType.year }, undefined);
        const jwk = UPJF.encodeIPAsJWK(ikp.ip);

        // write out updated JWKS        
        jwks.keys.push(jwk);
        fs.writeFileSync(options.jwksPath, JSON.stringify(jwks, null, 4));
        console.log(`Public JWKS written to ${options.jwksPath}`);

        // write out private key
        fs.writeFileSync(options.privatePath, UPJF.encodePrivateKeyAsBase64Url(ikp.y0));
        console.log(`Private key written to ${options.privatePath}`);

    } catch (err) {
        console.log(err);
    }
})();