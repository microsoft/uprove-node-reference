// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { Command } from 'commander';
import * as UPJF from '../../../src/upjf.js';
import { ECGroup } from '../../../src/uprove.js';
import * as jose from 'jose'; // TODO: do away with jose dependency
import fs from 'fs';
import settings from './settings.json' assert {type: "json"};
import process from 'process';


interface Options {
    curve: string;
    jwksPath: string;
    privatePath: string;
}

// process options
const program = new Command();
program.option('-k, --jwksPath <jwksPath>', "path to the JWKS file to add the issuer parameters; create it if doesn't exist", "public" + settings.IP_SUFFIX);
program.option('-p, --privatePath <privatePath>', "path to the output private key file", "private/ip.key");
program.option('-c, --curve <curve>', "recommended curve to use", "P256");
//program.addOption(new Option('-c, --curve <curve>', 'recommended curve to use').choices(['P256', 'P384', 'P521']).default('P256')); TODO: choices not supported?
program.parse(process.argv);
const options = program.opts() as Options;

void (async () => {
    try {
        let jwks: jose.JSONWebKeySet | undefined;
        let jwksUpdate = false;
        if (fs.existsSync(options.jwksPath)) {
            // read the JWKS file to update
            const jwksBytes = fs.readFileSync(options.jwksPath, 'utf8');
            jwks = JSON.parse(jwksBytes) as jose.JSONWebKeySet;
            jwksUpdate = true;
        } else {
            // create a new JWKS
            jwks = { keys: [] };
        }

        const descGq = ECGroup.P256 // TODO: use the curve option
        const ikp = UPJF.createIssuerKeyAndParamsUPJF(descGq, { n: 0 }, undefined);
        const jwk = UPJF.encodeIPAsJWK(ikp.ip);

        // write out updated JWKS        
        jwks.keys.push(jwk as unknown as jose.JWK);
        fs.writeFileSync(options.jwksPath, JSON.stringify(jwks, null, 4));
        console.log(`Public JWKS ${jwksUpdate ? 'added' : 'written'} to ${options.jwksPath}`);

        // write out private key
        fs.writeFileSync(options.privatePath, UPJF.encodePrivateKeyAsBase64Url(ikp.y0));
        console.log(`Private key written to ${options.privatePath}`);

    } catch (err) {
        console.log(err);
    }
})();