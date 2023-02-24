// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import settings from './settings.json';// assert {type: "json"};
import * as UPJF from '../../../src/upjf.js';
import * as uprove from '../../../src/uprove.js';
import * as serialization from '../../../src/serialization.js';
import got from 'got';

void (async () => {
    try {
        // fetch the Issuer parameters
        const ip = await got(settings.ISSUER_URL + settings.IP_SUFFIX).json();
        console.log(ip);
    } catch (err) {
        console.log(err);
    }
})();