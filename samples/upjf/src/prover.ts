// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import * as settings from './settings.json';
import * as UPJF from '../../../src/upjf';
import * as uprove from '../../../src/uprove';
import * as serialization from '../../../src/serialization';
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