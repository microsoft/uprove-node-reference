// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// config settings for the sample

export const HOST = "localhost"

// issuer settings
export const ISSUER_PORT =  "9000";
export const ISSUER_URL = `http://${HOST}:${ISSUER_PORT}`;
export const ISSUANCE_SUFFIX = "/issue";
export const JWKS_SUFFIX = "/.well-known/jwks.json";

// verifier settings
export const VERIFIER_PORT = "9001";
export const VERIFIER_URL = `http://${HOST}:${VERIFIER_PORT}`;
export const PRESENTATION_SUFFIX = "/verify";
