// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// config settings for the sample

// issuer settings
export const ISSUER_PORT: string =  "8080";
export const ISSUER_URL: string = "http://localhost:8080";
export const ISSUANCE_SUFFIX: string = "/issue";
export const JWKS_SUFFIX: string = "/.well-known/jwks.json";

// verifier settings
export const VERIFIER_PORT: string = "8081";
export const VERIFIER_URL: string = "http://localhost:8081";
export const PRESENTATION_SUFFIX: string = "/verify";
