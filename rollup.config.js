// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import commonjs from '@rollup/plugin-commonjs'
import resolve from '@rollup/plugin-node-resolve'
import replace from '@rollup/plugin-replace'
import terser from '@rollup/plugin-terser'
import typescript from 'rollup-plugin-typescript2'

const copyright = `
// @preserve Copyright (c) Microsoft Corporation.
// @preserve Licensed under the MIT license.
/* @preserve eslint-disable */`

const suppressKnownWarnings = true

export default {
    input: 'src/index.ts',
    output: {
        file: 'browser/index.js',
        format: 'umd',
        name: 'uproveNodeReference',
        sourcemap: false,
        globals: { 'crypto': 'crypto' },
        banner: copyright
    },
    external: ['crypto'],
    plugins: [
        // tells Rollup how to find dependencies in node_modules
        resolve(),
        // converts commonjs modules to ES modules
        commonjs(),
        // converts TypeScript to JavaScript
        typescript({
           tsconfig: './tsconfig.npm.json', // Specify the path to your tsconfig.json
           useTsconfigDeclarationDir: true, // use the declarations outputted to the declarationDir in tsconfig.json
        }),
        // replace Node's webCrypto api references (crypto.webcrypto) to the global browser crypto object (crypto)
        replace({ "crypto.webcrypto.": 'crypto.', preventAssignment: true }),
        // minifies the output for smaller bundle size
        terser(),
        // remove the @preserve comments from the output, @preserve is required to prevent terser from removing the license
        // the 'delimiters' is required because replace() only replaces on word-boundaries and @ apparently isn't a word-boundary
        replace({ "@preserve ": '', delimiters: ['', ''], preventAssignment: true }),
    ],
    onwarn(warning, warn) {
        if (suppressKnownWarnings && (
            // we know there are circular dependencies in the code
            warning.code === 'CIRCULAR_DEPENDENCY' ||
            // this is a warning about the node crypto not being included in the bundle
            warning.code === 'MISSING_NODE_BUILTINS'
        )) return
        warn(warning)
    }
};
