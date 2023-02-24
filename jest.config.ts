export default {
    testEnvironment: 'node',
    preset: 'ts-jest/presets/default-esm',
    globals: {
        'ts-jest': {
            tsconfig: 'tsconfig.json',
            useESM: true,
        },
    },
    extensionsToTreatAsEsm: ['.ts'],
    testTimeout: 15000,
};