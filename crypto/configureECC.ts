import fs from "fs";

// the javascript crypto library has several files that are all concatenated into a single library file
// there are no imports/exports on these files. They just assume the resources they need are globally
// available within the monolithic script.
// Since we are trying to use just one file (cryptoECC.js) we need to append to its dependencies

// read the files into variables - we'll append them into a single file
const msrCryptoPath = "./node_modules/@microsoft/msrcrypto";
const global = fs.readFileSync(`${msrCryptoPath}/scripts/global.js`);
const math = fs.readFileSync(`${msrCryptoPath}/scripts/cryptoMath.js`);
const ecc = fs.readFileSync(`${msrCryptoPath}/scripts/cryptoECC.js`);
const nistCurves = fs.readFileSync(`${msrCryptoPath}/scripts/curves_NIST.js`);
const destinationPath = `${msrCryptoPath}/scripts/cryptoECCLib.js`;

// append the global.js | cryptoMath.js | cryptoECC | curves_NIST.js into a single file
// as they depend on each other.
fs.rmSync(destinationPath, {force: true});
fs.writeFileSync(destinationPath, global);
fs.appendFileSync(destinationPath, math);
fs.appendFileSync(destinationPath, ecc);
fs.appendFileSync(destinationPath, nistCurves);

// to allow this new file to be imported we append a commonjs exports to the end of this new .js file
// we use commonjs instead of modern esm because the javascript crypto library package.json does
// not include the "type": "module" property and so it's "commonjs" by default
// your tsconfig file will require the "allowSyntheticDefaultImports" and "esModuleInterop" to be true
// to import commonjs.
fs.appendFileSync(destinationPath, "\nmodule.exports.cryptoECC = cryptoECC;");
fs.appendFileSync(destinationPath, "\nmodule.exports.cryptoMath = cryptoMath;");

// copy the d.ts file into the ./node_modules/@microsoft/msrcrypto/scripts folder
// this lets TypeScript know the what's in the file and its type signatures
fs.copyFileSync("./crypto/cryptoECCLib.d.ts", `${msrCryptoPath}/scripts/cryptoECCLib.d.ts`);
