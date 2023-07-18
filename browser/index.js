
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
/* eslint-disable */
(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('crypto')) :
	typeof define === 'function' && define.amd ? define(['exports', 'crypto'], factory) :
	(global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.uproveNodeReference = {}, global.crypto));
})(this, (function (exports, crypto) { 'use strict';

	function getDefaultExportFromCjs (x) {
		return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
	}

	function commonjsRequire(path) {
		throw new Error('Could not dynamically require "' + path + '". Please configure the dynamicRequireTargets or/and ignoreDynamicRequires option of @rollup/plugin-commonjs appropriately for this require call to work.');
	}

	var cryptoECC$2 = {exports: {}};

	var utilities = {exports: {}};

	var hasRequiredUtilities;

	function requireUtilities () {
		if (hasRequiredUtilities) return utilities.exports;
		hasRequiredUtilities = 1;
		(function (module, exports) {
			//*******************************************************************************
			//
			//    Copyright 2020 Microsoft
			//
			//    Licensed under the Apache License, Version 2.0 (the "License");
			//    you may not use this file except in compliance with the License.
			//    You may obtain a copy of the License at
			//
			//        http://www.apache.org/licenses/LICENSE-2.0
			//
			//    Unless required by applicable law or agreed to in writing, software
			//    distributed under the License is distributed on an "AS IS" BASIS,
			//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
			//    See the License for the specific language governing permissions and
			//    limitations under the License.
			//
			//*******************************************************************************

			// tslint:disable: no-bitwise

			var msrcryptoUtilities = (function() {

			    var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

			    var setterSupport = (function() {
			        try {
			            Object.defineProperty({}, "oncomplete", {});
			            return true;
			        } catch (ex) {
			            return false;
			        }
			    }());

			    function consoleLog(text) {
			        /// <signature>
			        ///     <summary>Logs a message to the debug console if the console is available.</summary>
			        ///     <param name="text" type="String">console message</param>
			        /// </signature>
			        // tslint:disable-next-line: no-console
			        if ("console" in self && "log" in console) { console.log(text); }
			    }

			    function toBase64(data, base64Url) {
			        /// <signature>
			        ///     <summary>Convert Array of bytes to a Base64 string.</summary>
			        ///     <param name="data" type="Array">Byte values (numbers 0-255)</param>
			        ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different
			        ///       from Base64 encoding.)</param >
			        ///     <returns type="String" />
			        /// </signature>
			        /// <signature>
			        ///     <summary>Convert Array of bytes to a Base64 string.</summary>
			        ///     <param name="data" type="Uint8Array">Byte values (numbers 0-255)</param>
			        ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different
			        ///       from Base64 encoding.)</param >
			        ///     <returns type="String" />
			        /// </signature>
			        /// <signature>
			        ///     <summary>Convert Array of bytes to a Base64 string.</summary>
			        ///     <param name="data" type="ArrayBuffer">Byte values (numbers 0-255)</param>
			        ///     <param name="base64Url" type="Boolean" optional="true">Return Base64Url encoding
			        ///       (this is different from Base64 encoding.)</param >
			        ///     <returns type="String" />
			        /// </signature>

			        var dataType = getObjectType(data);

			        if (dataType !== "Array" && dataType !== "Uint8Array" && dataType !== "ArrayBuffer") {
			            throw new Error("invalid input");
			        }

			        var output = "";
			        var input = toArray(data);

			        if (!base64Url) {
			            base64Url = false;
			        }

			        var char1, char2, char3, enc1, enc2, enc3, enc4;
			        var i;

			        for (i = 0; i < input.length; i += 3) {

			            // Get the next three chars.
			            char1 = input[i];
			            char2 = input[i + 1];
			            char3 = input[i + 2];

			            // Encode three bytes over four 6-bit values.
			            // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].
			            // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].

			            // 'enc1' = high 6-bits from char1
			            enc1 = char1 >> 2;
			            // 'enc2' = 2 low-bits of char1 + 4 high-bits of char2
			            enc2 = ((char1 & 0x3) << 4) | (char2 >> 4);
			            // 'enc3' = 4 low-bits of char2 + 2 high-bits of char3
			            enc3 = ((char2 & 0xF) << 2) | (char3 >> 6);
			            // 'enc4' = 6 low-bits of char3
			            enc4 = char3 & 0x3F;

			            // 'char2' could be 'nothing' if there is only one char left to encode
			            //   if so, set enc3 & enc4 to 64 as padding.
			            if (isNaN(char2)) {
			                enc3 = enc4 = 64;

			                // If there was only two chars to encode char3 will be 'nothing'
			                //   set enc4 to 64 as padding.
			            } else if (isNaN(char3)) {
			                enc4 = 64;
			            }

			            // Lookup the base-64 value for each encoding.
			            output = output +
			                encodingChars.charAt(enc1) +
			                encodingChars.charAt(enc2) +
			                encodingChars.charAt(enc3) +
			                encodingChars.charAt(enc4);

			        }

			        if (base64Url) {
			            return output.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
			        }

			        return output;
			    }

			    function base64ToBytes(encodedString) {
			        /// <signature>
			        ///     <summary>Converts a Base64/Base64Url string to an Array</summary>
			        ///     <param name="encodedString" type="String">A Base64/Base64Url encoded string</param>
			        ///     <returns type="Array" />
			        /// </signature>

			        // This could be encoded as base64url (different from base64)
			        encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

			        // In case the padding is missing, add some.
			        while (encodedString.length % 4 !== 0) {
			            encodedString += "=";
			        }

			        var output = [];
			        var char1, char2, char3;
			        var enc1, enc2, enc3, enc4;
			        var i;

			        // Remove any chars not in the base-64 space.
			        encodedString = encodedString.replace(/[^A-Za-z0-9\+\/\=]/g, "");

			        for (i = 0; i < encodedString.length; i += 4) {

			            // Get 4 characters from the encoded string.
			            enc1 = encodingChars.indexOf(encodedString.charAt(i));
			            enc2 = encodingChars.indexOf(encodedString.charAt(i + 1));
			            enc3 = encodingChars.indexOf(encodedString.charAt(i + 2));
			            enc4 = encodingChars.indexOf(encodedString.charAt(i + 3));

			            // Convert four 6-bit values to three 8-bit characters.
			            // [A7,A6,A5,A4,A3,A2][A1,A0, B7,B6,B5,B4][B3,B2,B1,B0, C7,C6][C5,C4,C3,C2,C1,C0].
			            // [A7,A6,A5,A4,A3,A2, A1,A0][B7,B6,B5,B4, B3,B2,B1,B0][C7,C6, C5,C4,C3,C2,C1,C0].

			            // 'char1' = all 6 bits of enc1 + 2 high-bits of enc2.
			            char1 = (enc1 << 2) | (enc2 >> 4);
			            // 'char2' = 4 low-bits of enc2 + 4 high-bits of enc3.
			            char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
			            // 'char3' = 2 low-bits of enc3 + all 6 bits of enc4.
			            char3 = ((enc3 & 3) << 6) | enc4;

			            // Convert char1 to string character and append to output
			            output.push(char1);

			            // 'enc3' could be padding
			            //   if so, 'char2' is ignored.
			            if (enc3 !== 64) {
			                output.push(char2);
			            }

			            // 'enc4' could be padding
			            //   if so, 'char3' is ignored.
			            if (enc4 !== 64) {
			                output.push(char3);
			            }

			        }

			        return output;

			    }

			    function getObjectType(object) {
			        /// <signature>
			        ///     <summary>Returns the name of an object type</summary>
			        ///     <param name="object" type="Object"></param>
			        ///     <returns type="String" />
			        /// </signature>

			        return Object.prototype.toString.call(object).slice(8, -1);
			    }

			    function bytesToHexString(bytes, separate) {
			        /// <signature>
			        ///     <summary>Converts an Array of bytes values (0-255) to a Hex string</summary>
			        ///     <param name="bytes" type="Array"/>
			        ///     <param name="separate" type="Boolean" optional="true">Inserts a separator for display purposes
			        ///       (default = false)</param >
			        ///     <returns type="String" />
			        /// </signature>

			        var result = "";
			        if (typeof separate === "undefined") {
			            separate = false;
			        }

			        for (var i = 0; i < bytes.length; i++) {

			            if (separate && (i % 4 === 0) && i !== 0) {
			                result += "-";
			            }

			            var hexval = bytes[i].toString(16).toUpperCase();
			            // Add a leading zero if needed.
			            if (hexval.length === 1) {
			                result += "0";
			            }

			            result += hexval;
			        }

			        return result;
			    }

			    function bytesToInt32(bytes, index) {
			        /// <summary>
			        /// Converts four bytes to a 32-bit int
			        /// </summary>
			        /// <param name="bytes">The bytes to convert</param>
			        /// <param name="index" optional="true">Optional starting point</param>
			        /// <returns type="Number">32-bit number</returns>
			        index = (index || 0);

			        return (bytes[index] << 24) |
			            (bytes[index + 1] << 16) |
			            (bytes[index + 2] << 8) |
			            bytes[index + 3];
			    }

			    function hexToBytesArray(hexString) {
			        /// <signature>
			        ///     <summary>Converts a Hex-String to an Array of byte values (0-255)</summary>
			        ///     <param name="hexString" type="String"/>
			        ///     <returns type="Array" />
			        /// </signature>

			        hexString = hexString.replace(/\-/g, "");

			        var result = [];
			        while (hexString.length >= 2) {
			            result.push(parseInt(hexString.substring(0, 2), 16));
			            hexString = hexString.substring(2, hexString.length);
			        }

			        return result;
			    }

			    function clone(object) {
			        /// <signature>
			        ///     <summary>Creates a shallow clone of an Object</summary>
			        ///     <param name="object" type="Object"/>
			        ///     <returns type="Object" />
			        /// </signature>

			        var newObject = {};
			        for (var propertyName in object) {
			            if (object.hasOwnProperty(propertyName)) {
			                newObject[propertyName] = object[propertyName];
			            }
			        }
			        return newObject;
			    }

			    function unpackData(base64String, arraySize, toUint32s) {
			        /// <signature>
			        ///     <summary>Unpacks Base64 encoded data into arrays of data.</summary>
			        ///     <param name="base64String" type="String">Base64 encoded data</param>
			        ///     <param name="arraySize" type="Number" optional="true">Break data into sub-arrays of a given
			        ///       length</param >
			        ///     <param name="toUint32s" type="Boolean" optional="true">Treat data as 32-bit data instead of byte
			        ///       data</param >
			        ///     <returns type="Array" />
			        /// </signature>

			        var bytes = base64ToBytes(base64String),
			            data = [],
			            i;

			        if (isNaN(arraySize)) {
			            return bytes;
			        } else {
			            for (i = 0; i < bytes.length; i += arraySize) {
			                data.push(bytes.slice(i, i + arraySize));
			            }
			        }

			        if (toUint32s) {
			            for (i = 0; i < data.length; i++) {
			                data[i] = (data[i][0] << 24) + (data[i][1] << 16) + (data[i][2] << 8) + data[i][3];
			            }
			        }

			        return data;
			    }

			    function int32ToBytes(int32) {
			        /// <signature>
			        ///     <summary>Converts a 32-bit number to an Array of 4 bytes</summary>
			        ///     <param name="int32" type="Number">32-bit number</param>
			        ///     <returns type="Array" />
			        /// </signature>
			        return [(int32 >>> 24) & 255, (int32 >>> 16) & 255, (int32 >>> 8) & 255, int32 & 255];
			    }

			    function int32ArrayToBytes(int32Array) {
			        /// <signature>
			        ///     <summary>Converts an Array 32-bit numbers to an Array bytes</summary>
			        ///     <param name="int32Array" type="Array">Array of 32-bit numbers</param>
			        ///     <returns type="Array" />
			        /// </signature>

			        var result = [];
			        for (var i = 0; i < int32Array.length; i++) {
			            result = result.concat(int32ToBytes(int32Array[i]));
			        }
			        return result;
			    }

			    function xorVectors(a, b, res) {
			        /// <signature>
			        ///     <summary>Exclusive OR (XOR) two arrays.</summary>
			        ///     <param name="a" type="Array">Input array.</param>
			        ///     <param name="b" type="Array">Input array.</param>
			        ///     <param name="c" type="Array" optional="true">Optional result array.</param>
			        ///     <returns type="Array">XOR of the two arrays. The length is minimum of the two input array lengths.
			        ///     </returns>
			        /// </signature>

			        var length = Math.min(a.length, b.length),
			            res = res || new Array(length);
			        for (var i = 0; i < length; i += 1) {
			            res[i] = a[i] ^ b[i];
			        }
			        return res;
			    }

			    function getVector(length, fillValue) {
			        /// <signature>
			        ///     <summary>Get an array filled with zeros (or optional fillValue.)</summary>
			        ///     <param name="length" type="Number">Requested array length.</param>
			        ///     <param name="fillValue" type="Number" optional="true"></param>
			        ///     <returns type="Array"></returns>
			        /// </signature>

			        // Use a default value of zero
			        if (isNaN(fillValue)) { fillValue = 0; }

			        var res = new Array(length);
			        for (var i = 0; i < length; i += 1) {
			            res[i] = fillValue;
			        }
			        return res;
			    }

			    function toArray(typedArray) {
			        /// <signature>
			        ///     <summary>Converts a UInt8Array to a regular JavaScript Array</summary>
			        ///     <param name="typedArray" type="UInt8Array"></param>
			        ///     <returns type="Array"></returns>
			        /// </signature>

			        // If undefined or null return an empty array
			        if (!typedArray) {
			            return [];
			        }

			        // If already an Array return it
			        if (typedArray.pop) {
			            return typedArray;
			        }

			        // If it's an ArrayBuffer, convert it to a Uint8Array first
			        if (getObjectType(typedArray) === "ArrayBuffer") {
			            typedArray = new Uint8Array(typedArray);
			        } else if (typedArray.BYTES_PER_ELEMENT > 1) {
			            typedArray = new Uint8Array(typedArray.buffer);
			        }

			        // A single element array will cause a new Array to be created with the length
			        // equal to the value of the single element. Not what we want.
			        // We'll return a new single element array with the single value.
			        if (typedArray.length === 1) { return [typedArray[0]]; }

			        if (typedArray.length < 65536) { return Array.apply(null, typedArray); }

			        // Apply() can only accept an array up to 65536, so we have to loop if bigger.
			        var returnArray = new Array(typedArray.length);
			        for (var i = 0; i < typedArray.length; i++) {
			            returnArray[i] = typedArray[i];
			        }

			        return returnArray;

			    }

			    function padEnd(array, value, finalLength) {
			        /// <signature>
			        ///     <summary>Pads the end of an array with a specified value</summary>
			        ///     <param name="array" type="Array"></param>
			        ///     <param name="value" type="Number">The value to pad to the array</param>
			        ///     <param name="finalLength" type="Number">The final resulting length with padding</param>
			        ///     <returns type="Array"></returns>
			        /// </signature>

			        while (array.length < finalLength) {
			            array.push(value);
			        }

			        return array;
			    }

			    function padFront(array, value, finalLength) {
			        /// <signature>
			        ///     <summary>Pads the front of an array with a specified value</summary>
			        ///     <param name="array" type="Array"></param>
			        ///     <param name="value" type="Number">The value to pad to the array</param>
			        ///     <param name="finalLength" type="Number">The final resulting length with padding</param>
			        ///     <returns type="Array"></returns>
			        /// </signature>

			        while (array.length < finalLength) {
			            array.unshift(value);
			        }

			        return array;
			    }

			    function arraysEqual(array1, array2) {
			        /// <signature>
			        ///     <summary>Checks if two Arrays are equal by comparing their values.</summary>
			        ///     <param name="array1" type="Array"></param>
			        ///     <param name="array2" type="Array"></param>
			        ///     <returns type="Array"></returns>
			        /// </signature>

			        var result = true;

			        if (array1.length !== array2.length) {
			            result = false;
			        }

			        for (var i = 0; i < array1.length; i++) {
			            if (array1[i] !== array2[i]) {
			                result = false;
			            }
			        }

			        return result;
			    }

			    function checkParam(param, type, errorMessage) {

			        if (!param) {
			            throw new Error(errorMessage);
			        }

			        if (type && (getObjectType(param) !== type)) {
			            throw new Error(errorMessage);
			        }

			        return true;
			    }

			    function stringToBytes(text) {
			        /// <signature>
			        ///     <summary>Converts a String to an Array of byte values (0-255).
			        ///              Supports UTF-8 encoding.
			        ///     </summary>
			        ///     <param name="text" type="String"/>
			        ///     <returns type="Array" />
			        /// </signature>

			        var encodedBytes = [];

			        for (var i = 0, j = 0; i < text.length; i++) {

			            var charCode = text.charCodeAt(i);

			            if (charCode < 128) {
			                encodedBytes[j++] = charCode;

			            } else if (charCode < 2048) {
			                encodedBytes[j++] = (charCode >>> 6) | 192;
			                encodedBytes[j++] = (charCode & 63) | 128;

			            } else if (charCode < 0xD800 || charCode > 0xDFFF) {
			                encodedBytes[j++] = (charCode >>> 12) | 224;
			                encodedBytes[j++] = ((charCode >>> 6) & 63) | 128;
			                encodedBytes[j++] = (charCode & 63) | 128;

			            } else {// surrogate pair (charCode >= 0xD800 && charCode <= 0xDFFF)
			                charCode = ((charCode - 0xD800) * 0x400) + (text.charCodeAt(++i) - 0xDC00) + 0x10000;
			                encodedBytes[j++] = (charCode >>> 18) | 240;
			                encodedBytes[j++] = ((charCode >>> 12) & 63) | 128;
			                encodedBytes[j++] = (charCode >>> 6) & 63 | 128;
			                encodedBytes[j++] = (charCode & 63) | 128;
			            }
			        }

			        return encodedBytes;
			    }

			    function bytesToString(textBytes) {
			        /// <signature>
			        ///     <summary>Converts an Array of byte values (0-255) to a String (Supports UTF-8 encoding)</summary>
			        ///     <param name="textBytes" type="Array"/>
			        ///     <returns type="String" />
			        /// </signature>

			        var result = "",
			            charCode;

			        // Convert from ArrayBuffer or Uint array if needed
			        textBytes = toArray(textBytes);

			        for (var i = 0; i < textBytes.length;) {

			            var encodedChar = textBytes[i++];

			            if (encodedChar < 128) {
			                charCode = encodedChar;

			            } else if (encodedChar < 224) {
			                charCode = (encodedChar << 6) + textBytes[i++] - 0x3080;

			            } else if (encodedChar < 240) {
			                charCode =
			                    (encodedChar << 12) + (textBytes[i++] << 6) + textBytes[i++] - 0xE2080;

			            } else {
			                charCode =
			                    (encodedChar << 18) + (textBytes[i++] << 12) + (textBytes[i++] << 6) + textBytes[i++] - 0x3C82080;
			            }

			            // Four byte UTF-8; Convert to UTF-16 surrogate pair
			            if (charCode > 0xFFFF) {
			                var surrogateHigh = Math.floor((charCode - 0x10000) / 0x400) + 0xD800;
			                var surrogateLow = ((charCode - 0x10000) % 0x400) + 0xDC00;
			                result += String.fromCharCode(surrogateHigh, surrogateLow);
			                continue;
			            }

			            result += String.fromCharCode(charCode);
			        }

			        return result;
			    }

			    function error(name, message) {
			        var err = Error(message);
			        err.name = name;
			        throw err;
			    }

			    function isBytes(array) {
			        if(!(array instanceof Array)) return false;
			        for (var i = 0; i < array.length; i++) {
			            var d = array[i];
			            if (!isInteger(d) || d > 255 || d < 0) return false;
			        }
			        return true;
			    }

			    function isInteger(value) {
			        return typeof value === "number" && isFinite(value) && Math.floor(value) === value;
			    }		    
			    function createProperty (parentObject, propertyName, initialValue, getterFunction, setterFunction) {
			        /// <param name="parentObject" type="Object"/>
			        /// <param name="propertyName" type="String"/>
			        /// <param name="initialValue" type="Object"/>
			        /// <param name="getterFunction" type="Function"/>
			        /// <param name="setterFunction" type="Function" optional="true"/>
			    
			        if (!setterSupport) {
			            parentObject[propertyName] = initialValue;
			            return;
			        }
			    
			        var setGet = {};
			    
			        // tslint:disable-next-line: no-unused-expression
			        getterFunction && (setGet.get = getterFunction);
			        // tslint:disable-next-line: no-unused-expression
			        setterFunction && (setGet.set = setterFunction);
			    
			        Object.defineProperty(
			            parentObject,
			            propertyName, setGet);
			    }
			    return {
			        consoleLog: consoleLog,
			        toBase64: toBase64,
			        fromBase64: base64ToBytes,
			        checkParam: checkParam,
			        getObjectType: getObjectType,
			        bytesToHexString: bytesToHexString,
			        bytesToInt32: bytesToInt32,
			        stringToBytes: stringToBytes,
			        bytesToString: bytesToString,
			        unpackData: unpackData,
			        hexToBytesArray: hexToBytesArray,
			        int32ToBytes: int32ToBytes,
			        int32ArrayToBytes: int32ArrayToBytes,
			        toArray: toArray,
			        arraysEqual: arraysEqual,
			        clone: clone,
			        xorVectors: xorVectors,
			        padEnd: padEnd,
			        padFront: padFront,
			        getVector: getVector,
			        error: error,
			        isBytes: isBytes,
			        isInteger: isInteger,
			        createProperty: createProperty
			    };

			})();

			/* commonjs-block */
			{
			    module.exports = msrcryptoUtilities;
			}
			/* end-commonjs-block */ 
		} (utilities));
		return utilities.exports;
	}

	var cryptoMath$1 = {exports: {}};

	(function (module, exports) {
		//*******************************************************************************
		//
		//    Copyright 2020 Microsoft
		//
		//    Licensed under the Apache License, Version 2.0 (the "License");
		//    you may not use this file except in compliance with the License.
		//    You may obtain a copy of the License at
		//
		//        http://www.apache.org/licenses/LICENSE-2.0
		//
		//    Unless required by applicable law or agreed to in writing, software
		//    distributed under the License is distributed on an "AS IS" BASIS,
		//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
		//    See the License for the specific language governing permissions and
		//    limitations under the License.
		//
		//*******************************************************************************

		// tslint:disable: no-bitwise
		// tslint:disable: no-shadowed-variable

		function msrcryptoMath() {
		    // 'number' of bits per digit. Must be even.
		    var DIGIT_BITS = 24;
		    // 'number' of bytes per digit.
		    var DIGIT_NUM_BYTES = Math.floor(DIGIT_BITS / 8);
		    // digit mask.
		    var DIGIT_MASK = (1 << DIGIT_BITS) - 1;
		    // digit base.
		    var DIGIT_BASE = (1 << DIGIT_BITS);
		    // max digit value, unsigned
		    var DIGIT_MAX = DIGIT_MASK;
		    // inverse of digit base to reduce digits with multiply
		    var DIG_INV = 1 / DIGIT_BASE;

		    // Construct scaler for DIGIT_NUM_BYTES, so I don't have to multiply in the loop
		    var DIGIT_SCALER = [1, 256];
		    for (var ds = 2; ds <= DIGIT_NUM_BYTES; ds++) {
		        DIGIT_SCALER[ds] = DIGIT_SCALER[ds - 1] * 256;
		    }

		    // Number of trailing zero bits in numbers 0..15 (4 bits). [0] is for 0, [15] is for 15.
		    var Zero = [0];
		    var One = [1];

		    // Create an array, mimics the constructors for typed arrays.
		    function createArray( /*@dynamic*/ parameter) {
		        var i, array = null;
		        if (!arguments.length || typeof arguments[0] === "number") {
		            // A number.
		            array = new Array(parameter);
		            for (i = 0; i < parameter; i += 1) {
		                array[i] = 0;
		            }
		        } else if (typeof arguments[0] === "object") {
		            // An array or other index-able object
		            array = new Array(parameter.length);
		            for (i = 0; i < parameter.length; i += 1) {
		                array[i] = parameter[i];
		            }
		        }
		        return array;
		    }

		    function stringToDigits(numberStr, radix) {
		        /// <summary>Parse a String in a given base into a little endian digit array.</summary>
		        /// <param name="number" type="String">Input unsigned integer in a string.</param>
		        /// <param name="radix" optional="true" integer="true">
		        /// <![CDATA[ Radix of the input. Must be >=2 and <=36. Default = 10. ]]>
		        /// </param>
		        /// <returns type="Array">Array of digits in little endian; [0] is LSW.</returns>

		        // skip leading and trailing whitespace.
		        numberStr = numberStr.replace(/^\s+|\s+$/g, "");
		        var num = [0];
		        var buffer = [0];
		        radix = radix || 10; // default radix is 10
		        for (var i = 0; i < numberStr.length; i += 1) {
		            // Extract character
		            var char = parseInt(numberStr[i], radix);
		            if (isNaN(char)) {
		                throw new Error("Failed to convert string to integer in radix " + radix.toString());
		            }

		            // 'buffer' = 'num' * 'radix'
		            multiply(num, radix, buffer);

		            // 'num' = 'buffer' + 'char'
		            add(buffer, [ /*@static_cast(Number)*/ char], num);
		            normalizeDigitArray(num);
		        }

		        return num;
		    }

		    function digitsToString(digits, radix) {
		        /// <summary>Convert a big-endian byte array to a number in string in radix.</summary>
		        /// <param name="digits" type="Digits">A big integer as a little-endian digit array.</param>
		        /// <param name="radix" optional="true" integer="true">Radix from 2 to 26. Default = 10.</param>
		        /// <returns type="String">The number in base radix as a string.</returns>

		        radix = radix || 10;
		        if (DIGIT_BASE <= radix) {
		            throw new Error("DIGIT_BASE is smaller than RADIX; cannot convert.");
		        }

		        var wordLength = digits.length;
		        var quotient = [];
		        var remainder = [];
		        var temp1 = [];
		        var temp2 = [];
		        var divisor = [];
		        var a = [];
		        var i;

		        // Find the largest divisor that fits in a digit in radix
		        //divisor[0] = 10000; // Largest power of ten fitting in a digit
		        var sb = "";
		        var pad = "0";
		        divisor[0] = radix;
		        while (Math.floor(DIGIT_BASE / divisor[0]) >= radix) {
		            divisor[0] = divisor[0] * radix;
		            pad = pad.concat("0");
		        }

		        for (i = 0; i < wordLength; i += 1) {
		            a[i] = digits[i];
		        }

		        do {
		            var allZeros = true;
		            for (i = 0; i < a.length; i += 1) {
		                if (a[i] !== 0) {
		                    allZeros = false;
		                    break;
		                }
		            }

		            if (allZeros) {
		                break;
		            }

		            divRem(a, divisor, quotient, remainder, temp1, temp2);
		            normalizeDigitArray(quotient, a.length, true);

		            var newDigits = remainder[0].toString(radix);
		            sb = pad.substring(0, pad.length - newDigits.length) + newDigits + sb;

		            var swap = a;
		            a = quotient;
		            quotient = swap;
		        } while (true);

		        // Trim leading zeros
		        while (sb.length !== 0 && sb[0] === "0") {
		            sb = sb.substring(1, sb.length);
		        }

		        if (sb.length === 0) {
		            sb = "0";
		        }

		        return sb;
		    }

		    function computeBitArray(bytes) {
		        /// <summary>Given an array of bytes in big-endian format, compute UInt8Array with
		        /// one element for each bit (0 or 1), in little-endian order.</summary>
		        /// <param name="bytes" type="Digits">An array of bytes in big-endian format.</param>
		        /// <returns type="Digits">An array of 0's and 1's representing the bits in little-endian.</returns>

		        var out = createArray(bytes.length * 8);
		        var bitLength = 0;
		        var i = bytes.length - 1;
		        while (i >= 0) {
		            var j = 0;
		            while (j < 8) {
		                var mask = (1 << j);
		                var bit = ((bytes[i] & mask) === mask) ? 1 : 0;
		                var thisBitIndex = (8 * ((bytes.length - i) - 1)) + j;

		                if (bit === 1) {
		                    bitLength = thisBitIndex + 1;
		                }

		                out[thisBitIndex] = bit;
		                j += 1;
		            }

		            i--;
		        }

		        return out.slice(0, bitLength);
		    }

		    function bitScanForward(digit) {// CT
		        /// <summary>Return the 0-based index of the first non-zero bit starting at the most significant
		        ///          bit position.</summary >
		        /// <param name="digit" type="Number" integer="true">Value to scan.</param>
		        /// <returns>Zero-based index of the first non-zero bit.</returns>
		        var index = 0;

		        for (var i = 0; i < DIGIT_BITS; i++) {
		            index = Math.max(index, -(digit >>> i & 1) & i);
		        }

		        return index;
		    }

		    function highestSetBit(bytes) {
		        /// <summary>Returns the (1 indexed) index of the highest set bit.</summary>
		        /// <param name="bytes" type="Array">A big-endian big integer byte array.</param>
		        /// <returns type="Number">The index of the highest bit.</returns>

		        var i = 0;
		        var bitLength = 0;

		        while (i < bytes.length) {
		            if (bitLength === 0) {
		                // Look for highest set bit in this byte
		                var j = 7;
		                while (j >= 0 && bitLength === 0) {
		                    var mask = (1 << j);
		                    if ((bytes[i] & mask) === mask) {
		                        bitLength = j + 1;
		                    }

		                    j--;
		                }
		            } else {
		                bitLength += 8;
		            }

		            i += 1;
		        }

		        return bitLength;
		    }

		    function fixedWindowRecode(digits, windowSize, t) {
		        /// <summary></summary>
		        /// <param name="digits" type="Array">Digits to recode</param>
		        /// <param name="windowSize" type="Number">Window size</param>
		        /// <returns type="Array">Recoded digits</returns>}

		        // Make a copy of digits because we are going to modify it with shifts below.
		        digits = digits.slice();

		        var recodedDigits = [],
		            windowSizeBits = Math.pow(2, windowSize),
		            windowSizeMinus1Bits = Math.pow(2, windowSize - 1);

		        for (var i = 0; i < t; i++) {

		            // k_digits[i] := (Z!k mod 2^w) - 2^(w-1);
		            recodedDigits[i] = (digits[0] % windowSizeBits) - windowSizeMinus1Bits;

		            // k := (k - k_digits[i])/2^(w-1);
		            digits[0] = digits[0] - recodedDigits[i];

		            // PERF : can probably do this faster
		            cryptoMath.shiftRight(digits, digits, windowSize - 1);
		        }

		        recodedDigits[i] = digits[0];

		        return recodedDigits;
		    }

		    function fixedWindowRecode2(digits, windowSize) {

		        // convert to array of individual bits
		        var digLen = digits.length;
		            new Array(digLen * DIGIT_BITS);
		            var i = 0,
		            j = 0,
		            k = 0,
		            r = 0,
		            dig,
		            result = new Array(Math.ceil(digLen * DIGIT_BITS / windowSize));

		        for (k = 0, result[0] = 0; i < digLen; i++) {
		            for (j = 0, dig = digits[i]; j < DIGIT_BITS; j++ , dig >>>= 1) {
		                if (k === windowSize) {
		                    result[++r] = 0;
		                    k = 0;
		                }
		                result[r] += (dig & 1) << k++;
		            }
		        }

		        return result;
		    }

		    function copyArray( /*@Array*/ source, sourceIndex, /*@Array*/ destination, destIndex, length) { //CT
		        /// <summary>Copies a range of elements from one array to another array.</summary>
		        /// <param name="source" type="Array">Source array to copy from.</param>
		        /// <param name="sourceIndex" type="Number">The index in the source array at which copying begins.</param>
		        /// <param name="destination" type="Array">The array that receives the data.</param>
		        /// <param name="destIndex" type="Number">The index in the destination array at which storing begins.</param>
		        /// <param name="length" type="Number">The number of elements to copy.</param>
		        while (length-- > 0) {
		            destination[destIndex + length] = source[sourceIndex + length];
		        }
		    }

		    function isZero(array) { //CT
		        /// <summary>Check if an array is zero. All elements are zero.</summary>
		        /// <param name="array" type="Digits">UInt16Array - An array to be checked.</param>
		        /// <returns type="Boolean"/>
		        var i,
		            result = 0;

		        for (i = 0; i < array.length; i += 1) {
		            result = result | array[i];
		        }
		        return !result;
		    }

		    function isEven(array) { //CT
		        /// <summary>Returns true if this number is even.</summary>
		        /// <param name="array" type="Digits"/>
		        /// <returns type="Boolean"/>
		        return (array[0] & 0x1) === 0x0;
		    }

		    function sequenceEqual(left, right) { //CT
		        /// <summary>Compare two indexable collections for sequence equality.</summary>
		        /// <param name="left" type="Digits">The left array.</param>
		        /// <param name="right" type="Digits">The right array.</param>
		        /// <returns type="Boolean">True if both arrays are the same.</returns>
		        var equal = left.length === right.length;

		        for (var i = 0; i < Math.min(left.length, right.length); i += 1) {
		            if (left[i] !== right[i]) {
		                equal = false;
		            }
		        }

		        return equal;
		    }

		    function bytesToDigits(bytes) {
		        /// <summary>Convert an unsigned number from big-endian bytes to little endian digits.</summary>
		        /// <param name="bytes" type="Bytes">The number in unsigned big-endian byte format.</param>
		        /// <returns type="Array">The digits in little-endian.</returns>

		        // Construct scaler for DIGIT_NUM_BYTES, so I don't have to multiply in the loop
		        var arrayLength = Math.floor((bytes.length + DIGIT_NUM_BYTES - 1) / DIGIT_NUM_BYTES);
		        var array = new Array(arrayLength);
		        array[0] = 0;
		        var digit = 0,
		            index = 0,
		            scIndex = 0;
		        for (var i = bytes.length - 1; i >= 0; i--) {
		            digit = digit + (DIGIT_SCALER[scIndex++] * (bytes[i] & 0x0ff));
		            if (DIGIT_SCALER[scIndex] === DIGIT_BASE) {
		                scIndex = 0;
		                array[index++] = digit;
		                digit = 0;
		            }
		        }

		        // Last digit (MSW), if there is a need
		        if (digit !== 0) {
		            array[index] = digit;
		        }

		        // Replace potential undefined elements with zeros
		        while (array[--arrayLength] == null) {
		            array[arrayLength] = 0;
		        }

		        return array;
		    }

		    function digitsToBytes(digits, trim, minTrimLength) {
		        /// <summary>Construct a big endian array of bytes from a little-endian array of digits.
		        /// Always returns at least one byte and trims leading zeros.</summary>
		        /// <param name="digits" type="Array">The digits in little-endian.</param>
		        /// <param name="trim" type="Boolean" optional="true">Remove the leading zeros from the result
		        ///     (default true)</param >
		        /// <param name="minTrimLength" type="Number" optional="true">Minimum length to trim down to.
		        ///     Valid only if trim is true.Default = 1.</param >
		        /// <returns type="Array">Encoded bytes in big-endian format.</returns>

		        var i, j, byte1;
		        var bytes = [0];

		        if (typeof trim === "undefined") {
		            trim = true;
		        }

		        for (i = 0; i < digits.length; i += 1) {
		            byte1 = digits[i];
		            for (j = 0; j < DIGIT_NUM_BYTES; j += 1) {
		                bytes[i * DIGIT_NUM_BYTES + j] = byte1 & 0x0FF;
		                byte1 = Math.floor(byte1 / 256);
		            }
		        }

		        //bytes = swapEndianness(bytes);
		        bytes.reverse();

		        if (minTrimLength === undefined) {
		            minTrimLength = 1;
		        }
		        if (trim) {
		            while (bytes.length > minTrimLength && bytes[0] === 0) {
		                bytes.shift();
		            }
		        }

		        return bytes;
		    }

		    function intToDigits(value, numDigits) {
		        /// <summary>Construct an array of digits from a positive integer.</summary>
		        /// <param name="value" type="Number" integer="true">A positive integer to be converted to digit form.</param>
		        /// <param name="numDigits" type="Number" optional="true" integer="true">The number of digits to use
		        ///     for the digit form.</param >
		        /// <returns type="Array">The given integer in digit form.</returns>

		        if (typeof numDigits === "undefined") {
		            if (value <= 1) {
		                numDigits = 1; // Special case <= 1
		            } else {
		                var numBits = Math.log(value) / Math.LN2;
		                numDigits = Math.ceil(numBits / DIGIT_BITS);
		            }
		        }

		        var digitRepresentation = [];
		        while (value > 0) {
		            digitRepresentation.push(value % DIGIT_BASE);
		            value = Math.floor(value / DIGIT_BASE);
		        }

		        while (digitRepresentation.length < numDigits) {
		            digitRepresentation.push(0);
		        }

		        return digitRepresentation;
		    }

		    function mswIndex(digits) {
		        /// <summary>Return the index of the most significant word of x, 0-indexed.
		        /// If x is zero (no significant index), then -1 is returned.</summary>
		        /// <param name="digits" type="Array">Digit array.</param>
		        /// <returns type="Number">Index of the most significant word, or -1 if digits is zero.</returns>
		        for (var i = digits.length - 1; i >= 0; i--) {
		            if (digits[i] !== undefined && digits[i] !== 0) {
		                return i;
		            }
		        }

		        return (digits[0] === 0) ? -1 : 0;
		    }

		    function compareDigits(left, right) {

		        // Constant-time compare digits
		        // The time will be different for different lengths of input, but will be constant for a given length.
		        // We expect any secret data passing through to be of some standard non-varying length.
		        // result will equal the difference of the highest order digit where left !== right
		        var result = 0,
		            val, i;

		        for (i = 0; i < Math.max(left.length, right.length); i++) {
		            val = ~~left[i] - ~~right[i];
		            // result = val === 0 ?  result : val;
		            result = val + (result & -!val);
		        }

		        return result;
		    }

		    function normalizeDigitArray(digits, length, pad) {
		        /// <summary>Normalize a digit array by truncating any leading zeros and adjusting its length.
		        /// Set the length if given, and pad it with zeros to that length of padding is requested.</summary>
		        /// <remarks>Normalization results with a zero-indexed length of the array such that the MSW is not zero.
		        /// If the final array length is zero and no non-zero digits are found, assign digits[0]=0 and set length to 1.
		        /// Optionally, pad with zeros to the given length, and set the array length.</remarks>
		        /// <param name="digits" type="Array">Digit array.</param>
		        /// <param name="length" type="Number" integer="true" optional="true">Output length to pad with zeros.</param>
		        /// <param name="pad" type="Boolean" optional="true">Pad with zeros to length if true [false].</param>
		        /// <returns type="Array">Resized digits array; same input object.</returns>

		        // Trim. Find the trimmed length and the position to start padding from (if padding is requested).
		        var i = mswIndex(digits);

		        // set the length to the given length (if given) or the trimmed length
		        digits.length = length || i + 1;

		        // Pad to the length
		        if (pad) {
		            while (++i < digits.length) {
		                digits[i] = 0;
		            }
		        }

		        if (digits.length <= 0) {
		            // no non-zero digits found.
		            digits[0] = 0;
		            digits.length = 1;
		        }

		        return digits;
		    }

		    function shiftRight(source, destination, bits, length) {
		        /// <summary>Shift a big integer to the right by the given number of bits or 1 if bits is not specified,
		        /// effectively dividing by two (or 2^bits) and ignoring the remainder.</summary>
		        /// <param name="source" type="Array">Source digit array.</param>
		        /// <param name="destination" type="Array">Destination digit array. May be the same as source.</param>
		        /// <param name="bits" integer="true" optional="true">Number of bits to shift, must be less than DIGIT_BITS
		        ///     and greater or equal to zero.Default is 1.</param >
		        /// <param name="length" optional="true" integer="true">Number of items to shift from he source array.
		        ///     Default is source.length.</param >
		        /// <remarks>This is a numerical shift. Integers are stored in arrays in little-endian format.
		        /// Thus, this function shifts an array from higher order indices into lower indices. [0] is LSW.
		        /// </remarks>

		        if (bits === undefined) {
		            bits = 1;
		        } else if (bits >= DIGIT_BITS || bits < 0) {
		            throw new Error("Invalid bit count for shiftRight");
		        }
		        if (length === undefined) {
		            length = source.length;
		        }

		        var n = length - 1;
		        var leftShiftBitCount = DIGIT_BITS - bits;
		        for (var i = 0; i < n; i++) {
		            destination[i] = ((source[i + 1] << leftShiftBitCount) | (source[i] >>> bits)) & DIGIT_MASK;
		            //a[i] = high|low = low bits of a[i+1] | high bits of a[i]
		        }

		        destination[n] = source[n] >>> bits;
		    }

		    function shiftLeft(source, destination, bits, length) {
		        /// <summary>Shift a number array to the left by given bits, i.e., multiply by 2^bits.</summary>
		        /// <param name="source" type="Array">Source digit array.</param>
		        /// <param name="destination" type="Array">Destination digit array. May be the same as source.</param>
		        /// <param name="bits" integer="true" optional="true">Number of bits to shift, must be less than DIGIT_BITS
		        ///     and greater or equal to zero.Default is 1.</param >
		        /// <param name="length" optional="true" integer="true">Number of items to shift from he source array.
		        ///     Default is source.length.</param >
		        /// <remarks>An additional MSW digit may be added if the leftshift out from the current MSW produces a
		        ///     non - zero result. [0] is LSW.</remarks >

		        if (bits === undefined) {
		            bits = 1;
		        } else if (bits >= DIGIT_BITS || bits < 0) {
		            throw new Error("bit count must be smaller than DIGIT_BITS and positive in shiftLeft");
		        }
		        if (length === undefined) {
		            length = source.length;
		        }

		        var rightShiftBitCount = DIGIT_BITS - bits;
		        // The following line is correct. destination should remain undefined if there are no bits going into it.
		        destination[length] = (source[length - 1] >>> (DIGIT_BITS - bits)) || destination[length];
		        for (var i = length - 1; i > 0; i--) {
		            destination[i] = ((source[i] << bits) | ((source[i - 1] >>> rightShiftBitCount))) & DIGIT_MASK;
		            // a[i] = high|low = low bits of a[i] | high bits of a[i-1]
		        }

		        destination[0] = (source[0] << bits) & DIGIT_MASK;
		    }

		    //// //// //// //// //// //// //// //// //// //// //// //// //// /
		    // Low level math routines
		    //// //// //// //// //// //// //// //// //// //// //// //// //// /

		    function add(addend1, addend2, sum) {
		        /// <summary>Add two arrays of digits into a third array: sum = addend1 + addend2. Carry is recorded
		        ///     in the output if there is one.</summary >
		        /// <param name="addend1" type="Array">The first addend.</param>
		        /// <param name="addend2" type="Array">The second added.</param>
		        /// <param name="sum" type="Array">The output sum buffer addend1 + addend2.</param>
		        /// <returns type="Number" integer="true">If carry out then 1, otherwise 0.</returns>

		        // Determine which is shorter
		        var shortArray = addend1;
		        var longArray = addend2;
		        if (addend2.length < addend1.length) {
		            shortArray = addend2;
		            longArray = addend1;
		        }

		        // Perform the addition
		        var s = shortArray.length;
		        var carry = 0;
		        var i;

		        for (i = 0; i < s; i += 1) {
		            carry += shortArray[i] + longArray[i];
		            sum[i] = carry & DIGIT_MASK;
		            carry = (carry >> DIGIT_BITS);
		        }

		        for (i = s; i < longArray.length; i += 1) {
		            carry += longArray[i];
		            sum[i] = carry & DIGIT_MASK;
		            carry = (carry >> DIGIT_BITS);
		        }

		        // Set output length
		        sum.length = longArray.length;

		        // Is there a carry into the next digit?
		        if (carry !== 0) {
		            sum[i] = carry & DIGIT_MASK;
		        }

		        return carry;
		    }

		    function subtract(minuend, subtrahend, difference) {
		        /// <summary>Subtraction: difference = minuend - subtrahend. Condition: minuend.length &lt;=
		        ///     subtrahend.length.</summary >
		        /// <param name="minuend" type="Array">Minuend.</param>
		        /// <param name="subtrahend" type="Array">Subtrahend.</param>
		        /// <param name="difference" type="Array">The difference.</param>
		        /// <returns type="Number" integer="true">Returns -1 if there is a borrow (minuend &lt; subtrahend),
		        ///     or 0 if there isn't (minuend &gt;= subtrahend).</returns>

		        var s = subtrahend.length;
		        if (minuend.length < subtrahend.length) {
		            s = mswIndex(subtrahend) + 1;
		            if (minuend.length < s) {
		                throw new Error("Subtrahend is longer than minuend, not supported.");
		            }
		        }
		        var i, carry = 0;
		        for (i = 0; i < s; i += 1) {
		            carry += minuend[i] - subtrahend[i];
		            difference[i] = carry & DIGIT_MASK;
		            carry = carry >> DIGIT_BITS;
		        }

		        // Propagate the carry by subtracting from minuend into difference
		        while (i < minuend.length) {
		            carry += minuend[i];
		            difference[i++] = carry & DIGIT_MASK;
		            carry = carry >> DIGIT_BITS;
		        }

		        return carry;
		    }

		    function multiply(a, b, p) {

		        b = (typeof b === "number") ? [b] : b;

		        var i, j, k, l, c, t1, t2, alen = a.length,
		            blen = b.length,
		            bi;

		        for (i = 0; i < alen + blen; i += 1) {
		            p[i] = 0;
		        }

		        i = 0;
		        l = 0;

		        var maxRounds = 31;
		        var ks = 0;

		        while (i < blen) {

		            l = Math.min(l + maxRounds, blen);

		            // For i from 0 by 1 to s - 1 do
		            for (; i < l; i++) {
		                bi = b[i];
		                for (j = 0; j < alen; j++) {
		                    p[i + j] += a[j] * bi;
		                }
		            }

		            c = 0;
		            // Reduce the answer to 24-bit digits
		            for (k = ks; k < i + alen; k++) {
		                t1 = p[k] + c;
		                t2 = t1 & DIGIT_MASK;
		                p[k] = t2;
		                c = (t1 - t2) * DIG_INV;
		            }
		            p[k] = c;

		            ks += maxRounds;
		        }

		        p.length = alen + blen;

		        return p;
		    }

		    function divRem(dividend, divisor, quotient, remainder, temp1, temp2) {
		        /// <summary>Computes the quotient q and remainder r when dividend is divided by
		        ///   divisor.</summary>
		        /// <param name="dividend" type="Array">The dividend.</param>
		        /// <param name="divisor" type="Array">The divisor.</param>
		        /// <param name="quotient" type="Array">Receives the quotient (n digits).</param>
		        /// <param name="remainder" type="Array">Receives the remainder (n digits).</param>
		        /// <param name="temp1" type="Array" optional="true">Temporary storage (n digits).</param>
		        /// <param name="temp2" type="Array" optional="true">Temporary storage (n digits).</param>
		        /// <remarks>This is an implementation of Figure 9-1 is Knuth's Algorithm D [Knu2 sec. 4.3.1].
		        /// Throws error on division by zero.
		        /// </remarks>
		        var m = mswIndex(dividend) + 1; // zero-based length
		        var n = mswIndex(divisor) + 1; // zero-based length
		        var qhat, rhat, carry, p, t, i, j;

		        // Check for quick results and clear out conditionals
		        if (m < n) {
		            // dividend < divisor. q=0, remainder=dividend
		            copyArray(dividend, 0, remainder, 0, dividend.length);
		            remainder.length = dividend.length;
		            normalizeDigitArray(remainder);
		            quotient[0] = 0;
		            quotient.length = 1;
		            return;
		        } else if (n === 0 || (n === 1 && divisor[n - 1] === 0)) { // self-explanatory
		            throw new Error("Division by zero.");
		        } else if (n === 1) {
		            // divisor is single digit; do a simpler division
		            t = divisor[0];
		            rhat = 0;
		            for (j = m - 1; j >= 0; j--) {
		                p = (rhat * DIGIT_BASE) + dividend[j];
		                quotient[j] = (p / t) & DIGIT_MASK;
		                rhat = (p - quotient[j] * t) & DIGIT_MASK;
		            }
		            quotient.length = m;
		            normalizeDigitArray(quotient);
		            remainder[0] = rhat;
		            remainder.length = 1;
		            return;
		        }

		        // Normalization step. Align dividend and divisor so that their
		        // most significant digits are at the same index.
		        // Shift divisor by so many bits (0..DIGIT_BITS-1) to make MSB non-zero.
		        var s = DIGIT_BITS - 1 - bitScanForward(divisor[n - 1]);
		        var vn = temp1 || [];
		        vn.length = n;
		        shiftLeft(divisor, vn, s, n);

		        var un = temp2 || [];
		        un.length = m;
		        shiftLeft(dividend, un, s, m);
		        un[m] = un[m] || 0; // must not be undefined

		        // Main division loop with quotient estimate qhat
		        quotient.length = m - n + 1;
		        remainder.length = n;
		        for (j = m - n; j >= 0; j--) {
		            // Estimate quotient qhat using two-digit by one-digit division
		            // because 3-digit by 2-digit division is more complex. Then, correct qhat after this.
		            qhat = Math.floor((un[j + n] * DIGIT_BASE + un[j + n - 1]) / vn[n - 1]);
		            rhat = (un[j + n] * DIGIT_BASE + un[j + n - 1]) - qhat * vn[n - 1];

		            // If the quotient estimate is large, reduce the quotient estimate till the following is satisfied:
		            //      qhat = {un[j+n, j+n-1, j+n-2]} div {uv[n-1,n-2]}
		            while (true) {
		                if (qhat >= DIGIT_BASE || (qhat * vn[n - 2]) > ((rhat * DIGIT_BASE) + un[j + n - 2])) {
		                    qhat = qhat - 1;
		                    rhat = rhat + vn[n - 1];
		                    if (rhat < DIGIT_BASE) {
		                        continue;
		                    }
		                }

		                break;
		            }

		            // Multiply the [shifted] divisor by the quotient estimate and subtract the product from the dividend
		            // un = un - qhat*vn
		            carry = 0;
		            for (i = 0; i < n; i++) {
		                p = qhat * vn[i];
		                t = un[i + j] - carry - (p & DIGIT_MASK);
		                un[i + j] = t & DIGIT_MASK;
		                //carry = (p >>> DIGIT_BITS) - (t >> DIGIT_BITS);
		                // Don't shift: integer shifts are defined over 32-bit numbers in JS.
		                carry = Math.floor(p / DIGIT_BASE) - Math.floor(t / DIGIT_BASE);
		            }

		            t = un[j + n] - carry;
		            un[j + n] = t & DIGIT_MASK;

		            // Store the estimated quotient digit (may need correction)
		            quotient[j] = qhat & DIGIT_MASK;

		            // Correction needed?
		            if (t < 0) {
		                // quotient too big (at most by 1 divisor)
		                // decrement the quotient, and add [shifted] divisor back to the running dividend (remainder)
		                quotient[j] = quotient[j] - 1;

		                // un = un + vn
		                carry = 0;
		                for (i = 0; i < n; i++) {
		                    t = un[i + j] + vn[i] + carry;
		                    un[i + j] = t & DIGIT_MASK;
		                    carry = t >> DIGIT_BITS;
		                }
		                un[j + n] = (un[j + n] + carry) & DIGIT_MASK;
		            }
		        }

		        // De-normalize the remainder (shift right by s bits).
		        for (i = 0; i < n; i++) {
		            remainder[i] = ((un[i] >>> s) | (un[i + 1] << (DIGIT_BITS - s))) & DIGIT_MASK;
		        }

		        // Compute correct lengths for the quotient and remainder
		        normalizeDigitArray(quotient);
		        normalizeDigitArray(remainder);
		    }

		    // tslint:disable-next-line: variable-name
		    function reduce(number, modulus, remainder, temp1, temp2) {
		        /// <summary>Integer reduction by a modulus to compute number mod modulus. This function uses division,
		        /// and should not be used for repetitive operations.</summary>
		        /// <param name="number" type="Array">Input number to reduce.</param>
		        /// <param name="modulus" type="Array">Modulus to reduce the input by.</param>
		        /// <param name="remainder" type="Array">Output remainder = number mod modulus.</param>
		        /// <param name="temp1" type="Array" optional="true">Temporary space, optional.</param>
		        /// <param name="temp2" type="Array" optional="true">Temporary space, optional.</param>
		        /// <returns type="Array">The resulting remainder is in 0..modulus-1; same as "remainder".</returns>

		        // TODO: More efficient reduction implementation
		        var quotient = [];
		        divRem(number, modulus, quotient, remainder, temp1, temp2);

		        return remainder;
		    }

		    function modMul(multiplicand, /*@dynamic*/ multiplier, modulus, product, temp1, temp2) {
		        /// <summary>Modular multiplication of two numbers for a modulus. This function uses multiply and divide method,
		        /// and should not be used for repetitive operations.
		        /// product can be same as multiplicand and multiplier.</summary>
		        /// <param name="multiplicand" type="Array">Multiplicand.</param>
		        /// <param name="multiplier">Multiplier.</param>
		        /// <param name="modulus" type="Array">Modulus to reduce the product.</param>
		        /// <param name="product" type="Array">Output product = multiplicand * multiplier mod modulus.</param>
		        /// <param name="temp1" type="Array" optional="true">Scratch space (optional).</param>
		        /// <param name="temp2" type="Array" optional="true">Scratch space (optional).</param>
		        /// <returns type="Array">The resulting product in in 0..modulus-1; same as product.</returns>

		        var quotient = [];
		        multiply(multiplicand, multiplier, quotient);
		        divRem(quotient, modulus, quotient, product, temp1, temp2);

		        return product;
		    }

		    function eea(a, b, upp, vpp, rpp) {
		        /// <summary>Extended Euclidean Algorithm, Berlekamp's version. On return
		        /// b*upp - a*vpp = (-1)(k-1)*rpp.</summary>
		        /// <param name="a" type="Array">The first number a.</param>
		        /// <param name="b" type="Array">The second number b.</param>
		        /// <param name="upp" type="Array">a^-1 mod b if gcd=1. Optional.</param>
		        /// <param name="vpp" type="Array">b^-1 mod a if gcd=1. Optional./</param>
		        /// <param name="rpp" type="Array">gcd(a,b).</param>
		        /// <returns type="Number">k value.</returns>
		        /// <remarks>, Pages 24-30.<code>
		        ///     if k is odd
		        ///         a*a^-1 = 1 mod b    ---> a^-1 = b - vpp
		        ///         b*b^-1 = 1 mod a    ---> b^-1 = vpp
		        ///     if k is even
		        ///         a*a^-1 = 1 mod b    ---> a^-1 = upp
		        ///         b*b^-1 = 1 mod a    ---> b^-1 = a - upp
		        /// </code></remarks>
		        // Initialize rpp and rp from two inputs a and b s.t. rpp >= rp
		        var rp; // initialized from a or b
		        if (isZero(a)) { // gcd = (0,b) = b
		            copyArray(b, 0, rpp, 0, b.length);
		            rpp.length = b.length;
		            return 0;
		        } else if (isZero(b)) { // gcd = (a,0) = a
		            copyArray(a, 0, rpp, 0, a.length);
		            rpp.length = a.length;
		            return 0;
		        } else if (compareDigits(a, b) < 0) {
		            rp = a.slice(0);
		            copyArray(b, 0, rpp, 0, b.length);
		            rpp.length = b.length;
		        } else {
		            rp = b.slice(0);
		            copyArray(a, 0, rpp, 0, a.length);
		            rpp.length = a.length;
		        }

		        normalizeDigitArray(rpp);
		        normalizeDigitArray(rp);
		        var q = new Array(rpp.length);
		        var r = new Array(rpp.length);

		        var v = new Array(rpp.length);
		        var vppPresent = vpp !== undefined;
		        var vp;
		        if (vppPresent) {
		            vp = new Array(rpp.length);
		            vp[0] = 1;
		            vp.length = 1;
		            vpp[0] = 0;
		            vpp.length = 1;
		        }

		        var up;
		        var u = new Array(rpp.length);
		        var uppPresent = upp !== undefined;
		        if (uppPresent) {
		            up = new Array(rpp.length);
		            up[0] = 0;
		            up.length = 1;
		            upp[0] = 1;
		            upp.length = 1;
		        }

		        // k starts at -1 so that on return, it is >=0.
		        // In the following discussion, assume a<b and this is computing a^-1 mod b where (a,b)=1, a<b.
		        // Initialize rp=a, rpp=b.
		        // The integer k keeps track of the sign of a^-1 (0 = positive) in b = q*a + r with 0 = q*a + r mod b
		        // such that for q=a^-1 and r=1 (which is gcd=1 for inverse to exist), we have q*a = (-1)^k mod b.
		        // Thus, for odd k, q*a = -1 mod b, and a^-1 = b-q as in the description.
		        var k = -1;

		        // At the end, gcd = rp = (a,b)
		        // tslint:disable-next-line: variable-name
		        var upp_out = upp;
		        // tslint:disable-next-line: variable-name
		        var vpp_out = vpp;
		        // tslint:disable-next-line: variable-name
		        var rpp_out = rpp;
		        var save;

		        // Recycle u and v as temp variables in division (divRem).
		        while (!isZero(rp)) {
		            // rpp = q*rp + r: compute q, r
		            divRem(rpp, rp, q, r, u, v);

		            if (uppPresent) {
		                // u = q*up + upp
		                // upp=up, up=u, u=upp
		                multiply(q, up, u);
		                add(u, upp, u);
		                normalizeDigitArray(u);
		                save = upp;
		                upp = up;
		                up = u;
		                u = save;
		            }

		            if (vppPresent) {
		                // v = q*vp + vpp
		                // vpp=vp, vp=v, v=vpp
		                multiply(q, vp, v);
		                add(v, vpp, v);
		                normalizeDigitArray(v);
		                save = vpp;
		                vpp = vp;
		                vp = v;
		                v = save;
		            }

		            // rpp=rp, rp=r, r=rpp
		            save = rpp;
		            rpp = rp;
		            rp = r;
		            r = save;

		            k++;
		        }

		        // copy to output upp, vpp, rpp
		        if (uppPresent) {
		            copyArray(upp, 0, upp_out, 0, upp.length);
		            upp_out.length = upp.length;
		        }
		        if (vppPresent) {
		            copyArray(vpp, 0, vpp_out, 0, vpp.length);
		            vpp_out.length = vpp.length;
		        }
		        copyArray(rpp, 0, rpp_out, 0, rpp.length);
		        rpp_out.length = rpp.length;

		        return k;
		    }

		    function gcd(a, b, output) {
		        /// <summary>Compute greatest common divisor or a and b.</summary>
		        /// <param name="a" type="Array">First integer input.</param>
		        /// <param name="b" type="Array">Second integer input.</param>
		        /// <param name="output" type="Array" optional="true">GCD output (optional).</param>
		        /// <returns type="Array">GCD(a,b), the same object as the output parameter if given or a new
		        ///     object otherwise.</returns >
		        var aa = a;
		        var bb = b;
		        if (compareDigits(a, b) > 0) {
		            aa = b;
		            bb = a;
		        }

		        eea(aa, bb, undefined, undefined, output);
		        return normalizeDigitArray(output);
		    }

		    function modInv(a, n, aInv, pad) {
		        //
		        // Not constant time
		        // Use this when n is not prime
		        //
		        /// <summary>Modular multiplicative inverse a^-1 mod n.</summary>
		        /// <param name="a" type="Array">The number to invert. Condition: a &lt; n, or the result would be
		        ///     n ^ -1 mod a.</param >
		        /// <param name="n" type="Array">The modulus.</param>
		        /// <param name="aInv" type="Array" optional="true">a^-1 mod n (optional).</param>
		        /// <param name="pad" type="Boolean" optional="true">True to pad the returned value to the length of the
		        ///     modulus(optional).</param >
		        /// <returns type="Array">a^-1 mod n. Same as the aInv parameter if the parameter is specified.</returns>
		        //var gcd = eea(a, n, inv);
		        var upp = new Array(n.length);
		        var vpp = new Array(n.length);
		        var rpp = new Array(n.length);
		        var k = eea(a, n, vpp, upp, rpp);

		        aInv = aInv || [];
		        if (compareDigits(rpp, One) !== 0) {
		            aInv[0] = NaN;
		            aInv.length = 1;
		        } else {
		            // gcd = 1, there is an inverse.
		            // Compute inverse from Berlekamp's EEA outputs.
		            if ((k & 1) === 1) {
		                subtract(n, upp, aInv);
		            } else {
		                copyArray(upp, 0, aInv, 0, upp.length);
		                aInv.length = upp.length;
		            }
		            if (pad) {
		                normalizeDigitArray(aInv, n.length, true);
		            } else {
		                normalizeDigitArray(aInv);
		            }
		        }

		        return aInv;
		    }

		    function modInvCT(a, n, aInv, pad) {
		        /// <summary>Modular multiplicative inverse a^-1 mod n.</summary>
		        /// <param name="a" type="Array">The number to invert. Condition: a &lt; n, or the result would be
		        ///     n ^ -1 mod a.</param >
		        /// <param name="n" type="Array">The modulus.</param>
		        /// <param name="aInv" type="Array" optional="true">a^-1 mod n (optional).</param>
		        /// <param name="pad" type="Boolean" optional="true">True to pad the returned value to the length of the
		        ///     modulus(optional).</param >
		        /// <returns type="Array">a^-1 mod n. Same as the aInv parameter if the parameter is specified.</returns>

		        // Constant time but slower modInv
		        var nMinus2 = [];
		        aInv = aInv || [];
		        subtract(n, [2], nMinus2);
		        modExp(a, nMinus2, n, aInv);
		        normalizeDigitArray(aInv);
		        return aInv;
		    }

		    function modExp(base, exponent, modulus, result) {
		        /// <summary>Modular exponentiation in an integer group.</summary>
		        /// <param name="base" type="Array">The base of the exponentiation.</param>
		        /// <param name="exponent" type="Array">The exponent.</param>
		        /// <param name="modulus" type="Array">Modulus to reduce the result.</param>
		        /// <param name="result" type="Array" optional="true">Output element that takes the modular exponentiation
		        ///     result(optional).</param >
		        /// <returns type="Array">Modular exponentiation result, same as <param name="result"/> if not null,
		        ///     or a new object.</returns >

		        result = result || [];

		        // If exponent is 0 return 1
		        if (compareDigits(exponent, Zero) === 0) {
		            result[0] = 1;
		        } else if (compareDigits(exponent, One) === 0) {
		            // If exponent is 1 return valueElement
		            copyArray(base, 0, result, 0, base.length);
		            result.length = base.length;
		        } else {
		            var montmul = new MontgomeryMultiplier(modulus);
		            normalizeDigitArray(base, montmul.s, true);
		            montmul.modExp(
		                base,
		                exponent,
		                result);
		            result.length = modulus.length;
		        }

		        return result;
		    }

		    function MontgomeryMultiplier(modulus, context) {
		        /// <summary>Construct a new montgomeryMultiplier object with the given modulus.</summary>
		        /// <param name="modulus" type="Array">A prime modulus in little-endian digit form</param>
		        /// <remarks>Montgomery Multiplier class
		        /// This class implements high performance montgomery multiplication using
		        /// CIOS, as well as modular exponentiation.</remarks>

		        function computeM0Prime(m0) {
		            /// <summary>Compute m' = -(m^-1) mod b, 24 bit digits. Based on Tolga Acar's code.</summary>
		            /// <param name="m0" type="Number" integer="true">Digit m.</param>
		            /// <returns type="Number">Digit m'.</returns>
		            var m0Pr = 1;
		            var a = 2;
		            var b = 3;
		            var c = b & m0;

		            for (var i = 2; i <= DIGIT_BITS; i += 1) {
		                if (a < c) {
		                    m0Pr += a;
		                }

		                a = a << 1;
		                b = (b << 1) | 1;
		                c = m0 * m0Pr & b;
		            }

		            var result = (~m0Pr & DIGIT_MASK) + 1;
		            return result;
		        }

		        function montgomeryMultiply(multiplicand, multiplier, result, ctx) {
		            /// <summary>Montgomery multiplication with the CIOS method.</summary>
		            /// <param name="multiplicand" type="Array">Multiplicand.</param>
		            /// <param name="multiplier" type="Array">Multiplier.</param>
		            /// <param name="result" type="Array">Computed result multiplicand * multiplier * r^-1 mod n.</param>
		            /// <param name="ctx" type="MontgomeryMultiplier" optional="true">Context (optional = this).</param>

		            // uses new temp for results so we can mult result

		            ctx = ctx || this;

		            var m = ctx.m,
		                s = m.length,
		                mPrime = ctx.mPrime,
		                m0 = ctx.m0,
		                rightI, r0, q, i = 0,
		                j, jm1, t1, t2, carry, rounds = 0;

		            // create the temp array
		            var temp = createArray(s + 2); //zeros.slice(0, s + 1);

		            while (i < s) {

		                rounds = Math.min(s, rounds + 16);

		                for (; i < rounds;) {

		                    rightI = ~~multiplier[i];

		                    r0 = temp[0] + multiplicand[0] * rightI;

		                    q = ((r0 & DIGIT_MASK) * mPrime) & DIGIT_MASK;

		                    temp[1] += ((m0 * q + r0) * DIG_INV) | 0;

		                    for (j = 1, jm1 = 0; j < s; jm1 = j, j += 1) {
		                        temp[jm1] = temp[j] + m[j] * q + multiplicand[j] * rightI;
		                    }
		                    temp[jm1] = temp[j];
		                    temp[j] = 0;

		                    i++;
		                }

		                carry = 0;
		                for (j = 0; j < s; j++) {
		                    t1 = temp[j] + carry;
		                    t2 = t1 & DIGIT_MASK;
		                    temp[j] = t2;
		                    carry = (t1 - t2) * DIG_INV;
		                }
		                temp[j] = carry;
		            }

		            for (i = 0; i < s; i += 1) {
		                result[i] = temp[i];
		            }
		            result.length = s;

		            // Subtract modulus
		            var needSubtract = +(cryptoMath.compareDigits(temp, m) > 0);
		            cryptoMath.subtract(result, m, ctx.temp2);

		            ctSetArray(needSubtract, result, ctx.temp2);

		            return;
		        }

		        function convertToMontgomeryForm( /*@type(Digits)*/ digits) {
		            /// <summary>Convert the digits in standard form to Montgomery residue representation.</summary>
		            /// <param name="digits" type="Array">Input digits to convert, and also the output converted digits.</param>

		            // Pad missing digits with zeros
		            if (digits.length < this.s) {
		                digits.length = this.s;
		                for (var i = 0; i < this.s; i++) {
		                    digits[i] = isNaN(digits[i]) ? 0 : digits[i];
		                }
		            }

		            var result = createArray(digits.length);

		            this.montgomeryMultiply(digits, this.rSquaredModm, result);
		            for (i = 0; i < this.s; i += 1) {
		                digits[i] = result[i];
		            }
		        }

		        function convertToStandardForm(digits) {
		            /// <summary>Convert from Montgomery residue representation to the standard form.</summary>
		            /// <param name="digits" type="Array">Input digits to convert, and also the output converted digits.</param>
		            this.montgomeryMultiply(digits, this.one, this.temp1);
		            for (var i = 0; i < this.s; i += 1) {
		                digits[i] = this.temp1[i];
		            }
		        }

		        function optimalWindowSize(length) {

		            var i = 2,
		                t1, t0, bits = length * DIGIT_BITS;

		            t0 = 4 + Math.ceil(bits / 2) * 3 + 1;
		            do {
		                i++;
		                t1 = t0;
		                t0 = Math.pow(2, i) + Math.ceil(bits / i) * (i + 1) + 1;
		            } while (t0 < t1);

		            return i - 1;
		        }

		        function modExp(base, exponent, result, skipSideChannel) {
		            /// <summary>Compute base to exponent mod m into result.</summary>
		            /// <param name="base" type="Array">Base of length s in the context.</param>
		            /// <param name="exponent" type="Array">Exponent.</param>
		            /// <param name="result" type="Array">Output as base raised to exponent, and reduced to the modulus
		            ///     in the context.</param >
		            /// <returns type="Array">result base^exponent mod m; the same result object.</returns>

		            skipSideChannel = !!skipSideChannel;

		            var windowBits = optimalWindowSize(exponent.length);

		            var i, j,
		                expBits = fixedWindowRecode2(exponent, windowBits).reverse(),
		                partialResult = this.rModM.slice(0),
		                baseTableLen = Math.pow(2, windowBits),
		                bt = baseTable;

		            // Prepare the precomputation table of base for k bits
		            // base[0..n] = [r, r*base, r*base^2, r*base^3, ...] mod m
		            bt.length = baseTableLen;
		            bt[0] = this.rModM;
		            for (i = 1; i < baseTableLen; i++) {
		                bt[i] = [];
		                multiply(bt[i - 1], base, bt[i]);
		                this.reduce(bt[i]);
		                //normalizeDigitArray(bt[i], this.m.length);
		            }

		            var tableVal = [];
		            var exp;

		            for (i = 0; i < expBits.length; i++) {
		                for (j = 0; j < windowBits; j++) {
		                    this.montgomeryMultiply(partialResult, partialResult, partialResult);
		                }

		                // windowed exponent bits
		                exp = expBits[i];

		                skipSideChannel ?  // allow faster lookup if explicitly requested.
		                    (tableVal = bt[exp]) :
		                    getTableEntry(bt, exp, tableVal);

		                this.montgomeryMultiply(partialResult, tableVal, partialResult);
		            }

		            this.montgomeryMultiply(partialResult, this.one, result);

		            return result;
		        }

		        function getTableEntry(bt, exp, tableVal) {

		            var z, t, mask, tableEntry, k;
		            // Constant-time/mem-access of pre-computation table
		            // Runs through each table entry value. Use mask to copy the desired value to tableVal
		            for (z = 0; z < bt[0].length; z++) { tableVal[z] = 0; } // zero-out the result
		            for (t = 0; t < bt.length; t++) {
		                tableEntry = bt[t];
		                mask = -(exp === t);
		                for (k = 0; k < tableEntry.length; k++) {
		                    tableVal[k] = tableVal[k] | (tableEntry[k] & mask);
		                }
		            }
		        }

		        function ctSetArray(condition, a, b) {
		            // condition: 1 = b->a
		            //            0 = a->a
		            var bMask = -condition; // condition = 1? bCond = -1 : bCond = -0
		            var aMask = ~bMask;     // condition = 1? aCond = 0  : aCond = -1

		            for (var i = 0; i < a.length; i++) {
		                a[i] = (a[i] & aMask) | (b[i] & bMask);
		            }
		        }

		        function reduce(x, result) {
		            // Barrett Reduction

		            // Requires mu = b^2k/m. mu is precomputed when MontgomeryMultiplier is initialized.
		            // Therefore this will only reduce by the modulus used for initialization.

		            var k = this.m.length,
		                q1, q2, q3,
		                r1, r2,
		                i,
		                needSubtract,
		                temp = [];

		            // overwrite input if output not supplied
		            result = result || x;

		            // 1. q1←[x/b^k−1], q2←q1 · mu, q3←bq2/bk+1c.
		            q1 = x.slice(k - 1);
		            q2 = []; multiply(q1, this.mu, q2);
		            q3 = q2.slice(k + 1);

		            // 2. r1←x mod bk + 1, r2←q3 · m mod bk + 1, r←r1 − r2.
		            r1 = x.slice(0, k + 1);
		            r2 = []; multiply(q3, m, r2); r2 = r2.slice(0, k + 1);

		            //3. If r < 0 then r←r + bk+1.
		            r1[k + 1] = compareDigits(r1, r2) >>> 31;

		            for (i = 0; i < result.length; i++) { result[i] = 0; }
		            subtract(r1, r2, result);

		            //4. If r ≥ m do: r←r − m.
		            needSubtract = +(compareDigits(result, m) > 0);
		            cryptoMath.subtract(result, m, temp);
		            ctSetArray(needSubtract, result, temp);

		            normalizeDigitArray(result);

		            return;
		        }

		        // precompute values we'll use later
		        function computeContext(modulus) {

		            // Operand size (number of digits)
		            var s = modulus.length;

		            // First digit of modulus
		            var m0 = modulus[0];

		            var ctx = {
		                m: modulus,
		                mPrime: computeM0Prime(m0),
		                m0: m0,
		                temp1: createArray(2 * s + 1),
		                temp2: createArray(2 * s + 1)
		            };

		            // Barrett pre-computation
		            var R = createArray(modulus.length * 2); R[R.length] = 1;
		            ctx.mu = []; divRem(R, modulus, ctx.mu, []);

		            // Create r and compute r mod m
		            // Since we are base b integers of length s, we want
		            // 'r = b^n = b^s'.
		            var quotient = createArray(2 * s + 1);
		            var rRemainder = createArray(s + 1); // becomes rModM
		            var temp1 = createArray(2 * s + 1);
		            var temp2 = createArray(2 * s + 1);
		            var rDigits = rRemainder;
		            rDigits[s] = 1;
		            divRem(rDigits, modulus, quotient, rRemainder, temp1, temp2);
		            ctx.rModM = normalizeDigitArray(rRemainder, s, true);

		            // Compute R^2 mod m
		            var rSquaredModm = createArray(2 * s + 1);
		            var rSquaredDigits = rSquaredModm;
		            rSquaredDigits[s * 2] = 1;
		            divRem(rSquaredDigits, modulus, quotient, rSquaredModm, temp1, temp2);
		            ctx.rSquaredModm = normalizeDigitArray(rSquaredModm, s, true);

		            // Ready to do MontMul now - compute R^3
		            ctx.rCubedModm = createArray(s);
		            montgomeryMultiply(rSquaredModm, rSquaredModm, ctx.rCubedModm, ctx);

		            return ctx;
		        }

		        // if a context is supplied, use it's values - if not, generate a new context
		        context = context || computeContext(modulus);

		        // set the member values from the context

		        // Modulus
		        var m = context.m;

		        // Barrett pre-computation of this modulus
		        var mu = context.mu;

		        // First digit of modulus
		        var m0 = context.m0;

		        // Operand size (number of digits)
		        var s = m.length;

		        // we'll use slice on this when we need a fresh array of zeros
		        var zeros = createArray(s + 1);

		        // The number one - used by modpow
		        var one = zeros.slice(0, s);
		        one[0] = 1;

		        // Compute m' = -(m^-1) mod b used by CIOS
		        var mPrime = context.mPrime;

		        // Create r and compute r mod m
		        // Since we are base b integers of length s, we want
		        // 'r = b^n = b^s'.
		        var rModM = context.rModM;

		        // Compute R^2 mod m
		        var rSquaredModm = context.rSquaredModm;

		        // Ready to do MontMul now - compute R^3
		        var rCubedModm = context.rCubedModm;

		        var temp1 = createArray(2 * s + 1);
		        var temp2 = createArray(2 * s + 1);

		        // Allocate space for multi-bit modular exponentiation
		        var baseTable = new Array(4);
		        baseTable[0] = rModM;
		        baseTable[1] = new Array(s);
		        baseTable[2] = new Array(s);
		        baseTable[3] = new Array(s);

		        // Return a per-instance context for Montgomery multiplier.
		        // There is no need to use the "new" keyword when using this function.
		        return {
		            // Modulus
		            m: m,

		            // First digit of modulus
		            m0: m0,

		            // Compute m' = -(m^-1) mod b used by CIOS
		            mPrime: mPrime,
		            mu: mu,

		            rSquaredModm: rSquaredModm,
		            s: s,
		            rModM: rModM,
		            rCubedModm: rCubedModm,
		            one: one,
		            temp1: temp1,
		            temp2: temp2,

		            // Functions
		            convertToMontgomeryForm: convertToMontgomeryForm,
		            convertToStandardForm: convertToStandardForm,
		            montgomeryMultiply: montgomeryMultiply,
		            modExp: modExp,
		            reduce: reduce,

		            ctx: context
		        };
		    }

		    function IntegerGroup(modulusBytes) {
		        /// <summary>Construct a new IntegerGroup object with the given modulus.</summary>
		        /// <param name="modulusBytes" type="Array">A big-endian number to represent the modulus in a
		        ///     byte array.</param >
		        /// <remarks>This class represents the set of integers mod n. It is meant to be used in
		        /// a variety of situations, for example to perform operations in the additive
		        /// or multiplicative groups mod n. The modulus can be an arbitrary integer and
		        /// in the case that it is a prime p then the integer group is the field Fp. The
		        /// user should be aware of what type of object the given modulus produces, and
		        /// thus which operations are valid.</remarks>

		        // Modulus
		        // tslint:disable-next-line: variable-name
		        var m_modulus = bytesToDigits(modulusBytes);

		        // Length of an element in digits
		        // tslint:disable-next-line: variable-name
		        var m_digitWidth = m_modulus.length;

		        // Setup numeric constants
		        // tslint:disable-next-line: variable-name
		        var m_zero = intToDigits(0, m_digitWidth);
		        // tslint:disable-next-line: variable-name
		        var m_one = intToDigits(1, m_digitWidth);

		        // Temp storage.
		        // Allocation in js is very slow, we use these temp arrays to avoid it.
		        var temp0 = createArray(m_digitWidth);
		        var temp1 = createArray(m_digitWidth);

		        // Create Montgomery multiplier object
		        var montmul = new MontgomeryMultiplier(m_modulus);

		        function createElementFromBytes(bytes) {
		            /// <summary>Create a new element object from a byte value.</summary>
		            /// <param name="bytes" type="Array">Desired element in big-endian format in an array of bytes.</param>
		            /// <returns type="integerGroupElement">An element object representing the given element.</returns>
		            var digits = bytesToDigits(bytes);

		            // Check size of the new element
		            if (cryptoMath.compareDigits(digits, this.m_modulus) >= 0) {
		                // Too many digits
		                throw new Error("The number provided is not an element of this group");
		            }

		            // expand to the group modulus length
		            normalizeDigitArray(digits, this.m_digitWidth, true);
		            return integerGroupElement(digits, this);
		        }

		        function createElementFromInteger(integer) {
		            /// <summary>Create a new element object from an integer value.</summary>
		            /// <param name="integer" type="Number" integer="true">Desired element as an integer.</param>
		            /// <returns type="integerGroupElement">An element object representing the given element.</returns>
		            var digits = intToDigits(integer, this.m_digitWidth);
		            return integerGroupElement(digits, this);
		        }

		        function createElementFromDigits(digits) {
		            /// <summary>Create a new element object from a digit array.</summary>
		            /// <param name="digits" type="Array">Desired element as a digit array.</param>
		            /// <returns type="integerGroupElement">Object initialized with the given value.</returns>
		            cryptoMath.normalizeDigitArray(digits, this.m_digitWidth, true);
		            return integerGroupElement(digits, this);
		        }

		        function equals(otherGroup) {
		            /// <summary>Return true if the given object is equivalent to this one.</summary>
		            /// <param name="otherGroup" type="IntegerGroup"/>)
		            /// <returns type="Boolean">True if the given objects are equivalent.</returns>

		            return compareDigits(this.m_modulus, otherGroup.m_modulus) === 0;
		        }

		        function add(addend1, addend2, sum) {
		            /// <summary>Add this element to another element.</summary>
		            /// <param name="addend1" type="integerGroupElement"/>
		            /// <param name="addend2" type="integerGroupElement"/>
		            /// <param name="sum" type="integerGroupElement"/>

		            var i;
		            var s = this.m_digitWidth;
		            var result = sum.m_digits;
		            cryptoMath.add(addend1.m_digits, addend2.m_digits, result);
		            var mask = (compareDigits(result, this.m_modulus) >>> 31) - 1 & DIGIT_MASK;

		            // Conditional reduction by the modulus (one subtraction, only) only if the sum>modulus in almost
		            //     constant time.
		            // The result is unmodified if the computed sum < modulus already.
		            var carry = 0;
		            for (i = 0; i < s; i += 1) {
		                carry = result[i] - (this.m_modulus[i] & mask) + carry;
		                result[i] = carry & DIGIT_MASK;
		                carry = (carry >> DIGIT_BITS);
		            }

		            result.length = s;
		        }

		        function subtract(leftElement, rightElement, outputElement) {
		            /// <summary>Subtract an element from another element.</summary>
		            /// <param name="leftElement" type="integerGroupElement"/>
		            /// <param name="rightElement" type="integerGroupElement"/>
		            /// <param name="outputElement" type="integerGroupElement"/>

		            var i, s = this.m_digitWidth;
		            var result = outputElement.m_digits;
		            var carry = cryptoMath.subtract(leftElement.m_digits, rightElement.m_digits, outputElement.m_digits);

		            // Final borrow?
		            if (carry === -1) {
		                carry = 0;
		                for (i = 0; i < s; i += 1) {
		                    carry += result[i] + this.m_modulus[i];
		                    result[i] = carry & DIGIT_MASK;
		                    carry = carry >> DIGIT_BITS;
		                }
		            }
		        }

		        function inverse(element, outputElement) {
		            /// <summary>Compute the modular inverse of the given element.</summary>
		            /// <param name="element" type="integerGroupElement">The element to be inverted.</param>
		            /// <param name="outputElement" type="integerGroupElement">Receives the inverse element.</param>
		            cryptoMath.modInv(element.m_digits, this.m_modulus, outputElement.m_digits);
		        }

		        function multiply(multiplicand, multiplier, product) {
		            /// <summary>Multiply an element by another element in the integer group.</summary>
		            /// <param name="multiplicand" type="integerGroupElement">Multiplicand.</param>
		            /// <param name="multiplier" type="integerGroupElement">Multiplier.</param>
		            /// <param name="product" type="integerGroupElement">Product reduced by the group modulus.</param>
		            /// <returns type="Array">Same as <param name="product"/>.</returns>

		            return cryptoMath.modMul(multiplicand.m_digits, multiplier.m_digits, this.m_modulus,
		                product.m_digits, temp0, temp1);
		        }

		        function modexp(valueElement, exponent, outputElement) {
		            /// <summary>Modular exponentiation in an integer group.</summary>
		            /// <param name="valueElement" type="integerGroupElement">The base input to the exponentiation.</param>
		            /// <param name="exponent" type="Array">The exponent is an unsigned integer.</param>
		            /// <param name="outputElement" type="integerGroupElement" optional="true">Output element that takes
		            //      the modular exponentiation result.</param >
		            /// <returns type="integerGroupElement">Computed result. Same as <param name="outputElement"/>
		            ///     if not null, a new object otherwise.</returns >

		            outputElement = outputElement || integerGroupElement([], this);

		            // If exponent is 0 return 1
		            if (compareDigits(exponent, m_zero) === 0) {
		                outputElement.m_digits = intToDigits(1, this.m_digitWidth);
		            } else if (compareDigits(exponent, m_one) === 0) {
		                // If exponent is 1 return valueElement
		                for (var i = 0; i < valueElement.m_digits.length; i++) {
		                    outputElement.m_digits[i] = valueElement.m_digits[i];
		                }
		                outputElement.m_digits.length = valueElement.m_digits.length;
		            } else {
		                this.montmul.modExp(
		                    valueElement.m_digits,
		                    exponent,
		                    outputElement.m_digits);
		                outputElement.m_digits.length = this.montmul.s;
		            }

		            return outputElement;
		        }

		        function integerGroupElement(digits, group) {
		            /// <summary>integerGroupElement inner class.
		            /// Create a new integer element mod n.
		            /// </summary>
		            /// <param name="digits" type="Array">
		            /// An array of digits representing the element.
		            /// </param>
		            /// <param name="group" type="IntegerGroup">
		            /// The parent group to which this element belongs.
		            /// </param>

		            // The value given in digits
		            // must be &gt;= 0 and &;lt; modulus. Note that the constructor should not be
		            // visible to the user, user should use group.createElementFromDigits(). This way we
		            // can use any digit size and endian-ness we wish internally, operating in
		            // our chosen representation until such time as the user wishes to produce
		            // a byte array as output, which will be done by calling
		            // toByteArrayUnsigned(). Note that other properties and methods are meant
		            // to be "public" of course and thus callable by the user.

		            return {
		                // Variables
		                m_digits: digits,
		                m_group: group,

		                // Functions
		                equals: function(element) {
		                    /// <summary>Compare an elements to this for equality.</summary>
		                    /// <param name="element" type="integerGroupElement">Element to compare.</param>
		                    /// <returns>True if elements are equal, false otherwise.</returns>
		                    return (compareDigits(this.m_digits, element.m_digits) === 0) &&
		                        this.m_group.equals(this.m_group, element.m_group);
		                }
		            };
		        }

		        return {
		            // Variables
		            m_modulus: m_modulus,
		            m_digitWidth: m_digitWidth,
		            montmul: montmul,

		            // Functions
		            createElementFromInteger: createElementFromInteger,
		            createElementFromBytes: createElementFromBytes,
		            createElementFromDigits: createElementFromDigits,
		            equals: equals,
		            add: add,
		            subtract: subtract,
		            multiply: multiply,
		            inverse: inverse,
		            modexp: modexp
		        };
		    }

		    return {
		        DIGIT_BITS: DIGIT_BITS,
		        DIGIT_NUM_BYTES: DIGIT_NUM_BYTES,
		        DIGIT_MASK: DIGIT_MASK,
		        DIGIT_BASE: DIGIT_BASE,
		        DIGIT_MAX: DIGIT_MAX,
		        Zero: Zero,
		        One: One,

		        normalizeDigitArray: normalizeDigitArray,
		        bytesToDigits: bytesToDigits,
		        stringToDigits: stringToDigits,
		        digitsToString: digitsToString,
		        intToDigits: intToDigits,
		        digitsToBytes: digitsToBytes,
		        isZero: isZero,
		        isEven: isEven,

		        shiftRight: shiftRight,
		        shiftLeft: shiftLeft,
		        compareDigits: compareDigits,
		        bitLength: highestSetBit,

		        fixedWindowRecode: fixedWindowRecode,
		        IntegerGroup: IntegerGroup,

		        add: add,
		        subtract: subtract,
		        multiply: multiply,
		        divRem: divRem,
		        reduce: reduce,
		        modInv: modInv,
		        modInvCT: modInvCT,
		        modExp: modExp,
		        modMul: modMul,
		        MontgomeryMultiplier: MontgomeryMultiplier,
		        gcd: gcd,

		        createArray: createArray,
		        //fetchBits: fetchBits

		        // Used by tests only
		        sequenceEqual: sequenceEqual,
		        swapEndianness: function(bytes) { return bytes.reverse(); },
		        computeBitArray: computeBitArray
		    };
		}

		var cryptoMath = cryptoMath || msrcryptoMath();

		/* commonjs-block */
		{
		    module.exports = cryptoMath;
		}
		/* end-commonjs-block */ 
	} (cryptoMath$1));

	var cryptoMathExports = cryptoMath$1.exports;
	var cryptoMath = /*@__PURE__*/getDefaultExportFromCjs(cryptoMathExports);

	(function (module, exports) {
		//*******************************************************************************
		//
		//    Copyright 2020 Microsoft
		//
		//    Licensed under the Apache License, Version 2.0 (the "License");
		//    you may not use this file except in compliance with the License.
		//    You may obtain a copy of the License at
		//
		//        http://www.apache.org/licenses/LICENSE-2.0
		//
		//    Unless required by applicable law or agreed to in writing, software
		//    distributed under the License is distributed on an "AS IS" BASIS,
		//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
		//    See the License for the specific language governing permissions and
		//    limitations under the License.
		//
		//*******************************************************************************

		/* commonjs-block */
		var cryptoMath;
		var msrcryptoUtilities;
		if(typeof commonjsRequire === "function" ) {
		    msrcryptoUtilities = requireUtilities();
		    cryptoMath = cryptoMathExports;
		} 
		/* end-commonjs-block */

		// tslint:disable: no-bitwise

		/// cryptoECC.js ==================================================================================
		/// Implementation of Elliptic Curve math routines for cryptographic applications.

		function MsrcryptoECC() {
		    /// <summary>Elliptic Curve Cryptography (ECC) functions.</summary>

		    var btd = cryptoMath.bytesToDigits;

		    var utils = msrcryptoUtilities;

		    var setterSupport = utils.setterSupport;

		    // Create an array, mimics the constructors for typed arrays.
		    function createArray(/*@dynamic*/parameter) {
		        var i, array = null;
		        if (!arguments.length || typeof arguments[0] === "number") {
		            // A number.
		            array = [];
		            for (i = 0; i < parameter; i += 1) {
		                array[i] = 0;
		            }
		        } else if (typeof arguments[0] === "object") {
		            // An array or other index-able object
		            array = [];
		            for (i = 0; i < parameter.length; i += 1) {
		                array[i] = parameter[i];
		            }
		        }
		        return array;
		    }

		    var EllipticCurveFp = function(p1, a1, b1, order, gx, gy) {
		        /// <param name="p1" type="Digits"/>
		        /// <param name="a1" type="Digits"/>
		        /// <param name="b1" type="Digits"/>
		        /// <param name="order" type="Digits"/>
		        /// <param name="gx" type="Digits"/>
		        /// <param name="gy" type="Digits"/>
		        /// <returns type="EllipticCurveFp"/>

		        var fieldStorageBitLength = p1.length;

		        var generator = EllipticCurvePointFp(this, false, gx, gy, null, false);

		        return {
		            p: p1,                  // field prime
		            a: a1,                  // Weierstrass coefficient a
		            b: b1,                  // Weierstrass coefficient b
		            order: order,           // EC group order
		            generator: generator,   // EC group generator
		            allocatePointStorage: function() {
		                return EllipticCurvePointFp(
		                    this,
		                    false,
		                    cryptoMath.intToDigits(0, fieldStorageBitLength),
		                    cryptoMath.intToDigits(0, fieldStorageBitLength)
		                );
		            },
		            createPointAtInfinity: function() {
		                return EllipticCurvePointFp(
		                    this,
		                    true,
		                    cryptoMath.intToDigits(0, fieldStorageBitLength),
		                    cryptoMath.intToDigits(0, fieldStorageBitLength)
		                );
		            }
		        };
		    };

		    var createWeierstrassCurve = function(curveData) {

		        var newCurve = new EllipticCurveFp(
		            btd(curveData.p), // P
		            btd(curveData.a), // A
		            btd(curveData.b), // B
		            btd(curveData.order), // Order
		            btd(curveData.gx), // gX
		            btd(curveData.gy)  // gy
		        );

		        newCurve.type = curveData.type;
		        newCurve.name = curveData.name;
		        newCurve.generator.curve = newCurve;

		        return newCurve;
		    };

		    var createTedCurve = function(curveData) {

		        //var btd = cryptoMath.bytesToDigits;

		        var newCurve = new EllipticCurveFp(
		            btd(curveData.p), // P
		            btd(curveData.a), // A
		            btd(curveData.d), // D
		            btd(curveData.order), // Order
		            btd(curveData.gx), // gX
		            btd(curveData.gy)  // gy
		        );

		        newCurve.type = curveData.type;

		        if (newCurve.type === 1) {
		            newCurve.d = newCurve.b.slice();
		            delete newCurve.b;
		        }

		        newCurve.rbits = curveData.info[2];
		        newCurve.name = curveData.name;
		        newCurve.generator.curve = newCurve;

		        return newCurve;
		    };

		    var EllipticCurvePointFp = function(curve, isInfinity, x, y, z, isInMontgomeryForm) {
		        /// <param name="curve" type="EllipticCurveFp"/>
		        /// <param name="isInfinity" type="Boolean"/>
		        /// <param name="x" type="Digits"/>
		        /// <param name="y" type="Digits"/>
		        /// <param name="z" type="Digits" optional="true"/>
		        /// <param name="isInMontgomeryForm" type="Boolean" optional="true"/>
		        /// <returns type="EllipticCurvePointFp"/>

		        var returnObj;

		        // 'optional' parameters
		        if (typeof z === "undefined") {
		            z = null;
		        }

		        var isAffine = z === null;

		        if (typeof isInMontgomeryForm === "undefined") {
		            isInMontgomeryForm = false;
		        }

		        function equals(/*@type(EllipticCurvePointFp)*/ellipticCurvePointFp) {
		            /// <param name="ellipticCurvePointFp" type="EllipticCurvePointFp"/>

		            // If null
		            if (!ellipticCurvePointFp) {
		                return false;
		            }

		            // Infinity == infinity
		            if (returnObj.isInfinity && ellipticCurvePointFp.isInfinity) {
		                return true;
		            }

		            // Otherwise its member-wise comparison

		            if (returnObj.z === null && ellipticCurvePointFp.z !== null) {
		                return false;
		            }

		            if (returnObj.z !== null && ellipticCurvePointFp.z === null) {
		                return false;
		            }

		            if (returnObj.z === null) {
		                return cryptoMath.compareDigits(returnObj.x, ellipticCurvePointFp.x) === 0 &&
		                    cryptoMath.compareDigits(returnObj.y, ellipticCurvePointFp.y) === 0 &&
		                    returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm;
		            }

		            return cryptoMath.compareDigits(returnObj.x, ellipticCurvePointFp.x) === 0 &&
		                cryptoMath.compareDigits(returnObj.y, ellipticCurvePointFp.y) === 0 &&
		                cryptoMath.compareDigits(returnObj.z, ellipticCurvePointFp.z) === 0 &&
		                returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm;
		        }

		        function copyTo(/*@type(EllipticCurvePointFp)*/ source, /*@type(EllipticCurvePointFp)*/ destination) {
		            /// <param name="source" type="EllipticCurvePointFp"/>
		            /// <param name="destination" type="EllipticCurvePointFp"/>

		            destination.curve = source.curve;
		            destination.x = source.x.slice();
		            destination.y = source.y.slice();

		            if (source.z !== null) {
		                destination.z = source.z.slice();
		            } else {
		                destination.z = null;
		            }

		            // tslint:disable-next-line: no-unused-expression
		            setterSupport || (destination.isAffine = source.isAffine);
		            destination.isInMontgomeryForm = source.isInMontgomeryForm;
		            destination.isInfinity = source.isInfinity;

		            if (!destination.equals(source)) {
		                throw new Error("Instances should be equal.");
		            }

		        }

		        function clone() {

		            var clonePoint = EllipticCurvePointFp(
		                returnObj.curve,
		                returnObj.isInfinity,
		                createArray(returnObj.x),
		                createArray(returnObj.y),
		                returnObj.z ? createArray(returnObj.z) : null,
		                returnObj.isInMontgomeryForm);

		            // tslint:disable-next-line: no-unused-expression
		            returnObj.ta && (clonePoint.ta = createArray(returnObj.ta));
		            // tslint:disable-next-line: no-unused-expression
		            returnObj.tb && (clonePoint.tb = createArray(returnObj.tb));

		            return clonePoint;
		        }

		        returnObj = /*@static_cast(EllipticCurvePointFp)*/ {
		            equals: function (ellipticCurvePointFp) {
		                return equals(ellipticCurvePointFp);
		            },
		            copy: function (destination) {
		                copyTo(this, destination);
		                return;
		            },
		            clone: function () {
		                return clone();
		            }
		        };

		        utils.createProperty(returnObj, "curve", curve, function () { return curve; }, function (val) { curve = val; });

		        utils.createProperty(returnObj, "x", x, function () { return x; }, function (val) { x = val; });
		        utils.createProperty(returnObj, "y", y, function () { return y; }, function (val) { y = val; });
		        utils.createProperty(returnObj, "z", z, function () { return z; }, function (val) { z = val; });

		        utils.createProperty(returnObj, "isInMontgomeryForm", isInMontgomeryForm,
		            function () { return isInMontgomeryForm; }, function (val) { isInMontgomeryForm = val; });
		        utils.createProperty(returnObj, "isInfinity", isInfinity,
		            function () { return isInfinity; }, function (val) { isInfinity = val; });
				utils.createProperty(returnObj, "isAffine", isAffine, 
		            function () { return z === null; }, function (val) { isAffine = val; });

		        return returnObj;
		    };

		    var EllipticCurveOperatorFp = function(curve) {

		        var tedCurve = curve.type === 1;

		        var fieldElementWidth = curve.p.length;

		        var montgomeryMultiplier = cryptoMath.MontgomeryMultiplier(curve.p);

		        // Pre-compute and store the montgomeryized form of A, and set our
		        // zero flag to determine whether or not we should use implementations
		        // optimized for A = 0.
		        var montgomerizedA = curve.a.slice();
		        montgomeryMultiplier.convertToMontgomeryForm(montgomerizedA);

		        var aequalsZero = cryptoMath.isZero(curve.a);

		        var one = cryptoMath.One;

		        var onemontgomery = createArray(fieldElementWidth);
		        onemontgomery[0] = 1;
		        montgomeryMultiplier.convertToMontgomeryForm(onemontgomery);

		        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(montgomeryMultiplier.m), true);

		        // Setup temp storage.
		        var temp0 = createArray(fieldElementWidth);
		        var temp1 = createArray(fieldElementWidth);
		        var temp2 = createArray(fieldElementWidth);
		        var temp3 = createArray(fieldElementWidth);
		        var temp4 = createArray(fieldElementWidth);
		        var temp5 = createArray(fieldElementWidth);
		        var temp6 = createArray(fieldElementWidth);
		        var temp7 = createArray(fieldElementWidth);
		        var swap0 = createArray(fieldElementWidth);

		        // Some additional temp storage used in point conversion routines.
		        var conversionTemp0 = createArray(fieldElementWidth);
		        var conversionTemp1 = createArray(fieldElementWidth);
		        var conversionTemp2 = createArray(fieldElementWidth);

		        function modSub(left, right, result) {
		            var resultElement = group.createElementFromInteger(0);
		            resultElement.m_digits = result;
		            group.subtract(
		                group.createElementFromDigits(left),
		                group.createElementFromDigits(right),
		                resultElement);
		        }

		        function modAdd(left, right, result) {
		            var resultElement = group.createElementFromInteger(0);
		            resultElement.m_digits = result;
		            group.add(
		                group.createElementFromDigits(left),
		                group.createElementFromDigits(right),
		                resultElement);
		        }

		        function modDivByTwo( /*@type(Digits)*/ dividend,  /*@type(Digits)*/ result) {

		            var s = dividend.length;

		            var modulus = curve.p;

		            // If dividend is odd, add modulus
		            if ((dividend[0] & 0x1) === 0x1) {
		                var carry = 0;

		                for (var i = 0; i < s; i += 1) {
		                    carry += dividend[i] + modulus[i];
		                    result[i] = carry & cryptoMath.DIGIT_MASK;
		                    carry = carry >>> cryptoMath.DIGIT_BITS;
		                }

		                // Put carry bit into position for masking in
		                carry = carry << cryptoMath.DIGIT_BITS - 1;

		                // Bit shift
		                cryptoMath.shiftRight(result, result);

		                // Mask in the carry bit
		                result[s - 1] |= carry;
		            } else {
		                // Shift directly into result
		                cryptoMath.shiftRight(dividend, result);
		            }

		        }

		        function montgomeryMultiply(left, right, result) {
		            montgomeryMultiplier.montgomeryMultiply(
		                left,
		                right,
		                result);
		        }

		        function montgomerySquare(left, result) {
		            montgomeryMultiplier.montgomeryMultiply(
		                left,
		                left,
		                result);
		        }

		        function doubleAequalsNeg3(point, outputPoint) {
		            /// <param name="point" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            // If point = infinity then outputPoint := infinity.
		            if (point.isInfinity) {
		                outputPoint.isInfinity = true;
		                return;
		            }

		            // t1 = z^2
		            montgomerySquare(point.z, temp1);

		            // t4 = zy
		            montgomeryMultiply(point.z, point.y, temp4);

		            // t2 = x + z^2
		            // t2 = x + t1
		            modAdd(point.x, temp1, temp2);

		            // t1 = x - z^2
		            // t1 = x - t1
		            modSub(point.x, temp1, temp1);

		            // Zfinal = zy
		            outputPoint.z = temp4.slice();

		            // t3 = (x + z^2)(x - z^2)
		            montgomeryMultiply(temp1, temp2, temp3);

		            // t2 = (x + z^2)(x - z^2)/2
		            modDivByTwo(temp3, temp2);

		            // t1 = alpha = 3(x + z^2)(x - z^2)/2
		            modAdd(temp3, temp2, temp1);

		            // t2 = y^2
		            montgomerySquare(point.y, temp2);

		            // t4 = alpha^2
		            montgomerySquare(temp1, temp4);

		            // t3 = beta = xy^2
		            montgomeryMultiply(point.x, temp2, temp3);

		            // t4 = alpha^2-beta
		            modSub(temp4, temp3, temp4);

		            // Xfinal = alpha^2-2beta
		            modSub(temp4, temp3, outputPoint.x);

		            // t4 = beta-Xfinal
		            modSub(temp3, outputPoint.x, temp4);

		            // t3 = y^4
		            montgomerySquare(temp2, temp3);

		            // t3 = y^4
		            montgomeryMultiply(temp1, temp4, temp2);

		            // Yfinal = alpha.(beta-Xfinal)-y^4
		            modSub(temp2, temp3, outputPoint.y);

		            // Finalize the flags on the output point.
		            outputPoint.isInfinity = false;
		            outputPoint.isInMontgomeryForm = true;
		        }

		        function doubleAequals0(point, outputPoint) {
		            /// <param name="point" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            // If point = infinity then outputPoint := infinity.
		            if (point.isInfinity) {
		                outputPoint.isInfinity = true;
		                return;
		            }

		            // 't3:=Y1^2;'
		            montgomerySquare(point.y, temp3);

		            // 't4:=X1^2;'
		            montgomerySquare(point.x, temp4);

		            // 't4:=3*t4;'
		            modAdd(temp4, temp4, temp0);
		            modAdd(temp0, temp4, temp4);

		            // 't5:=X1*t3;'
		            montgomeryMultiply(point.x, temp3, temp5);

		            // 't0:=t3^2;'
		            montgomerySquare(temp3, temp0);

		            // 't1:=t4/2;'
		            modDivByTwo(temp4, temp1);

		            // 't3:=t1^2;'
		            montgomerySquare(temp1, temp3);

		            // 'Z_out:=Y1*Z1;'
		            montgomeryMultiply(point.y, point.z, swap0);
		            for (var i = 0; i < swap0.length; i += 1) {
		                outputPoint.z[i] = swap0[i];
		            }

		            // 'X_out:=t3-2*t5;'
		            modSub(temp3, temp5, outputPoint.x);
		            modSub(outputPoint.x, temp5, outputPoint.x);

		            // 't4:=t5-X_out;'
		            modSub(temp5, outputPoint.x, temp4);

		            // 't2:=t1*t4;'
		            montgomeryMultiply(temp1, temp4, temp2);

		            // 'Y_out:=t2-t0;'
		            modSub(temp2, temp0, outputPoint.y);

		            // Finalize the flags on the output point.
		            outputPoint.isInfinity = false;
		            outputPoint.isInMontgomeryForm = true;
		        }

		        // Given a povar P on an elliptic curve, return a table of
		        // size 2^(w-2) filled with pre-computed values for
		        // P, 3P, 5P, ... Etc.
		        function generatePrecomputationTable(w, generatorPoint) {
		            /// <summary>Given a point P on an elliptic curve, return a table of
		            /// size 2^(w-2) filled with pre-computed values for
		            /// P, 3P, 5P, ... Etc.</summary>
		            /// <param name="w" type="Array">Window size</param>
		            /// <param name="generatorPoint" type="EllipticCurvePointFp"></param>
		            /// <returns type="Array">Precomputation table</returns>

		            var validationPoint = generatorPoint.clone();
		            convertToStandardForm(validationPoint);
		            if (!validatePoint(validationPoint)) {
		                throw new Error("Invalid Parameter");
		            }

		            // Create a Jacobian clone
		            var pointJac = generatorPoint.clone();
		            convertToJacobianForm(pointJac);

		            var tablePos = [generatorPoint.clone()];

		            // Q := P;
		            var qJac = pointJac.clone();

		            // Px2 = 2 * P
		            var px2 = pointJac.clone();
		            double(pointJac, px2);
		            convertToAffineForm(px2);

		            var qAff;

		            for (var i = 1; i < Math.pow(2, w - 2); i++) {

		                //Q := Q+P2;
		                mixedAdd(qJac, px2, qJac);

		                qAff = qJac.clone();
		                convertToAffineForm(qAff);

		                tablePos[i] = qAff;
		            }

		            return tablePos;
		        }

		        function double(point, outputPoint) {
		            /// <param name="point" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            if (typeof point === "undefined") {
		                throw new Error("point undefined");
		            }
		            if (typeof outputPoint === "undefined") {
		                throw new Error("outputPoint undefined");
		            }

		            //// if (!point.curve.equals(outputPoint.curve)) {
		            ////    throw new Error("point and outputPoint must be from the same curve object.");
		            //// }

		            if (point.isAffine) {
		                throw new Error("Given point was in Affine form. Use convertToJacobian() first.");
		            }

		            if (!point.isInMontgomeryForm) {
		                throw new Error("Given point must be in Montgomery form. Use montgomeryize() first.");
		            }
		            // Currently we support only two curve types, those with A=-3, and
		            // those with A=0. In the future we will implement general support.
		            // For now we switch here, assuming that the curve was validated in
		            // the constructor.
		            if (aequalsZero) {
		                doubleAequals0(point, outputPoint);
		            } else {
		                doubleAequalsNeg3(point, outputPoint);
		            }

		        }

		        function mixedDoubleAdd(jacobianPoint, affinePoint, outputPoint) {
		            /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
		            /// <param name="affinePoint" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            if (jacobianPoint.isInfinity) {
		                affinePoint.copy(outputPoint);
		                this.convertToJacobianForm(outputPoint);
		                return;
		            }

		            if (affinePoint.isInfinity) {
		                jacobianPoint.copy(outputPoint);
		                return;
		            }

		            // Ok then we do the full double and add.

		            // Note: in pseudo-code the uppercase X,Y,Z is Jacobian point, lower
		            // case x, y, z is Affine point.

		            // 't5:=Z1^ 2;'
		            montgomerySquare(jacobianPoint.z, temp5);

		            // 't6:=Z1*t5;'
		            montgomeryMultiply(jacobianPoint.z, temp5, temp6);

		            // 't4:=x2*t5;'
		            montgomeryMultiply(affinePoint.x, temp5, temp4);

		            // 't5:=y2*t6;'
		            montgomeryMultiply(affinePoint.y, temp6, temp5);

		            // 't1:=t4-X1;'
		            modSub(temp4, jacobianPoint.x, temp1);

		            // 't2:=t5-Y1;'
		            modSub(temp5, jacobianPoint.y, temp2);

		            //if t1 eq 0 then
		            if (cryptoMath.isZero(temp1)) {
		                // if t2 eq 0 then
		                if (cryptoMath.isZero(temp2)) {
		                    //  X2,Y2,Z2 := DBL(X1,Y1,Z1,prime,rr,m,RR);
		                    // return mADD(X2,Y2,Z2,x2,y2,prime,rr,m,RR);
		                    double(jacobianPoint, outputPoint);
		                    mixedAdd(outputPoint, affinePoint, outputPoint);
		                    return;
		                } else {
		                    // return X1,Y1,Z1;Z
		                    outputPoint.x = jacobianPoint.x.slice(0);
		                    outputPoint.y = jacobianPoint.y.slice(0);
		                    outputPoint.z = jacobianPoint.z.slice(0);
		                    return;
		                }
		            }

		            // 't4:=t2^2;'
		            montgomerySquare(temp2, temp4);

		            // 't6:=t1^2;'
		            montgomerySquare(temp1, temp6);

		            // 't5:=t6*X1;'
		            montgomeryMultiply(temp6, jacobianPoint.x, temp5);

		            // 't0:=t1*t6;'
		            montgomeryMultiply(temp1, temp6, temp0);

		            // 't3:=t4-2*t5;'
		            modSub(temp4, temp5, temp3);
		            modSub(temp3, temp5, temp3);

		            // 't4:=Z1*t1;'
		            montgomeryMultiply(jacobianPoint.z, temp1, temp4);

		            // 't3:=t3-t5;'
		            modSub(temp3, temp5, temp3);

		            // 't6:=t0*Y1;'
		            montgomeryMultiply(temp0, jacobianPoint.y, temp6);

		            // 't3:=t3-t0;'
		            modSub(temp3, temp0, temp3);

		            //if t3 eq 0 then
		            //    return 0,1,0;
		            //end if;
		            //var temp3isZero = cryptoMath.isZero(temp3);

		            // for (var i = 0; i < temp3.length; i++) {
		            //     if (temp3[i] !== 0) {
		            //         temp3isZero = false;
		            //         break;
		            //     }
		            // }

		            if (cryptoMath.isZero(temp3)) {
		                for (i = 0; i < outputPoint.x.length; i++) {
		                    outputPoint.x[i] = 0;
		                    outputPoint.y[i] = 0;
		                    outputPoint.z[i] = 0;
		                }
		                outputPoint.y[0] = 1;
		                return;
		            }

		            // 't1:=2*t6;'
		            modAdd(temp6, temp6, temp1);

		            // 'Zout:=t4*t3;'
		            montgomeryMultiply(temp4, temp3, outputPoint.z);

		            // 't4:=t2*t3;'
		            montgomeryMultiply(temp2, temp3, temp4);

		            // 't0:=t3^2;'
		            montgomerySquare(temp3, temp0);

		            // 't1:=t1+t4;'
		            modAdd(temp1, temp4, temp1);

		            // 't4:=t0*t5;'
		            montgomeryMultiply(temp0, temp5, temp4);

		            // 't7:=t1^2;'
		            montgomerySquare(temp1, temp7);

		            // 't4:=t0*t5;'
		            montgomeryMultiply(temp0, temp3, temp5);

		            // 'Xout:=t7-2*t4;'
		            modSub(temp7, temp4, outputPoint.x);
		            modSub(outputPoint.x, temp4, outputPoint.x);

		            // 'Xout:=Xout-t5;'
		            modSub(outputPoint.x, temp5, outputPoint.x);

		            // 't3:=Xout-t4;'
		            modSub(outputPoint.x, temp4, temp3);

		            // 't0:=t5*t6;'
		            montgomeryMultiply(temp5, temp6, temp0);

		            // 't4:=t1*t3;'
		            montgomeryMultiply(temp1, temp3, temp4);

		            // 'Yout:=t4-t0;'
		            modSub(temp4, temp0, outputPoint.y);

		            outputPoint.isInfinity = false;
		            outputPoint.isInMontgomeryForm = true;

		        }

		        function mixedAdd(jacobianPoint, affinePoint, outputPoint) {
		            /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
		            /// <param name="affinePoint" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            if (jacobianPoint === null) {
		                throw new Error("jacobianPoint");
		            }

		            if (affinePoint === null) {
		                throw new Error("affinePoint");
		            }

		            if (outputPoint === null) {
		                throw new Error("outputPoint");
		            }

		            if (jacobianPoint.curve !== affinePoint.curve ||
		                jacobianPoint.curve !== outputPoint.curve) {
		                throw new Error("All points must be from the same curve object.");
		            }

		            if (jacobianPoint.isAffine) {
		                throw new Error(
		                    "Given jacobianPoint was in Affine form. Use ConvertToJacobian()\
	                     before calling DoubleJacobianAddAffinePoints().");
		            }

		            if (!affinePoint.isAffine) {
		                throw new Error(
		                    "Given affinePoint was in Jacobian form. Use ConvertToAffine() before \
	                     calling DoubleJacobianAddAffinePoints().");
		            }

		            if (outputPoint.isAffine) {
		                throw new Error(
		                    "Given jacobianPoint was in Jacobian form. Use ConvertToJacobian() before \
	                     calling DoubleJacobianAddAffinePoints().");
		            }

		            if (!jacobianPoint.isInMontgomeryForm) {
		                throw new Error("Jacobian point must be in Montgomery form");
		            }

		            if (!affinePoint.isInMontgomeryForm) {
		                throw new Error("Affine point must be in Montgomery form");
		            }

		            if (jacobianPoint.isInfinity) {
		                affinePoint.copy(outputPoint);
		                this.convertToJacobianForm(outputPoint);
		                return;
		            }

		            if (affinePoint.isInfinity) {
		                jacobianPoint.copy(outputPoint);
		                return;
		            }

		            // Ok then we do the full double and add.

		            // Note: in pseudo-code the uppercase X1,Y1,Z1 is Jacobian point,
		            // lower case x2, y2, z2 is Affine point.

		            //if (X1 eq 0) and (Y1 eq 1) and (Z1 eq 0) then
		            //    z2 := ToMontgomery(1,prime,rr,m,RR);
		            //    return x2,y2;
		            //end if;
		            //if (x2 eq 0) and (y2 eq 1) then
		            //    return X1,Y1,Z1;
		            //end if;

		            // 't1 := Z1^2;'.
		            montgomerySquare(jacobianPoint.z, temp1);

		            // 't2 := t1 * Z1;'
		            montgomeryMultiply(temp1, jacobianPoint.z, temp2);

		            // 't3 := t1 * x2;'
		            montgomeryMultiply(temp1, affinePoint.x, temp3);

		            // 't4 := t2 * y2;'
		            montgomeryMultiply(temp2, affinePoint.y, temp4);

		            // 't1 := t3 - X1;'
		            modSub(temp3, jacobianPoint.x, temp1);

		            // 't2 := t4 - Y1;'
		            modSub(temp4, jacobianPoint.y, temp2);

		            // If t1 != 0 then
		            var i;
		            for (i = 0; i < temp1.length; i += 1) {
		                if (temp1[i] !== 0) {

		                    // 'Zout := Z1 * t1;'
		                    montgomeryMultiply(jacobianPoint.z, temp1, temp0);
		                    for (var j = 0; j < fieldElementWidth; j += 1) {
		                        outputPoint.z[j] = temp0[j];
		                    }

		                    // 't3 := t1^2;'
		                    montgomerySquare(temp1, temp3);

		                    // 't4 := t3 * t1;'
		                    montgomeryMultiply(temp3, temp1, temp4);

		                    // 't5 := t3 * X1;'
		                    montgomeryMultiply(temp3, jacobianPoint.x, temp5);

		                    // 't1 := 2 * t5;'
		                    modAdd(temp5, temp5, temp1);

		                    // 'Xout := t2^2;'
		                    montgomerySquare(temp2, outputPoint.x);

		                    // 'Xout := Xout - t1;'
		                    modSub(outputPoint.x, temp1, outputPoint.x);

		                    // 'Xout := Xout - t4;'
		                    modSub(outputPoint.x, temp4, outputPoint.x);

		                    // 't3 := t5 - Xout;'
		                    modSub(temp5, outputPoint.x, temp3);

		                    // 't5 := t3*t2;'
		                    montgomeryMultiply(temp2, temp3, temp5);

		                    // 't6 := t4*Y1;'
		                    montgomeryMultiply(jacobianPoint.y, temp4, temp6);

		                    // 'Yout := t5-t6;'
		                    modSub(temp5, temp6, outputPoint.y);

		                    outputPoint.isInfinity = false;
		                    outputPoint.isInMontgomeryForm = true;

		                    return;
		                }
		            }

		            // Else if T2 != 0 then
		            for (i = 0; i < temp2.length; i += 1) {
		                if (temp2[i] !== 0) {
		                    //         Return infinity
		                    outputPoint.isInfinity = true;
		                    outputPoint.isInMontgomeryForm = true;
		                    return;
		                }
		            }
		            // Else use DBL routine to return 2(x2, y2, 1)
		            affinePoint.copy(outputPoint);
		            this.convertToJacobianForm(outputPoint);
		            this.double(outputPoint, outputPoint);
		            outputPoint.isInMontgomeryForm = true;

		        }

		        function scalarMultiply(k, point, outputPoint, multiplyBy4) {
		            /// <param name="k" type="Digits"/>
		            /// <param name="point" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            // Special case for the point at infinity or k == 0
		            if (point.isInfinity || cryptoMath.isZero(k)) {
		                outputPoint.isInfinity = true;
		                return;
		            }

		            // Runtime check for 1 <= k < order to ensure we don't get hit by
		            // subgroup attacks. Since k is a FixedWidth it is a positive integer
		            // and we already checked for zero above. So it must be >= 1 already.
		            if (cryptoMath.compareDigits(k, curve.order) >= 0) {
		                throw new Error("The scalar k must be in the range 1 <= k < order.");
		            }

		            // copy k so we can modify it without modifying the passed in array.
		            k = k.slice();

		            if (point.curve.type === 1 /* TED */) {

		                var pointIsEP = typeof point.ta !== "undefined";

		                if (!pointIsEP) {
		                    convertToExtendedProjective(point);
		                }

		                scalarMultiplyTed(k, point, outputPoint, multiplyBy4);

		                // Convert the points back to standard if they arrived that way.
		                if (!pointIsEP) {
		                    normalizeTed(point);
		                }

		            } else {

		                var pointIsMF = point.isInMontgomeryForm,
		                    outputIsMF = outputPoint.isInMontgomeryForm,
		                    outputIsAffine = outputPoint.isAffine;

		                // Convert parameters to Montgomery form if not already.
		                if (!pointIsMF) {
		                    convertToMontgomeryForm(point);
		                }

		                if (!outputIsMF) {
		                    convertToMontgomeryForm(outputPoint);
		                }

		                scalarMultiplyW(k, point, outputPoint);

		                // outputPoint returns as Jacobian - convert back to original state.
		                if (outputIsAffine) {
		                    convertToAffineForm(outputPoint);
		                }

		                // Convert the points back to standard if they arrived that way.
		                if (!pointIsMF) {
		                    convertToStandardForm(point);
		                }

		                if (!outputIsMF) {
		                    convertToStandardForm(outputPoint);
		                }
		            }

		            return;

		        }

		        function scalarMultiplyW(k, point, outputPoint) {
		            /// <param name="k" type="Digits"/>
		            /// <param name="point" type="EllipticCurvePointFp"/>
		            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

		            // The point should be in Montgomery form.
		            var validationPoint = point.clone();
		            convertToStandardForm(validationPoint);

		            if (!validatePoint(validationPoint)) {
		                throw new Error("Invalid Parameters.");
		            }

		            var odd = k[0] & 1,
		                tempk = [];

		            // If (odd) then k = temp else k = k
		            modSub(point.curve.order, k, tempk);
		            for (i = 0; i < k.length; i++) {
		                k[i] = odd - 1 & (k[i] ^ tempk[i]) ^ k[i];
		            }

		            // Change w based on the size of the digits,
		            // 5 is good for 256 bits, use 6 for bigger sizes.
		            var w = fieldElementWidth <= 8 ? 5 : 6;
		            var m = point.curve.p.length * cryptoMath.DIGIT_BITS;
		            var t = Math.ceil(m / (w - 1));

		            var kDigits = cryptoMath.fixedWindowRecode(k, w, t);

		            var Tm = generatePrecomputationTable(w, point);

		            var position =
		                Math.floor(Math.abs(kDigits[t]) - 1) / 2;

		            var Q = Tm[position].clone();
		            convertToJacobianForm(Q);

		            for (var i = t - 1; i >= 0; i--) {

		                for (var j = 0; j < w - 2; j++) {
		                    double(Q, Q);
		                }

		                position = Math.floor((Math.abs(kDigits[i]) - 1) / 2);

		                var L = tableLookupW(Tm, position);

		                // if (kDigits[i] < 0) negate(L) - constant-time
		                //modSub(L.curve.p, L.y, [tempk, L.y][kDigits[i] >>> 31]);
		                modSub(L.curve.p, L.y, tempk);
		                var mask = -(kDigits[i] >>> 31);
		                for (var n = 0; n < L.y.length; n++) {
		                    L.y[n] = (L.y[n] & ~mask) | (tempk[n] & mask);
		                }

		                mixedDoubleAdd(Q, L, Q);

		            }

		            // if k is even, negate Q
		            modSub(point.curve.p, Q.y, tempk);
		            for (i = 0; i < Q.y.length; i++) {
		                Q.y[i] = odd - 1 & (Q.y[i] ^ tempk[i]) ^ Q.y[i];
		            }

		            Q.copy(outputPoint);

		            return;

		        }

		        function tableLookupW(table, index) {

		            var mask,
		                L;

		            for (var i = 0; i < table.length; i++) {
		                mask = +(i === index);
		                L = [L, table[i].clone()][mask];
		            }

		            return L;
		        }

		        function negate(point, outputPoint) {
		            /// <param name="point" type="EllipticCurvePointFp">Input point to negate.</param>
		            /// <param name="outputPoint" type="EllipticCurvePointFp">(x, p - y).</param>

		            if (point !== outputPoint) {
		                point.copy(outputPoint);
		            }
		            modSub(point.curve.p, point.y, outputPoint.y);
		        }

		        function convertToMontgomeryForm(point) {
		            /// <param name="point" type="EllipticCurvePointFp"/>

		            if (point.isInMontgomeryForm) {
		                throw new Error("The given point is already in Montgomery form.");
		            }

		            if (!point.isInfinity) {
		                montgomeryMultiplier.convertToMontgomeryForm(point.x);
		                montgomeryMultiplier.convertToMontgomeryForm(point.y);

		                if (point.z !== null) {
		                    montgomeryMultiplier.convertToMontgomeryForm(point.z);
		                }

		                if (typeof point.ta !== "undefined") {
		                    montgomeryMultiplier.convertToMontgomeryForm(point.ta);
		                    montgomeryMultiplier.convertToMontgomeryForm(point.tb);
		                }
		            }

		            point.isInMontgomeryForm = true;
		        }

		        function convertToStandardForm(point) {
		            /// <param name="point" type="EllipticCurvePointFp"/>

		            if (!point.isInMontgomeryForm) {
		                throw new Error("The given point is not in montgomery form.");
		            }

		            if (!point.isInfinity) {
		                montgomeryMultiplier.convertToStandardForm(point.x);
		                montgomeryMultiplier.convertToStandardForm(point.y);
		                if (point.z !== null) {
		                    montgomeryMultiplier.convertToStandardForm(point.z);
		                }
		                if (typeof point.ta !== "undefined") {
		                    montgomeryMultiplier.convertToStandardForm(point.ta);
		                    montgomeryMultiplier.convertToStandardForm(point.tb);
		                }
		            }

		            point.isInMontgomeryForm = false;

		        }

		        function convertToAffineForm(point) {
		            /// <param name="point" type="EllipticCurvePointFp"/>

		            if (point.isInfinity) {
		                point.z = null;
		                // tslint:disable-next-line: no-unused-expression
		                setterSupport || (point.isAffine = true);
		                return;
		            }

		            // DETERMINE 1/Z IN MONTGOMERY FORM --------------------------------

		            // Call out to the basic inversion function, not the one in this class.
		            cryptoMath.modInv(point.z, curve.p, conversionTemp2, true);

		            if (point.isInMontgomeryForm) {
		                montgomeryMultiply(conversionTemp2, montgomeryMultiplier.rCubedModm, conversionTemp1);
		                var swap = conversionTemp2;
		                conversionTemp2 = conversionTemp1;
		                conversionTemp1 = swap;
		            }

		            // CONVERT TO AFFINE COORDS ----------------------------------------

		            // 'temp0 <- 1/z^2'
		            montgomerySquare(conversionTemp2, conversionTemp0);

		            // Compute point.x = x / z^2 mod p
		            // NOTE: We cannot output directly to the X digit array since it is
		            // used for input to the multiplication routine, so we output to temp1
		            // and copy.
		            montgomeryMultiply(point.x, conversionTemp0, conversionTemp1);
		            for (var i = 0; i < fieldElementWidth; i += 1) {
		                point.x[i] = conversionTemp1[i];
		            }

		            // Compute point.y = y / z^3 mod p
		            // temp1 <- y * 1/z^2.
		            montgomeryMultiply(point.y, conversionTemp0, conversionTemp1);
		            // 'y <- temp1 * temp2 (which == 1/z)'
		            montgomeryMultiply(conversionTemp1, conversionTemp2, point.y);

		            // Finally, point.z = z / z mod p = 1
		            // We use z = NULL for this case to make detecting Jacobian form
		            // faster (otherwise we would have to scan the entire Z digit array).
		            point.z = null;

		            delete point.ta;
		            delete point.tb;

		            // tslint:disable-next-line: no-unused-expression
		            setterSupport || (point.isAffine = true);
		        }

		        function convertToJacobianForm(point) {
		            /// <param name="point" type="EllipticCurvePointFp"/>

		            if (!point.isAffine) {
		                throw new Error("The given point is not in Affine form.");
		            }

		            // tslint:disable-next-line: no-unused-expression
		            setterSupport || (point.isAffine = false);

		            var clonedDigits,
		                i,
		                zOne = point.isInMontgomeryForm ? onemontgomery : one;

		            clonedDigits = createArray(zOne.length);
		            for (i = 0; i < zOne.length; i += 1) {
		                clonedDigits[i] = zOne[i];
		            }

		            point.z = clonedDigits;

		            return;
		        }

		        function validatePoint(point) {
		            /// <summary>
		            /// Point validation
		            //  Check if point P=(x,y) lies on the curve and if x,y are in [0, p-1]
		            /// </summary>

		            if (point.isInfinity) {
		                return false;
		            }

		            // Does P lie on the curve?
		            cryptoMath.modMul(point.y, point.y, point.curve.p, temp1);

		            cryptoMath.modMul(point.x, point.x, point.curve.p, temp2);
		            cryptoMath.modMul(point.x, temp2, point.curve.p, temp3);
		            modAdd(temp3, point.curve.b, temp2);
		            cryptoMath.modMul(point.x, point.curve.a, point.curve.p, temp3);
		            modAdd(temp2, temp3, temp2);
		            modSub(temp1, temp2, temp1);

		            if (cryptoMath.isZero(temp1) === false) {
		                return false;
		            }

		            return true;
		        }

		        /// Ted functions

		        function validatePointTed(point) {

		            if (point.ta) {
		                point = point.clone();
		                normalizeTed(point);
		            }

		            // Does P lie on the curve?
		            cryptoMath.modMul(point.y, point.y, point.curve.p, temp3);
		            cryptoMath.modMul(point.x, point.x, point.curve.p, temp2);

		            cryptoMath.add(temp2, temp3, temp1);
		            cryptoMath.reduce(temp4, point.curve.p, temp4);

		            cryptoMath.modMul(temp2, temp3, point.curve.p, temp4);
		            cryptoMath.modMul(point.curve.d, temp4, point.curve.p, temp3);

		            cryptoMath.add(temp3, [1], temp2);
		            cryptoMath.reduce(temp2, point.curve.p, temp2);

		            cryptoMath.subtract(temp1, temp2, temp1);

		            if (cryptoMath.isZero(temp1) === false) {
		                cryptoMath.reduce(temp1, point.curve.p, temp1);
		                if (cryptoMath.isZero(temp1) === false) {
		                    return false;
		                }
		            }

		            return true;
		        }

		        function generatePrecomputationTableTed(npoints, point) {

		            // Precomputation function, points are stored using representation (X,Y,Z,dT)
		            // Twisted Edwards a=1 curve

		            var Q = point.clone(),
		                P2 = Q.clone(),
		                T = [];

		            // Generating P2 = 2(X1,Y1,Z1,T1a,T1b) -> (XP2,YP2,ZP2,d*TP2) and T[0] = P = (X1,Y1,Z1,T1a,T1b)
		            T[0] = convert_R1_to_R2(point);
		            doubleTed(Q, Q);
		            P2 = convert_R1_to_R2(Q);
		            Q = point.clone();

		            for (var i = 1; i < npoints; i++) {
		                // T[i] = 2P+T[i-1] = (2*i+1)P = (XP2,Y2P,ZP2,d*TP2) + (X_(2*i-1), Y_(2*i-1), Z_(2*i-1), Ta_(2*i-1),
		                // Tb_(2 * i - 1)) = (X_(2 * i + 1), Y_(2 * i + 1), Z_(2 * i + 1), d * T_(2 * i + 1))
		                addTedExtended(P2, Q, Q);
		                T[i] = convert_R1_to_R2(Q);
		            }

		            return T;
		        }

		        function convertToExtendedProjective(affinePoint) {
		            affinePoint.ta = affinePoint.x.slice();
		            affinePoint.tb = affinePoint.y.slice();
		            affinePoint.z = [1];
		        }

		        function scalarMultiplyTed(k, point, outputPoint, multiplyBy4) {

		            if (!validatePointTed(point)) {
		                throw new Error("Invalid Parameter");
		            }

		            var rbits = point.curve.rbits;
		            multiplyBy4 = typeof multiplyBy4 === "undefined" ? true : multiplyBy4;

		            var w = fieldElementWidth <= 8 ? 5 : 6;

		            var t = Math.floor((rbits + (w - 2)) / (w - 1));
		            var i, j;

		            // copy k so we can modify it without modifying the passed in array.
		            k = k.slice();

		            var T = point.clone();

		            convertToExtendedProjective(T);

		            if (multiplyBy4) {
		                doubleTed(T, T);
		                doubleTed(T, T);
		            }

		            var precomputationTable = generatePrecomputationTableTed(1 << w - 2, T);

		            var odd = k[0] & 1,
		                tempk = [];

		            // If (odd) then k = temp else k = k
		            modSub(point.curve.order, k, tempk);
		            for (i = 0; i < k.length; i++) {
		                k[i] = odd - 1 & (k[i] ^ tempk[i]) ^ k[i];
		            }

		            var kDigits = cryptoMath.fixedWindowRecode(k, w, t);

		            var position =
		                Math.floor(Math.abs(kDigits[t]) - 1) / 2;

		            var R = precomputationTable[position];

		            T.x = R.x.slice();
		            T.y = R.y.slice();
		            T.z = R.z.slice();

		            for (i = t - 1; i >= 0; i--) {

		                for (j = 0; j < w - 1; j++) {
		                    doubleTed(T, T);
		                }

		                position = Math.floor((Math.abs(kDigits[i]) - 1) / 2);

		                var L = tableLookupTed(precomputationTable, position);

		                // subtract if k is negative - constant time
		                // modSub(point.curve.p, L.x, [tempk, L.x][kisNeg]);
		                // modSub(point.curve.p, L.td, [tempk, L.td][kisNeg]);

		                var mask = -(kDigits[i] >>> 31);

		                modSub(point.curve.p, L.x, tempk);
		                for (var m = 0; m < L.x.length; m++) {
		                    L.x[m] = (L.x[m] & ~mask) | (tempk[m] & mask);
		                }

		                modSub(point.curve.p, L.td, tempk);
		                for (m = 0; m < L.td.length; m++) {
		                    L.td[m] = (L.td[m] & ~mask) | (tempk[m] & mask);
		                }

		                addTedExtended(L, T, T);
		            }

		            // If (odd) then T.x = temp else T.x = T.x
		            modSub(point.curve.p, T.x, tempk);
		            for (i = 0; i < T.x.length; i++) {
		                T.x[i] = odd - 1 & (T.x[i] ^ tempk[i]) ^ T.x[i];
		            }

		            normalizeTed(T);

		            outputPoint.x = T.x.slice();
		            outputPoint.y = T.y.slice();

		            return;

		        }

		        function tableLookupTed(table, index) {

		            var pos = (index + 1) % table.length;

		            for (var i = 0; i < table.length; i++) {
		                var L = {
		                    x: table[pos].x.slice(),
		                    y: table[pos].y.slice(),
		                    z: table[pos].z.slice(),
		                    td: table[pos].td.slice()
		                };
		                pos = (pos + 1) % table.length;
		            }

		            return L;
		        }

		        function normalizeTed(point) {

		            cryptoMath.modInv(point.z, curve.p, conversionTemp2, true);

		            cryptoMath.modMul(point.x, conversionTemp2, curve.p, point.x);

		            cryptoMath.modMul(point.y, conversionTemp2, curve.p, point.y);

		            delete point.ta;
		            delete point.tb;

		            point.z = null;

		            return;
		        }

		        function doubleTed(point, outputPoint) {

		            if (typeof point.ta === "undefined") {
		                throw new Error("Point should be in Extended Projective form.");
		            }

		            // t0 = x1^2
		            cryptoMath.modMul(point.x, point.x, point.curve.p, temp0);

		            // t1 = y1^2
		            cryptoMath.modMul(point.y, point.y, point.curve.p, temp1);

		            // Ta = z1^2
		            cryptoMath.modMul(point.z, point.z, point.curve.p, point.ta);
		            // (new) Tbfinal = Y1^2-X1^2
		            modSub(temp1, temp0, outputPoint.tb);
		            //(new) t0 = X1^2+Y1^2
		            modAdd(temp0, temp1, temp0);

		            //(ok) Ta = 2z1^2
		            modAdd(point.ta, point.ta, point.ta);

		            // (ok) y = 2y1
		            modAdd(point.y, point.y, point.y);

		            // (new) t1 = 2z1^2-(X1^2+Y1^2)
		            modSub(point.ta, temp0, temp1);

		            // Tafinal = 2x1y1
		            cryptoMath.modMul(point.x, point.y, point.curve.p, outputPoint.ta);

		            // Yfinal = (x1^2+y1^2)(y1^2-x1^2)
		            cryptoMath.modMul(temp0, outputPoint.tb, point.curve.p, outputPoint.y);

		            // Xfinal = 2x1y1[2z1^2-(y1^2-x1^2)]
		            cryptoMath.modMul(temp1, outputPoint.ta, point.curve.p, outputPoint.x);

		            // Zfinal = (y1^2-x1^2)[2z1^2-(y1^2-x1^2)]
		            cryptoMath.modMul(temp0, temp1, point.curve.p, outputPoint.z);

		            return;
		        }

		        function addTed(point1 /*Q*/, point2 /*P*/, outputPoint) {

		            // var modulus = point1.curve.p;
		            // var temp1 = [];

		            if (typeof point1.ta === "undefined") {
		                throw new Error("Point1 should be in Extended Projective form.");
		            }

		            if (typeof point2.ta === "undefined") {
		                throw new Error("Point2 should be in Extended Projective form.");
		            }
		            var qq = convert_R1_to_R2(point1);

		            addTedExtended(qq, point2, outputPoint);

		            return;
		        }

		        function convert_R1_to_R2(point) {

		            // tslint:disable-next-line: no-shadowed-variable
		            var curve = point.curve,
		                modulus = curve.p,
		                qq = {
		                    x: point.x.slice(),
		                    y: point.y.slice(),
		                    z: point.z.slice(),
		                    td: [],
		                    curve: point.curve
		                };

		            cryptoMath.modMul(point.ta, point.tb, modulus, conversionTemp0);

		            cryptoMath.modMul(conversionTemp0, curve.d, modulus, qq.td);

		            return qq;
		        }

		        function addTedExtended(qq /*Q*/, point2 /*P*/, outputPoint) {

		            // Complete point addition P = P+Q, including the cases P!=Q, P=Q, P=-Q, P=neutral and Q=neutral
		            // Twisted Edwards a=1 curve
		            // Inputs: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted
		            //             Edwards coordinates(X1: Y1: Z1: T1)
		            //         Q = (X2,Y2,Z2,dT2), corresponding to extended twisted Edwards coordinates
		            //             (X2: Y2: Z2: T2)
		            // Output: P = (X1,Y1,Z1,Ta,Tb), where T1 = Ta*Tb, corresponding to extended twisted
		            //             Edwards coordinates(X1: Y1: Z1: T1)

		            var cm = cryptoMath;
		            var modulus = point2.curve.p;

		            temp1 = []; temp2 = []; temp3 = [];

		            //FP_MUL(P->Z, Q->Z, t3);             // t3 = Z1*Z2
		            cm.modMul(point2.z, qq.z, modulus, temp3);

		            //FP_MUL(P->Ta, P->Tb, t1);           // t1 = T1
		            cm.modMul(point2.ta, point2.tb, modulus, temp1);

		            //FP_ADD(P->X, P->Y, P->Ta);          // Ta = (X1+Y1)
		            modAdd(point2.x, point2.y, point2.ta);

		            //FP_MUL(t1, Q->Td, t2);              // t2 = dT1*T2
		            cm.modMul(temp1, qq.td, modulus, temp2);

		            //FP_ADD(Q->X, Q->Y, P->Tb);          // Tb = (X2+Y2)
		            modAdd(qq.x, qq.y, point2.tb);

		            //FP_SUB(t3, t2, t1);                 // t1 = theta
		            modSub(temp3, temp2, temp1);

		            //FP_ADD(t3, t2, t3);                 // t3 = alpha
		            modAdd(temp3, temp2, temp3);

		            //FP_MUL(P->Ta, P->Tb, t2);           // t2 = (X1+Y1)(X2+Y2)
		            cm.modMul(point2.ta, point2.tb, modulus, temp2);

		            //FP_MUL(P->X, Q->X, P->Z);           // Z = X1*X2
		            cm.modMul(point2.x, qq.x, modulus, point2.z);

		            //FP_MUL(P->Y, Q->Y, P->X);           // X = Y1*Y2
		            cm.modMul(point2.y, qq.y, modulus, point2.x);

		            //FP_SUB(t2, P->Z, t2);
		            modSub(temp2, point2.z, temp2);

		            //FP_SUB(P->X, P->Z, P->Ta);          // Tafinal = omega = Y1*Y2-X1*X2
		            modSub(point2.x, point2.z, outputPoint.ta);

		            //FP_SUB(t2, P->X, P->Tb);            // Tbfinal = beta = (X1+Y1)(X2+Y2)-X1*X2-Y1*Y2
		            modSub(temp2, point2.x, outputPoint.tb);

		            //FP_MUL(P->Ta, t3, P->Y);            // Yfinal = alpha*omega
		            cm.modMul(outputPoint.ta, temp3, modulus, outputPoint.y);

		            //FP_MUL(P->Tb, t1, P->X);            // Xfinal = beta*theta
		            cm.modMul(outputPoint.tb, temp1, modulus, outputPoint.x);

		            //FP_MUL(t3, t1, P->Z);               // Zfinal = theta*alpha
		            cm.modMul(temp3, temp1, modulus, outputPoint.z);

		            return;
		        }

		        function convertTedToWeierstrass(tedPoint, wPoint) {
		            /// <summary></summary>
		            /// <param name="tedPoint" type=""></param>
		            /// <param name="outputPoint" type=""></param>

		            var a = tedPoint.curve.a.slice(),
		                d = tedPoint.curve.d.slice(),
		                p = tedPoint.curve.p,
		                modMul = cryptoMath.modMul,
		                // tslint:disable-next-line: no-shadowed-variable
		                modInv = cryptoMath.modInv;

		            // t1 = 5
		            temp1 = [5];

		            // t2 = 5a
		            modMul(a, temp1, p, temp2);

		            // t2 = 5a-d
		            modSub(temp2, d, temp2);

		            // t3 = 5d
		            modMul(d, temp1, p, temp3);

		            // t1 = a-5d
		            modSub(a, temp3, temp1);

		            // t3 = yTE*(a-5d)
		            modMul(tedPoint.y, temp1, p, temp3);

		            // t2 = (5a-d) + yTE*(a-5d)
		            modAdd(temp3, temp2, temp2);

		            // t1 = 1
		            temp1 = [1];

		            // t3 = 1-yTE
		            modSub(temp1, tedPoint.y, temp3);

		            // t1 = 12
		            temp1 = [12];

		            // t4 = 12(1-yTE)
		            modMul(temp1, temp3, p, temp4);

		            // t4 = 1/12(1-yTE)
		            modInv(temp4, p, temp4, true);

		            // t1 = xTE*(1-yTE)
		            modMul(tedPoint.x, temp3, p, temp1);

		            // t3 = 2xTE*(1-yTE)
		            modAdd(temp1, temp1, temp3);

		            // t3 = 4xTE*(1-yTE)
		            modAdd(temp3, temp3, temp3);

		            // t3 = 1/4xTE*(1-yTE)
		            modInv(temp3, p, temp3, true);

		            // Xfinal = ((5a-d) + yTE*(a-5d))/12(1-yTE)
		            modMul(temp4, temp2, p, wPoint.x);

		            // t1 = 1
		            temp1 = [1];

		            // t1 = yTE+1
		            modAdd(tedPoint.y, temp1, temp1);

		            // t2 = a-d
		            modSub(a, d, temp2);

		            // t4 = (a-d)*(yTE+1)
		            modMul(temp1, temp2, p, temp4);

		            // Yfinal = ((a-d)*(yTE+1))/4xTE*(1-yTE)
		            modMul(temp4, temp3, p, wPoint.y);

		            return;
		        }

		        function convertWeierstrassToTed(wPoint, tedPoint) {

		            var a = tedPoint.curve.a.slice(),
		                d = tedPoint.curve.d.slice(),
		                p = tedPoint.curve.p,
		                modMul = cryptoMath.modMul,
		                // tslint:disable-next-line: no-shadowed-variable
		                modInv = cryptoMath.modInv;

		            modAdd(wPoint.x, wPoint.x, temp1);

		            modAdd(wPoint.x, temp1, temp1);

		            // t1 = 6xW
		            modAdd(temp1, temp1, temp1);

		            // t2 = 6xW - a
		            modSub(temp1, a, temp2);

		            // t2 = 6xW - a - d
		            modSub(temp2, d, temp2);

		            modAdd(wPoint.y, wPoint.y, temp3);

		            modAdd(wPoint.y, temp3, temp3);

		            // t3 = 6yW
		            modAdd(temp3, temp3, temp3);

		            // t3 = 1/6yW
		            modInv(temp3, p, temp3, true);

		            // Xfinal = (6xW - a - d)/6yW
		            modMul(temp2, temp3, p, tedPoint.x);

		            // t1 = 12xW
		            modAdd(temp1, temp1, temp1);

		            // t2 = 12xW + d
		            modAdd(temp1, d, temp2);

		            // t1 = 12xW + a
		            modAdd(temp1, a, temp1);

		            modAdd(a, a, temp3);

		            // t2 = 12xW + d - 2a
		            modSub(temp2, temp3, temp2);

		            // t2 = 12xW + d - 4a
		            modSub(temp2, temp3, temp2);

		            // t2 = 12xW + d - 5a
		            modSub(temp2, a, temp2);

		            modAdd(d, d, temp3);

		            // t1 = 12xW + a - 2d
		            modSub(temp1, temp3, temp1);

		            // t1 = 12xW + a - 4d
		            modSub(temp1, temp3, temp1);

		            // t1 = 12xW + a - 5d
		            modSub(temp1, d, temp1);

		            // t1 = 1/(12xW + a - 5d)
		            modInv(temp1, p, temp1, true);

		            // Yfinal = (12xW + d - 5a)/(12xW + a - 5d)
		            modMul(temp1, temp2, p, tedPoint.y);

		            return;
		        }

		        var methods = {

		            convertToMontgomeryForm: convertToMontgomeryForm,

		            convertToStandardForm: convertToStandardForm,

		            convertToAffineForm: convertToAffineForm,

		            convertToJacobianForm: convertToJacobianForm,

		            // For tests
		            generatePrecomputationTable: function(w, generatorPoint) {
		                /// <param name="w" type="Number"/>
		                /// <param name="generatorPoint" type="EllipticCurvePointFp"/>

		                return generatePrecomputationTable(w, generatorPoint);
		            }

		        };

		        if (tedCurve) {

		            methods.double = doubleTed;
		            methods.add = addTed;
		            methods.scalarMultiply = scalarMultiply;
		            methods.normalize = normalizeTed;
		            methods.convertToExtendedProjective = convertToExtendedProjective;
		            methods.convertTedToWeierstrass = convertTedToWeierstrass;
		            methods.convertWeierstrassToTed = convertWeierstrassToTed;
		            methods.validatePoint = validatePointTed;
		            methods.generatePrecomputationTable = function(w, generatorPoint) {
		                /// <param name="w" type="Number"/>
		                /// <param name="generatorPoint" type="EllipticCurvePointFp"/>

		                return generatePrecomputationTableTed(w, generatorPoint);
		            };
		        } else {

		            methods.double = double;
		            methods.mixedDoubleAdd = mixedDoubleAdd;
		            methods.mixedAdd = mixedAdd;
		            methods.scalarMultiply = scalarMultiply;
		            methods.negate = negate;
		            methods.validatePoint = validatePoint;
		        }

		        return methods;

		    };

		    var sec1EncodingFp = function() {
		        return {
		            encodePoint: function(/*@type(EllipticCurvePointFp)*/ point) {
		                /// <summary>Encode an EC point without compression.
		                /// This function encodes a given points into a bytes array containing 0x04 | X | Y, where
		                ///      X and Y are big endian bytes of x and y coordinates.</summary >
		                /// <param name="point" type="EllipticCurvePointFp">Input EC point to encode.</param>
		                /// <returns type="Array">A bytes array containing 0x04 | X | Y, where X and Y are big endian
		                ///     encoded x and y coordinates.</returns >

		                if (!point) {
		                    throw new Error("point");
		                }

		                if (!point.isAffine) {
		                    throw new Error("Point must be in affine form.");
		                }

		                if (point.isInMontgomeryForm) {
		                    throw new Error("Point must not be in Montgomery form.");
		                }

		                if (point.isInfinity) {
		                    return createArray(1); /* [0] */
		                } else {
		                    var xOctetString = cryptoMath.digitsToBytes(point.x);
		                    var yOctetString = cryptoMath.digitsToBytes(point.y);
		                    var pOctetString = cryptoMath.digitsToBytes(point.curve.p);     // just to get byte length of p
		                    var mlen = pOctetString.length;
		                    if (mlen < xOctetString.length || mlen < yOctetString.length) {
		                        throw new Error("Point coordinate(s) are bigger than the field order.");
		                    }
		                    var output = createArray(2 * mlen + 1);       // for encoded x and y

		                    output[0] = 0x04;
		                    var offset = mlen - xOctetString.length;
		                    for (var i = 0; i < xOctetString.length; i++) {
		                        output[i + 1 + offset] = xOctetString[i];
		                    }
		                    offset = mlen - yOctetString.length;
		                    for (i = 0; i < yOctetString.length; i++) {
		                        output[mlen + i + 1 + offset] = yOctetString[i];
		                    }

		                    return output;
		                }

		            },
		            decodePoint: function(encoded, curve) {
		                /// <param name="encoded" type="Digits"/>
		                /// <param name="curve" type="EllipticCurveFp"/>

		                if (encoded.length < 1) {
		                    throw new Error("Byte array must have non-zero length");
		                }

		                var pOctetString = cryptoMath.digitsToBytes(curve.p);
		                var mlen = pOctetString.length;

		                if (encoded[0] === 0x0 && encoded.length === 1) {
		                    return curve.createPointAtInfinity();
		                } else if (encoded[0] === 0x04 && encoded.length === 1 + 2 * mlen) {
		                    // Standard encoding.
		                    // Each point is a big endian string of bytes of length.
		                    //      'ceiling(log_2(Q)/8)'
		                    // Zero-padded and representing the magnitude of the coordinate.
		                    var xbytes = createArray(mlen);
		                    var ybytes = createArray(mlen);

		                    for (var i = 0; i < mlen; i++) {
		                        xbytes[i] = encoded[i + 1];
		                        ybytes[i] = encoded[mlen + i + 1];
		                    }

		                    var x = cryptoMath.bytesToDigits(xbytes);
		                    var y = cryptoMath.bytesToDigits(ybytes);

		                    return EllipticCurvePointFp(curve, false, x, y);
		                } else {
		                    // We don't support other encoding features such as compression
		                    throw new Error("Unsupported encoding format");
		                }
		            }
		        };
		    };

		    var ModularSquareRootSolver = function(modulus) {
		        /// <param name="modulus" type="Digits"/>

		        // The modulus we are going to use.
		        var p = modulus;

		        // Special-K not just for breakfast anymore! This is k = (p-3)/4 + 1
		        // which is used for NIST curves (or any curve of with P= 3 mod 4).
		        // This field is null if p is not of the special form, or k if it is.
		        var specialK = [];

		        if (typeof modulus === "undefined") {
		            throw new Error("modulus");
		        }

		        // Support for odd moduli, only.
		        if (cryptoMath.isEven(modulus)) {
		            throw new Error("Only odd moduli are supported");
		        }

		        // A montgomery multiplier object for doing fast squaring.
		        var mul = cryptoMath.MontgomeryMultiplier(p);

		        // 'p === 3 mod 4' then we can use the special super fast version.
		        // Otherwise we must use the slower general case algorithm.
		        if (p[0] % 4 === 3) {
		            // 'special k = (p + 1) / 4'
		            cryptoMath.add(p, cryptoMath.One, specialK);
		            cryptoMath.shiftRight(specialK, specialK, 2);
		        } else {
		            specialK = null;
		        }

		        // Temp storage
		        var temp0 = new Array(p.length);
		        var temp1 = new Array(p.length);

		        function squareRootNistCurves(a) {
		            /// <summary>Given a number a, returns a solution x to x^2 = a (mod p).</summary>
		            /// <param name="a" type="Array">An integer a.</param>
		            /// <returns type="Array">The square root of the number a modulo p, if it exists,
		            /// otherwise null.</returns>

		            // beta = a^k mod n where k=(n+1)/4 for n == 3 mod 4, thus a^(1/2) mod n
		            var beta = cryptoMath.intToDigits(0, 16);
		            mul.modExp(a, specialK, beta);

		            // Okay now we gotta double check by squaring.
		            var aPrime = [0];
		            cryptoMath.modMul(beta, beta, mul.m, aPrime);

		            // If a != x^2 then a has no square root
		            if (cryptoMath.compareDigits(a, aPrime) !== 0) {
		                return null;
		            }

		            return beta;
		        }

		        var publicMethods = {

		            squareRoot: function(a) {
		                if (specialK !== null) {
		                    // Use the special case fast code
		                    return squareRootNistCurves(a);
		                } else {
		                    // Use the general case code
		                    throw new Error("GeneralCase not supported.");
		                }
		            },

		            // Given an integer a, this routine returns the Jacobi symbol (a/p),
		            // where p is the modulus given in the constructor, which for p an
		            // odd prime is also the Legendre symbol. From "Prime Numbers, A
		            // Computational Perspective" by Crandall and Pomerance, alg. 2.3.5.
		            // The Legendre symbol is defined as:
		            //   0   if a === 0 mod p.
		            //   1   if a is a quadratic residue (mod p).
		            //   -1  if a is a quadratic non-reside (mod p).
		            jacobiSymbol: function(a) {
		                /// <param name="a">An integer a.</param>

		                var modEightMask = 0x7,
		                    modFourMask = 0x3,
		                    aPrime,
		                    pPrime;

		                // Clone our inputs, we are going to destroy them
		                aPrime = a.slice();
		                pPrime = p.slice();

		                // 'a = a mod p'.
		                cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);

		                // 't = 1'
		                var t = 1;

		                // While (a != 0)
		                while (!cryptoMath.isZero(aPrime)) {
		                    // While a is even
		                    while (cryptoMath.isEven(aPrime)) {
		                        // 'a <- a / 2'
		                        cryptoMath.shiftRight(aPrime, aPrime);

		                        // If (p mod 8 in {3,5}) t = -t;
		                        var pMod8 = pPrime[0] & modEightMask;
		                        if (pMod8 === 3 || pMod8 === 5) {
		                            t = -t;
		                        }
		                    }

		                    // Swap variables
		                    // (a, p) = (p, a).
		                    var tmp = aPrime;
		                    aPrime = pPrime;
		                    pPrime = tmp;

		                    // If (a === p === 3 (mod 4)) t = -t;
		                    var aMod4 = aPrime[0] & modFourMask;
		                    var pMod4 = pPrime[0] & modFourMask;
		                    if (aMod4 === 3 && pMod4 === 3) {
		                        t = -t;
		                    }

		                    // 'a = a mod p'
		                    cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);
		                }

		                // If (p == 1) return t else return 0
		                if (cryptoMath.compareDigits(pPrime, cryptoMath.One) === 0) {
		                    return t;
		                } else {
		                    return 0;
		                }
		            }

		        };

		        return publicMethods;
		    };

		    var curvesInternal = {};

		    var createCurve = function(curveName) {

		        var curveData = curvesInternal[curveName.toUpperCase()];

		        if (!curveData) {
		            throw new Error(curveName + " Unsupported curve.");
		        }

		        if (curveData.type === 0) {
		            return createWeierstrassCurve(curveData);
		        }

		        if (curveData.type === 1) {
		            return createTedCurve(curveData);
		        }

		        throw new Error(curveName + " Unsupported curve type.");
		    };

		    var validateEccPoint = function(curveName, x, y, z) {
		        var curve = createCurve(curveName);
		        var point = new EllipticCurvePointFp(curve, false, btd(x), btd(y), z && btd(z), false);
		        var opp = new EllipticCurveOperatorFp(curve);
		        return opp.validatePoint(point);
		    };

		    return {
		        createCurve: createCurve,
		        curves: curvesInternal,
		        sec1EncodingFp: sec1EncodingFp,
		        validatePoint: validateEccPoint,
		        EllipticCurvePointFp: EllipticCurvePointFp,
		        EllipticCurveOperatorFp: EllipticCurveOperatorFp,
		        ModularSquareRootSolver: ModularSquareRootSolver
		    };
		}

		var cryptoECC = cryptoECC || MsrcryptoECC();

		/* commonjs-block */
		{
		    module.exports = cryptoECC;
		}
		/* end-commonjs-block */ 
	} (cryptoECC$2));

	var cryptoECCExports = cryptoECC$2.exports;
	var cryptoECC$1 = /*@__PURE__*/getDefaultExportFromCjs(cryptoECCExports);

	//*******************************************************************************
	//
	//    Copyright 2020 Microsoft
	//
	//    Licensed under the Apache License, Version 2.0 (the "License");
	//    you may not use this file except in compliance with the License.
	//    You may obtain a copy of the License at
	//
	//        http://www.apache.org/licenses/LICENSE-2.0
	//
	//    Unless required by applicable law or agreed to in writing, software
	//    distributed under the License is distributed on an "AS IS" BASIS,
	//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	//    See the License for the specific language governing permissions and
	//    limitations under the License.
	//
	//*******************************************************************************

	// tslint:disable: max-line-length
	// tslint:disable: variable-name

	var curve_P256 = {
	    name: "P-256",
	    type: 0, // Curve Type 0 = Weierstrass, 1 Twisted Edwards
	    p: [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
	    a: [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC],
	    b: [0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B],
	    order: [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51],
	    gx: [0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96],
	    gy: [0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5],
	    cf: 1  // co-factor
	};

	var curve_P384 = {
	    name: "P-384",
	    type: 0, // Curve Type 0 = Weierstrass, 1 Twisted Edwards
	    p: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
	    a: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC],
	    b: [0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4, 0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19, 0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12, 0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A, 0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D, 0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF],
	    order: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73],
	    gx: [0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37, 0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74, 0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98, 0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38, 0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C, 0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7],
	    gy: [0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F, 0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29, 0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C, 0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0, 0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D, 0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F],
	    cf: 1  // co-factor
	};

	var curve_P521 = {
	    name: "P-521",
	    type: 0, // Curve Type 0 = Weierstrass, 1 Twisted Edwards
	    p: [0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
	    a: [0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC],
	    b: [0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C, 0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85, 0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3, 0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1, 0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E, 0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1, 0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C, 0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50, 0x3F, 0x00],
	    order: [0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38, 0x64, 0x09],
	    gx: [0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04, 0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95, 0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F, 0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D, 0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7, 0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF, 0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A, 0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5, 0xBD, 0x66],
	    gy: [0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B, 0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D, 0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B, 0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E, 0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4, 0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD, 0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72, 0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1, 0x66, 0x50],
	    cf: 1  // co-factor
	};

	/* commonjs-block */
	var cryptoECC = typeof commonjsRequire === "function" ? cryptoECCExports : cryptoECC;
	/* end-commonjs-block */

	if (typeof cryptoECC !== "undefined") {
	    // Add curves to ECC object
	    cryptoECC.curves["P-256"] = curve_P256;
	    cryptoECC.curves["P-384"] = curve_P384;
	    cryptoECC.curves["P-521"] = curve_P521;
	}

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	// implements the U-Prove hash formatting
	const groupToHash = (g) => {
	    switch (g) {
	        case ECGroup.P256: return 'sha256';
	        case ECGroup.P384: return 'sha384';
	        case ECGroup.P521: return 'sha512';
	        default: throw 'invalid group';
	    }
	};
	class Byte {
	    constructor(b) {
	        if (0 < b && b > 255)
	            throw 'invalid byte value' + b;
	        this.b = new Uint8Array([b]);
	    }
	}
	// c.f. spec section 2.2
	class Hash {
	    constructor(descGq) {
	        this.hash = new Uint8Array(0);
	        this.descGq = descGq;
	    }
	    getIntArray(n) {
	        return new Uint8Array([
	            (n >> 24),
	            (n >> 16),
	            (n >> 8),
	            n
	        ]);
	    }
	    updateInternal(data) {
	        const temp = new Uint8Array(this.hash.length + data.length);
	        temp.set(this.hash);
	        temp.set(data, this.hash.length);
	        this.hash = temp;
	    }
	    update(data) {
	        if (Array.isArray(data)) {
	            this.update(data.length);
	            data.forEach(v => this.update(v));
	        }
	        else if (data instanceof Byte) {
	            this.updateInternal(data.b);
	        }
	        else if (data === null) {
	            this.updateInternal(this.getIntArray(0));
	        }
	        else if (typeof data === 'number') {
	            this.updateInternal(this.getIntArray(data));
	        }
	        else if (data instanceof Uint8Array) {
	            this.updateInternal(this.getIntArray(data.length));
	            this.updateInternal(data);
	        }
	        else if (data instanceof GroupElement) {
	            this.update(data.getBytes());
	        }
	        else if (data instanceof FieldZqElement) {
	            this.update(data.getBytes());
	        }
	        else {
	            throw "invalid input";
	        }
	    }
	    async digest(data = undefined) {
	        if (data || data === null) {
	            this.update(data);
	        }
	        return crypto.subtle.digest({ name: groupToHash(this.descGq).replace('sha', 'sha-') }, this.hash)
	            .then(arrayBuffer => {
	            return new Uint8Array(arrayBuffer);
	        });
	    }
	}

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	class FieldZqElement {
	    constructor(scalar) {
	        this.scalar = scalar;
	    }
	    getBytes() {
	        const bytes = cryptoMath.digitsToBytes(this.scalar.m_digits);
	        return new Uint8Array(bytes);
	    }
	    equals(e) {
	        return this.scalar.equals(e.scalar);
	    }
	}
	class FieldZq {
	    constructor(q) {
	        this.q = q;
	        const qBytes = cryptoMath.digitsToBytes(q);
	        this.elementLength = qBytes.length;
	        this.Zq = new cryptoMath.IntegerGroup(qBytes);
	        this.ZERO = new FieldZqElement(this.Zq.createElementFromInteger(0));
	        this.ONE = new FieldZqElement(this.Zq.createElementFromInteger(1));
	    }
	    getElement(encoded) {
	        let digits = cryptoMath.bytesToDigits(Array.from(encoded));
	        // Check size of the new element
	        const result = cryptoMath.intToDigits(0);
	        while (cryptoMath.compareDigits(digits, this.q) >= 0) {
	            // too big, reduce (will only call once)
	            cryptoMath.subtract(digits, this.q, result); // could I replace result with digits? TODO
	            digits = result;
	        }
	        return new FieldZqElement(this.Zq.createElementFromDigits(digits));
	    }
	    getRandomElement(nonZero = false) {
	        let done = false;
	        let randZq = cryptoMath.Zero;
	        while (!done) {
	            const ranBytes = crypto.getRandomValues(new Uint8Array(this.elementLength));
	            randZq = cryptoMath.bytesToDigits(Array.from(ranBytes));
	            if (cryptoMath.compareDigits(randZq, this.q) < 0) {
	                done = true;
	            }
	            if (nonZero && cryptoMath.isZero(randZq)) {
	                done = false;
	            }
	        }
	        return new FieldZqElement(this.Zq.createElementFromDigits(randZq));
	    }
	    getRandomElements(n, nonZero = false) {
	        const r = [];
	        for (let i = 0; i < n; i++) {
	            r.push(this.getRandomElement(nonZero));
	        }
	        return r;
	    }
	    add(a, b) {
	        const sum = this.Zq.createElementFromInteger(0);
	        this.Zq.add(a.scalar, b.scalar, sum);
	        return new FieldZqElement(sum);
	    }
	    mul(a, b) {
	        const product = this.Zq.createElementFromInteger(0);
	        this.Zq.multiply(a.scalar, b.scalar, product);
	        return new FieldZqElement(product);
	    }
	    negate(a) {
	        const minusA = this.Zq.createElementFromInteger(0);
	        this.Zq.subtract(this.Zq.createElementFromInteger(0), a.scalar, minusA);
	        return new FieldZqElement(minusA);
	    }
	    invert(a) {
	        const aInverse = this.Zq.createElementFromInteger(0);
	        this.Zq.inverse(a.scalar, aInverse);
	        return new FieldZqElement(aInverse);
	    }
	}
	class GroupElement {
	    constructor(point) {
	        this.point = point;
	    }
	    getBytes() {
	        const encoded = cryptoECC$1.sec1EncodingFp().encodePoint(this.point);
	        return new Uint8Array(encoded);
	    }
	    equals(e) {
	        return this.point.equals(e.point);
	    }
	}
	// the underlying cryptoMath lib expects points to be on the same curve object (===)
	// so we instantiate them once
	var CurveNames;
	(function (CurveNames) {
	    CurveNames["P256"] = "P-256";
	    CurveNames["P384"] = "P-384";
	    CurveNames["P521"] = "P-521";
	})(CurveNames || (CurveNames = {}));
	const P256Curve = cryptoECC$1.createCurve(CurveNames.P256);
	const P384Curve = cryptoECC$1.createCurve(CurveNames.P384);
	const P521Curve = cryptoECC$1.createCurve(CurveNames.P521);
	class Group {
	    constructor(descGq) {
	        if (descGq == ECGroup.P256) {
	            this.curve = P256Curve;
	        }
	        else if (descGq == ECGroup.P384) {
	            this.curve = P384Curve;
	        }
	        else if (descGq == ECGroup.P521) {
	            this.curve = P521Curve;
	        }
	        else {
	            throw 'invalid group description';
	        }
	        this.ecOperator = cryptoECC$1.EllipticCurveOperatorFp(this.curve);
	        this.Zq = new FieldZq(this.curve.order);
	        this.g = new GroupElement(this.curve.generator);
	        this.descGq = descGq;
	    }
	    getHash() {
	        return new Hash(this.descGq);
	    }
	    // update a hash with this group's description (see Section 2.1)
	    updateHash(H) {
	        // H(p,a,b,g,q,1)
	        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.p)));
	        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.a)));
	        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.b)));
	        H.update(this.g /*new GroupElement(this.curve.generator).getBytes()*/);
	        H.update(new Uint8Array(cryptoMath.digitsToBytes(this.curve.order)));
	        H.update(new Uint8Array([1]));
	    }
	    parsePoint(x, y) {
	        const point = new cryptoECC$1.EllipticCurvePointFp(this.curve, false, cryptoMath.bytesToDigits(x), cryptoMath.bytesToDigits(y));
	        return new GroupElement(point);
	    }
	    getElement(encoded) {
	        return new GroupElement(cryptoECC$1.sec1EncodingFp().decodePoint(Array.from(encoded), this.curve));
	    }
	    getIdentity() {
	        return new GroupElement(this.curve.createPointAtInfinity());
	    }
	    // return a.b = point + point
	    mul(a, b) {
	        if (a === undefined || b === undefined || (a === null || a === void 0 ? void 0 : a.point) === undefined || (b === null || b === void 0 ? void 0 : b.point) === undefined) {
	            console.log('undefined point in mul');
	        }
	        const pointA = a.point;
	        const pointB = (pointA === b.point) ? b.point.clone() : b.point; // a and b can't be the same
	        // result must be in Jacobian, Montgomery form for the mixed add
	        const temp = this.curve.allocatePointStorage();
	        this.ecOperator.convertToMontgomeryForm(temp);
	        this.ecOperator.convertToJacobianForm(temp);
	        // "a" must be in Jacobian, Montgomery form 
	        if (!pointA.isInMontgomeryForm)
	            this.ecOperator.convertToMontgomeryForm(pointA);
	        if (pointA.isAffine)
	            this.ecOperator.convertToJacobianForm(pointA);
	        // "b" must be in Affine, Montgomery form
	        if (!pointB.isAffine)
	            this.ecOperator.convertToAffineForm(pointB);
	        if (!pointB.isInMontgomeryForm)
	            this.ecOperator.convertToMontgomeryForm(pointB);
	        // perform the mixed add
	        this.ecOperator.mixedAdd(pointA, pointB, temp);
	        // now convert everyone back to Affine, Standard form
	        this.ecOperator.convertToAffineForm(pointA);
	        this.ecOperator.convertToStandardForm(pointA);
	        // b already in affine form
	        this.ecOperator.convertToStandardForm(pointB);
	        this.ecOperator.convertToAffineForm(temp);
	        this.ecOperator.convertToStandardForm(temp);
	        return new GroupElement(temp);
	    }
	    // return g^e = [scalar] point.
	    modExp(g, e) {
	        const result = this.curve.allocatePointStorage();
	        // point must be in Affine, Montgomery form
	        if (!g.point.isAffine)
	            this.ecOperator.convertToAffineForm(g.point);
	        if (!g.point.isInMontgomeryForm)
	            this.ecOperator.convertToMontgomeryForm(g.point);
	        // scalar multiplication
	        this.ecOperator.scalarMultiply(e.scalar.m_digits, g.point, result);
	        // convert everyone back to Affine, Standard form
	        if (!g.point.isAffine)
	            this.ecOperator.convertToAffineForm(g.point);
	        if (g.point.isInMontgomeryForm)
	            this.ecOperator.convertToStandardForm(g.point);
	        if (!result.isAffine)
	            this.ecOperator.convertToAffineForm(result);
	        if (result.isInMontgomeryForm)
	            this.ecOperator.convertToStandardForm(result);
	        return new GroupElement(result);
	    }
	    // return g[0]^e[0] ... g[n]^e[n]
	    multiModExp(g, e) {
	        if (g.length !== e.length) {
	            throw `g and e length mismatch`;
	        }
	        let result = this.getIdentity();
	        for (let i = 0; i < g.length; i++) {
	            const temp = this.modExp(g[i], e[i]);
	            result = this.mul(result, temp);
	        }
	        return result;
	    }
	    isValid(g) {
	        return this.ecOperator.validatePoint(g.point);
	    }
	}

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	// U-Prove Recommended Parameters Profile Lite (elliptic curve construction)
	class P256ECGroupParams {
	    constructor() {
	        this.descGq = ECGroup.P256;
	        this.Gq = new Group(this.descGq);
	        this.oid = "1.3.6.1.4.1.311.75.1.2.2";
	        this.g = [
	            this.Gq.parsePoint([
	                0xf1, 0xb9, 0x86, 0xd5, 0xd1, 0x1f, 0x43, 0x48,
	                0x3a, 0xe7, 0x36, 0xe8, 0x86, 0xaf, 0x75, 0x0e,
	                0x87, 0x0d, 0x7f, 0x0c, 0x23, 0x12, 0xaa, 0xd8,
	                0xdb, 0x5c, 0x8a, 0x3e, 0x34, 0xf5, 0x39, 0x1e
	            ], [
	                0x64, 0x34, 0x7b, 0x7f, 0x49, 0x31, 0x87, 0xa5,
	                0x3b, 0x37, 0x08, 0x94, 0xb8, 0xf8, 0xe3, 0x8f,
	                0xd2, 0x2c, 0xb9, 0x93, 0x02, 0x39, 0x3d, 0x79,
	                0xdc, 0xe2, 0x25, 0x91, 0x8e, 0xba, 0x61, 0xee
	            ]),
	            this.Gq.parsePoint([
	                0x15, 0x54, 0xcf, 0x98, 0x3e, 0x0b, 0x06, 0x0c,
	                0x78, 0x70, 0x5e, 0xd7, 0xd1, 0x4a, 0x49, 0x41,
	                0xb0, 0x2e, 0x60, 0x8c, 0xdb, 0x78, 0xf6, 0xa7,
	                0x5a, 0x52, 0x34, 0x59, 0x78, 0x14, 0x1f, 0xd3
	            ], [
	                0x62, 0x54, 0x0e, 0x69, 0x0c, 0x8f, 0xa9, 0xfe,
	                0x10, 0x7e, 0x21, 0x41, 0xdf, 0xc6, 0x90, 0x7f,
	                0x74, 0xf5, 0xfe, 0xeb, 0xdf, 0x5b, 0x12, 0xd7,
	                0x15, 0x3b, 0x46, 0x35, 0xa2, 0xdf, 0x6a, 0x76
	            ]),
	            this.Gq.parsePoint([
	                0x32, 0x79, 0x1a, 0x77, 0x9e, 0x9a, 0xa4, 0x75,
	                0xba, 0x26, 0x66, 0xa0, 0xe4, 0x7a, 0x92, 0x8b,
	                0x21, 0xab, 0x19, 0x05, 0xfa, 0xaf, 0x48, 0xbb,
	                0x80, 0x62, 0xba, 0xe9, 0x00, 0x9e, 0xb2, 0x7d
	            ], [
	                0x18, 0x74, 0xba, 0x86, 0xea, 0x19, 0x4f, 0xb1,
	                0x4d, 0xcc, 0xe9, 0xfa, 0x22, 0x36, 0x6f, 0x47,
	                0x35, 0xca, 0xea, 0x21, 0x19, 0xbe, 0xb6, 0x3f,
	                0x2b, 0xae, 0xc1, 0x9a, 0x9e, 0x93, 0xa5, 0x45
	            ]),
	            this.Gq.parsePoint([
	                0xc0, 0xef, 0xad, 0xb5, 0xc3, 0x01, 0x5e, 0x42,
	                0xc1, 0xd7, 0x1a, 0xc3, 0x90, 0xc4, 0xd2, 0x2a,
	                0x6f, 0x5d, 0x55, 0x2f, 0x63, 0xbb, 0xcc, 0x59,
	                0x19, 0x0a, 0xea, 0x6a, 0xee, 0x16, 0x35, 0x4a
	            ], [
	                0x53, 0xf0, 0x13, 0x3e, 0xa4, 0x4d, 0xa2, 0x0c,
	                0x50, 0x9a, 0x4e, 0x5b, 0xe9, 0xb0, 0x27, 0xdb,
	                0xe1, 0x3e, 0x3a, 0x60, 0x43, 0x9d, 0xbe, 0x72,
	                0x08, 0x4b, 0x0c, 0x75, 0xa0, 0x49, 0x72, 0x3f
	            ]),
	            this.Gq.parsePoint([
	                0xbd, 0x5f, 0x29, 0xdf, 0x66, 0x40, 0x49, 0x3f,
	                0xf9, 0x6c, 0x6c, 0xbc, 0x49, 0xcb, 0x8e, 0x5f,
	                0x61, 0x46, 0x27, 0x92, 0xdb, 0x75, 0xf2, 0x0e,
	                0xf4, 0x9b, 0xf8, 0x6e, 0x26, 0x0d, 0xc9, 0x55
	            ], [
	                0x20, 0x4c, 0x44, 0x0e, 0xf8, 0xc6, 0xeb, 0x2b,
	                0xec, 0x0c, 0x34, 0x3a, 0xce, 0x9c, 0x6d, 0x64,
	                0xe1, 0x88, 0xc8, 0xb4, 0xf0, 0x61, 0x3d, 0x64,
	                0x84, 0x6a, 0xdb, 0xdc, 0x3d, 0x8f, 0xdf, 0xad
	            ]),
	            this.Gq.parsePoint([
	                0xd9, 0x1a, 0xbd, 0xa2, 0x6e, 0xc5, 0xc3, 0x00,
	                0x1c, 0xf1, 0xca, 0x2c, 0x09, 0xad, 0x88, 0x66,
	                0x25, 0x58, 0x42, 0x6d, 0xc3, 0xb4, 0xd1, 0xb5,
	                0x01, 0xe7, 0xab, 0xc2, 0xdb, 0x08, 0x0c, 0xdc
	            ], [
	                0x54, 0xeb, 0xb1, 0x7f, 0xed, 0x85, 0x5a, 0x36,
	                0xc1, 0xf7, 0x4a, 0xb8, 0x25, 0x62, 0x08, 0xe8,
	                0x63, 0x07, 0xa9, 0xf2, 0xb7, 0x56, 0xd7, 0xc8,
	                0x4b, 0x4f, 0xb9, 0x48, 0x5e, 0x0f, 0xf5, 0xf5
	            ]),
	            this.Gq.parsePoint([
	                0x86, 0xeb, 0x2c, 0x94, 0xe2, 0xb6, 0xd6, 0x20,
	                0xa3, 0x91, 0xb4, 0x08, 0x0d, 0xfe, 0x2b, 0x37,
	                0x7c, 0xc2, 0x0d, 0x98, 0x1b, 0x5b, 0xc0, 0xcc,
	                0xa9, 0x4e, 0x86, 0x56, 0x97, 0x95, 0x9e, 0xbe
	            ], [
	                0x26, 0xac, 0x15, 0x89, 0xc5, 0x28, 0x80, 0xc3,
	                0xb8, 0xf8, 0x1d, 0x2b, 0xf3, 0x29, 0x76, 0x63,
	                0x60, 0x19, 0xf1, 0x6d, 0x8e, 0xfa, 0x1f, 0x4d,
	                0x20, 0x95, 0x0b, 0x99, 0x08, 0xce, 0xb7, 0xe1
	            ]),
	            this.Gq.parsePoint([
	                0x55, 0x53, 0x14, 0x8e, 0x44, 0x25, 0x26, 0x92,
	                0xd9, 0xe7, 0xea, 0x9c, 0x18, 0x94, 0x69, 0xdd,
	                0x2c, 0x0e, 0x8b, 0xd4, 0x49, 0x40, 0x5b, 0x6f,
	                0x3b, 0x1f, 0x27, 0x92, 0x45, 0xb3, 0x7f, 0x0d
	            ], [
	                0x79, 0x0c, 0xa4, 0xce, 0x90, 0xe0, 0x48, 0xa7,
	                0x42, 0x5b, 0x66, 0x2a, 0x63, 0x16, 0x12, 0xd0,
	                0x22, 0x4f, 0x20, 0x8e, 0x4b, 0xe6, 0xe9, 0x07,
	                0xc3, 0xe7, 0xd9, 0x60, 0x7a, 0x99, 0x7f, 0x6d
	            ]),
	            this.Gq.parsePoint([
	                0x77, 0x66, 0x8d, 0x97, 0xbf, 0xf7, 0xd5, 0xda,
	                0x69, 0x5d, 0x6d, 0x72, 0xe4, 0xf8, 0x40, 0x20,
	                0x5d, 0xe2, 0x89, 0xce, 0x8f, 0xf1, 0xe9, 0x95,
	                0x24, 0x35, 0xb0, 0xb4, 0xdd, 0x4e, 0x22, 0x2e
	            ], [
	                0x14, 0x76, 0x06, 0x0b, 0x33, 0xfe, 0x63, 0x6b,
	                0xb9, 0xb7, 0x5f, 0x10, 0x78, 0x5d, 0x4b, 0x43,
	                0x19, 0x05, 0xcd, 0x00, 0x6f, 0x83, 0x2b, 0xf7,
	                0x31, 0x03, 0xb9, 0xf8, 0x80, 0x37, 0x85, 0x56
	            ]),
	            this.Gq.parsePoint([
	                0x72, 0x9a, 0x72, 0xbe, 0x83, 0x75, 0x88, 0x8f,
	                0x67, 0xdf, 0x96, 0xd2, 0xa5, 0x2e, 0x1b, 0x38,
	                0x4a, 0xf1, 0xc6, 0x8f, 0xf8, 0xb7, 0x3c, 0xad,
	                0xf6, 0x29, 0x6c, 0x72, 0xc2, 0xc1, 0xfa, 0xb2
	            ], [
	                0x01, 0x31, 0x20, 0xe6, 0x94, 0x2d, 0x07, 0x40,
	                0xa2, 0x5f, 0x8b, 0x87, 0x1e, 0x1f, 0x2f, 0xe9,
	                0xa8, 0x60, 0x49, 0x77, 0xd1, 0xda, 0xa1, 0x8a,
	                0xf0, 0xe4, 0xfe, 0xd5, 0x70, 0xc6, 0xea, 0x2e
	            ]),
	            this.Gq.parsePoint([
	                0xcf, 0xba, 0x01, 0x4e, 0xf2, 0x73, 0x4b, 0xb0,
	                0xd5, 0x18, 0x63, 0xa1, 0xe6, 0xae, 0x8e, 0xb4,
	                0xae, 0x18, 0x9f, 0x8c, 0x19, 0x43, 0x2a, 0xf4,
	                0x6d, 0x9f, 0x16, 0xfd, 0xd4, 0x3f, 0xbc, 0x18
	            ], [
	                0x12, 0x56, 0xc7, 0x84, 0xf8, 0x27, 0xc3, 0x1a,
	                0xd2, 0x3d, 0x8d, 0x23, 0x36, 0x78, 0xce, 0x2e,
	                0xeb, 0xce, 0x34, 0x46, 0x29, 0xe7, 0xa5, 0xf7,
	                0xa6, 0xd9, 0x4a, 0xdc, 0x0f, 0xf4, 0x7a, 0x7e
	            ]),
	            this.Gq.parsePoint([
	                0x6c, 0x14, 0x07, 0xc4, 0x9a, 0x51, 0xf6, 0x76,
	                0x25, 0xeb, 0x8b, 0x29, 0x95, 0xac, 0x11, 0x94,
	                0x42, 0x88, 0x99, 0x5b, 0x3a, 0x81, 0x78, 0x9a,
	                0x5e, 0xb3, 0xe6, 0xbf, 0x4f, 0x2d, 0xed, 0x78
	            ], [
	                0x16, 0xd8, 0x72, 0x49, 0x4f, 0xc1, 0x8d, 0x77,
	                0x40, 0x4f, 0x90, 0x6e, 0x58, 0x90, 0x21, 0x50,
	                0xe1, 0xfc, 0xdd, 0xa0, 0xcf, 0x21, 0x15, 0x16,
	                0xf6, 0xf1, 0x94, 0x15, 0xe8, 0x89, 0x2f, 0x26
	            ]),
	            this.Gq.parsePoint([
	                0xd9, 0x23, 0x1c, 0x31, 0x5b, 0xaf, 0x72, 0x24,
	                0x69, 0xf7, 0x4f, 0xba, 0x55, 0xba, 0x66, 0x17,
	                0x77, 0xe9, 0x1c, 0xa6, 0x32, 0x0a, 0x88, 0x25,
	                0xbd, 0xa1, 0xcb, 0xf0, 0xea, 0x20, 0x60, 0x92
	            ], [
	                0x36, 0xe4, 0xcd, 0x12, 0x88, 0x08, 0x8d, 0xec,
	                0xee, 0xa8, 0xe7, 0xb6, 0xd2, 0x2c, 0xfd, 0x97,
	                0xb9, 0x9f, 0x87, 0xfa, 0xcc, 0x95, 0xf1, 0x89,
	                0x1f, 0xc6, 0xa2, 0x8b, 0xd8, 0x1e, 0x5f, 0x50
	            ]),
	            this.Gq.parsePoint([
	                0x35, 0x35, 0x87, 0x11, 0x38, 0x41, 0x06, 0xb8,
	                0x62, 0xa2, 0xcf, 0x0b, 0x40, 0x3e, 0x80, 0x55,
	                0x92, 0x0c, 0x75, 0x98, 0xbf, 0xb4, 0x99, 0x87,
	                0xa8, 0x9c, 0x35, 0x69, 0xe5, 0xa0, 0x5b, 0x61
	            ], [
	                0x18, 0xed, 0xfa, 0x1d, 0xfc, 0x65, 0x3a, 0x05,
	                0x74, 0xca, 0x88, 0xfd, 0xaa, 0xec, 0xdf, 0xe9,
	                0xeb, 0x75, 0x30, 0x9a, 0xac, 0xbe, 0x92, 0x6c,
	                0x21, 0x10, 0xe9, 0x26, 0x78, 0xc8, 0x4e, 0x3d
	            ]),
	            this.Gq.parsePoint([
	                0x25, 0xd0, 0x5c, 0x26, 0x17, 0x72, 0x16, 0x6c,
	                0x08, 0x48, 0x3d, 0x00, 0x00, 0x3f, 0x44, 0x35,
	                0x20, 0xe9, 0x13, 0x24, 0xcb, 0xe9, 0x18, 0xfc,
	                0x34, 0x00, 0x8a, 0x93, 0x27, 0x16, 0xd7, 0xeb
	            ], [
	                0x66, 0x8a, 0x13, 0xc5, 0xd1, 0x63, 0xf6, 0x64,
	                0x6b, 0xf2, 0xe8, 0xf4, 0x2d, 0x1f, 0x48, 0xe7,
	                0x9a, 0x9e, 0xad, 0x02, 0x09, 0x22, 0xb3, 0x83,
	                0x00, 0x6b, 0x67, 0x6d, 0x29, 0xd3, 0x5a, 0x42
	            ]),
	            this.Gq.parsePoint([
	                0xfc, 0x03, 0x5c, 0x85, 0xaa, 0x0e, 0x9c, 0x52,
	                0x7e, 0xa7, 0xdc, 0xa2, 0x6a, 0x2d, 0xb7, 0x4d,
	                0xc2, 0x50, 0xe8, 0xa5, 0xab, 0xe8, 0x53, 0xbb,
	                0xde, 0xd1, 0x59, 0x59, 0xd7, 0x23, 0x0f, 0x43
	            ], [
	                0x65, 0xf0, 0x52, 0xa3, 0x82, 0xb2, 0xc7, 0x8c,
	                0xaa, 0x9f, 0xcf, 0xc9, 0x52, 0x09, 0x6f, 0x4c,
	                0xcc, 0x47, 0x72, 0x54, 0x6e, 0x57, 0x98, 0x64,
	                0x91, 0x23, 0xfe, 0xf9, 0x4e, 0xc9, 0x5a, 0xcc
	            ]),
	            this.Gq.parsePoint([
	                0x85, 0xb3, 0x87, 0x3f, 0xd9, 0x11, 0xbf, 0x06,
	                0xa9, 0x78, 0xfa, 0x40, 0xe2, 0x61, 0xe1, 0xc8,
	                0x56, 0xf6, 0x38, 0xca, 0x9e, 0xc8, 0xcb, 0xe8,
	                0x82, 0x6a, 0x60, 0x82, 0xc8, 0x45, 0x2d, 0x0f
	            ], [
	                0x3c, 0xf0, 0x0d, 0x69, 0x58, 0x6f, 0x56, 0xbe,
	                0xd8, 0x49, 0xd5, 0xe9, 0xe2, 0x82, 0x5a, 0x00,
	                0x3c, 0xe5, 0x62, 0xaa, 0xb5, 0xf8, 0x1b, 0xd7,
	                0x18, 0xa4, 0xe9, 0x41, 0x98, 0x9e, 0x11, 0x01
	            ]),
	            this.Gq.parsePoint([
	                0x45, 0x49, 0xf8, 0xc6, 0x21, 0xea, 0xba, 0x57,
	                0xed, 0x23, 0x36, 0xd5, 0x19, 0x20, 0xf6, 0xfc,
	                0x4d, 0xc3, 0x4e, 0x04, 0x7d, 0xb1, 0x34, 0xc6,
	                0x19, 0x80, 0xe4, 0xe3, 0x58, 0xc5, 0xe3, 0x24
	            ], [
	                0x39, 0xe8, 0xbe, 0x23, 0xf0, 0x40, 0x33, 0xa0,
	                0xf8, 0xbc, 0x43, 0xd5, 0xa1, 0x1b, 0x1e, 0x79,
	                0x8d, 0x25, 0xb5, 0xc7, 0x5d, 0x74, 0x0e, 0xfd,
	                0x30, 0x99, 0x85, 0xed, 0xc5, 0xde, 0xdb, 0x98
	            ]),
	            this.Gq.parsePoint([
	                0xb8, 0xad, 0x38, 0x6b, 0x54, 0xf9, 0x76, 0x6e,
	                0x5c, 0xb1, 0xa2, 0xf0, 0x50, 0xcb, 0xca, 0x2a,
	                0x22, 0x61, 0x9b, 0xa0, 0x08, 0xfd, 0xf9, 0x49,
	                0x6d, 0xf3, 0x8a, 0x6c, 0xea, 0x78, 0x4e, 0xb2
	            ], [
	                0x5b, 0x33, 0x3a, 0x0c, 0xde, 0x9d, 0xdc, 0x8d,
	                0x65, 0x71, 0xb1, 0xca, 0xc4, 0x56, 0xa4, 0x71,
	                0x44, 0xc9, 0xc1, 0x6e, 0xce, 0x86, 0x6a, 0x53,
	                0x84, 0x94, 0xea, 0x0f, 0xea, 0xee, 0xf0, 0xac
	            ]),
	            this.Gq.parsePoint([
	                0x56, 0x62, 0x8c, 0x7d, 0x63, 0x66, 0xe1, 0xc4,
	                0xa9, 0x36, 0x1e, 0x5f, 0x7e, 0x49, 0x41, 0x5c,
	                0x80, 0xfd, 0xa1, 0x4c, 0x04, 0xf1, 0x06, 0xf0,
	                0x63, 0x8e, 0xc8, 0xcf, 0x59, 0xaa, 0x04, 0x85
	            ], [
	                0x74, 0xfd, 0xc2, 0x60, 0x80, 0x2b, 0x6d, 0xf5,
	                0x5a, 0x64, 0x02, 0x33, 0x88, 0x95, 0x35, 0xcd,
	                0x04, 0xe0, 0xdf, 0x84, 0xb6, 0x6d, 0x9d, 0xa4,
	                0x64, 0x5d, 0xa3, 0x11, 0x93, 0x99, 0x50, 0x46
	            ]),
	            this.Gq.parsePoint([
	                0x8f, 0x1f, 0x5a, 0x0e, 0x34, 0x2e, 0x65, 0x57,
	                0xb9, 0x55, 0x35, 0x54, 0x38, 0x60, 0x8d, 0xb0,
	                0x9e, 0x4d, 0x23, 0x7e, 0xc7, 0x23, 0x0e, 0x2c,
	                0x83, 0x6b, 0xd5, 0xf3, 0xe9, 0x1c, 0x6c, 0x12
	            ], [
	                0x2c, 0x1a, 0x21, 0x02, 0xa6, 0x9e, 0xf7, 0x4a,
	                0x00, 0x63, 0x53, 0xc2, 0xd2, 0xd1, 0xdd, 0x9d,
	                0xbd, 0xfa, 0xb0, 0x07, 0xfd, 0x08, 0xe7, 0xc8,
	                0x8e, 0xb8, 0x69, 0xa0, 0xa6, 0x69, 0xb1
	            ]),
	            this.Gq.parsePoint([
	                0xbe, 0xaf, 0x77, 0x57, 0xa3, 0xce, 0x43, 0xdc,
	                0x8d, 0x4a, 0x07, 0x32, 0xe1, 0xe3, 0x18, 0xf4,
	                0x97, 0x55, 0xe6, 0x1e, 0x5f, 0x57, 0xa8, 0x5b,
	                0xec, 0xcf, 0x21, 0xb7, 0xdc, 0xc8, 0x18, 0xe2
	            ], [
	                0x40, 0xd2, 0x6c, 0x2a, 0xdc, 0x3f, 0x41, 0xd0,
	                0x91, 0x56, 0x02, 0x5a, 0x9d, 0xc3, 0x4f, 0xd3,
	                0xca, 0x6b, 0x96, 0x80, 0x9d, 0x3d, 0x7c, 0xf5,
	                0xf2, 0x8d, 0x00, 0xa1, 0xed, 0xbd, 0x69, 0x95
	            ]),
	            this.Gq.parsePoint([
	                0xe5, 0x13, 0xc3, 0xe5, 0x0e, 0xfa, 0x44, 0x36,
	                0x19, 0x9c, 0x5a, 0x51, 0xfd, 0x69, 0x1e, 0xa4,
	                0xdc, 0xab, 0xbc, 0x20, 0x2a, 0x80, 0x29, 0xba,
	                0x3d, 0xf0, 0x33, 0x6f, 0x12, 0xd8, 0x26, 0x63
	            ], [
	                0x75, 0xf4, 0x2f, 0x58, 0x48, 0x0d, 0x2c, 0xad,
	                0x56, 0x9b, 0x0f, 0x13, 0xcb, 0xf3, 0x76, 0xc3,
	                0x91, 0x32, 0x71, 0xd9, 0xf7, 0x84, 0x42, 0x42,
	                0xb8, 0x70, 0x51, 0x9d, 0x2b, 0xe8, 0x39, 0x8e
	            ]),
	            this.Gq.parsePoint([
	                0xb4, 0x2b, 0x3b, 0x05, 0xbc, 0xaf, 0xbb, 0x72,
	                0x80, 0x0e, 0xe2, 0x42, 0xab, 0x4c, 0xb7, 0xab,
	                0xd7, 0x7f, 0x1f, 0xce, 0xac, 0x7c, 0xe1, 0xd3,
	                0x27, 0xee, 0xc2, 0x5b, 0x3d, 0xe6, 0xc4, 0x3d
	            ], [
	                0x72, 0x5f, 0x5b, 0x3d, 0x0c, 0xdd, 0x1b, 0x86,
	                0xbd, 0x7a, 0x8b, 0xd6, 0x35, 0xc1, 0xac, 0xed,
	                0xba, 0xc9, 0x1d, 0x6c, 0x35, 0x16, 0x3e, 0xae,
	                0x66, 0x81, 0x07, 0x51, 0xf4, 0xd4, 0x62, 0x88
	            ]),
	            this.Gq.parsePoint([
	                0xc8, 0xa4, 0xa7, 0xdf, 0x6b, 0xef, 0x6c, 0x61,
	                0xef, 0x50, 0xbf, 0xfd, 0x9c, 0xfa, 0x7e, 0xfd,
	                0xe2, 0x25, 0x30, 0xf0, 0xb2, 0xd0, 0x37, 0x1e,
	                0x81, 0x9b, 0x80, 0xe8, 0x85, 0xd5, 0x92, 0xdd
	            ], [
	                0x19, 0x6e, 0x7e, 0x0a, 0x81, 0xd0, 0x3b, 0x38,
	                0xa8, 0xf9, 0x91, 0x04, 0x81, 0x2f, 0x64, 0x78,
	                0x4b, 0x62, 0xd4, 0x19, 0x91, 0xf5, 0x66, 0xde,
	                0x27, 0x84, 0x7b, 0x6b, 0xb9, 0xba, 0xa2, 0x51
	            ]),
	            this.Gq.parsePoint([
	                0xa2, 0x2a, 0xf4, 0x5e, 0x5a, 0x7a, 0x9a, 0x9f,
	                0x94, 0x91, 0x0e, 0x8c, 0xdb, 0x5e, 0x64, 0x9e,
	                0x83, 0xc3, 0x8f, 0xc1, 0x36, 0x9f, 0x1c, 0xa9,
	                0xfa, 0x1d, 0x51, 0x88, 0x7c, 0x38, 0xdd, 0xf1
	            ], [
	                0x75, 0x9b, 0xd3, 0x8c, 0x6e, 0x09, 0xfe, 0x2c,
	                0xd7, 0x5b, 0x4f, 0x35, 0x5f, 0x44, 0x20, 0xe2,
	                0xe7, 0xb2, 0xdf, 0xd9, 0xf7, 0x14, 0x7a, 0xa0,
	                0x3d, 0x53, 0x73, 0xb3, 0x61, 0x2b, 0x83, 0x89
	            ]),
	            this.Gq.parsePoint([
	                0x22, 0xf4, 0x7a, 0x6a, 0xae, 0xc1, 0x42, 0x35,
	                0x94, 0x81, 0xee, 0xa4, 0x90, 0x98, 0x88, 0x2b,
	                0x3e, 0xca, 0xc4, 0x62, 0x5b, 0x1d, 0x25, 0x62,
	                0xb0, 0x27, 0x18, 0x48, 0x76, 0x2c, 0x5d, 0xde
	            ], [
	                0x3e, 0x0b, 0x7e, 0x0c, 0x51, 0xa0, 0x63, 0x30,
	                0x35, 0x80, 0xca, 0x25, 0xe3, 0x26, 0xae, 0x7e,
	                0x61, 0x08, 0x6e, 0xa6, 0xe4, 0xc4, 0x95, 0xd2,
	                0x51, 0x62, 0x86, 0x70, 0x39, 0xd9, 0xfe, 0x4c
	            ]),
	            this.Gq.parsePoint([
	                0xea, 0xe2, 0x4e, 0x9c, 0xbf, 0x4a, 0x8e, 0xb9,
	                0x2c, 0x1c, 0xc8, 0x0d, 0x75, 0xdc, 0xf4, 0x4c,
	                0x39, 0xdf, 0xe4, 0xed, 0xcf, 0x13, 0xc3, 0xe5,
	                0xe4, 0xb7, 0xba, 0x08, 0xc3, 0x29, 0x37, 0x8d
	            ], [
	                0x2f, 0x7f, 0xff, 0xfa, 0x43, 0xa2, 0xd0, 0x26,
	                0x8c, 0x25, 0xe4, 0xf0, 0x86, 0x63, 0xfe, 0xf2,
	                0x6c, 0x57, 0x96, 0x2f, 0xd5, 0xf6, 0x23, 0x29,
	                0x2f, 0x06, 0x1e, 0xa1, 0x9c, 0x57, 0x10, 0xa1
	            ]),
	            this.Gq.parsePoint([
	                0xad, 0x92, 0xb0, 0x98, 0x52, 0x8a, 0xe2, 0x08,
	                0x57, 0x24, 0x74, 0xe3, 0xca, 0x2b, 0x1f, 0x6f,
	                0xbe, 0x13, 0x3c, 0xb4, 0xfa, 0xb5, 0xee, 0xba,
	                0x0e, 0x46, 0x10, 0x0c, 0x68, 0x4d, 0x5b, 0xbc
	            ], [
	                0x47, 0x97, 0x86, 0x85, 0xfa, 0x8f, 0x41, 0xca,
	                0x52, 0x46, 0xbd, 0x63, 0x47, 0xba, 0x65, 0xf6,
	                0x70, 0xec, 0x65, 0xa1, 0x36, 0x16, 0x6c, 0x75,
	                0xe7, 0x93, 0x63, 0x46, 0xe1, 0x6a, 0xd7, 0x90
	            ]),
	            this.Gq.parsePoint([
	                0xdc, 0x5a, 0xbc, 0x9d, 0x9e, 0x2a, 0x04, 0xa7,
	                0xba, 0x38, 0x34, 0x6e, 0x82, 0x71, 0x19, 0xf5,
	                0x0f, 0xa3, 0x11, 0xb8, 0xcb, 0x4b, 0x12, 0xcf,
	                0x53, 0x60, 0x2f, 0x34, 0x82, 0xa6, 0x09, 0xc0
	            ], [
	                0xe9, 0x4f, 0x73, 0xd5, 0xd9, 0x64, 0x19, 0x42,
	                0x18, 0x8f, 0xd0, 0xff, 0x64, 0xa7, 0x75, 0x10,
	                0x21, 0xfa, 0xf6, 0xcc, 0x9c, 0x4d, 0x2a, 0xa0,
	                0x31, 0x8e, 0x94, 0xf0, 0x59, 0x78, 0xbe
	            ]),
	            this.Gq.parsePoint([
	                0x5d, 0x00, 0x8b, 0x9b, 0xde, 0xbb, 0x38, 0x24,
	                0x93, 0x5b, 0xdc, 0x68, 0xa7, 0xac, 0x42, 0x6c,
	                0x55, 0x40, 0x58, 0xa9, 0xdc, 0x4e, 0xd8, 0xbe,
	                0xa2, 0xea, 0x74, 0xa9, 0x2d, 0xf4, 0x7f, 0xc3
	            ], [
	                0x18, 0x05, 0xd5, 0xf8, 0xf0, 0x97, 0xea, 0x8b,
	                0x3b, 0x86, 0x08, 0xdc, 0x5f, 0x01, 0x6f, 0xd9,
	                0x09, 0x78, 0x1b, 0x75, 0x90, 0x0d, 0x53, 0xce,
	                0x8b, 0x65, 0x84, 0x65, 0x18, 0xca, 0x0b, 0xda
	            ]),
	            this.Gq.parsePoint([
	                0x4b, 0xff, 0x16, 0x06, 0x7e, 0x37, 0x79, 0x8f,
	                0xf3, 0xe3, 0x24, 0x2b, 0x11, 0xbe, 0x39, 0xf8,
	                0x3d, 0xd7, 0x45, 0x1e, 0xbe, 0x11, 0x01, 0xea,
	                0xc4, 0x88, 0x7a, 0x6f, 0x93, 0xd5, 0x02, 0x06
	            ], [
	                0x06, 0x5e, 0x5e, 0x31, 0xe1, 0x50, 0x13, 0x60,
	                0x36, 0xe1, 0x92, 0x25, 0x49, 0xb9, 0xfd, 0x9a,
	                0x85, 0x59, 0x97, 0x12, 0x9f, 0x45, 0x66, 0xd3,
	                0xf5, 0xac, 0xf8, 0xa1, 0xe4, 0xd0, 0xac, 0x83
	            ]),
	            this.Gq.parsePoint([
	                0xae, 0xcb, 0xa7, 0xf0, 0x74, 0x51, 0x23, 0xd9,
	                0xc6, 0xa6, 0x0e, 0x9b, 0xd4, 0x61, 0xa8, 0x63,
	                0x61, 0x31, 0xb0, 0x95, 0xf5, 0x96, 0x17, 0x84,
	                0x9d, 0x33, 0x5d, 0x2a, 0x7d, 0x8b, 0x18, 0x7b
	            ], [
	                0x5f, 0x62, 0xd5, 0xea, 0xf4, 0xa9, 0xa8, 0x92,
	                0x48, 0x8c, 0x0d, 0xe9, 0x5d, 0x8d, 0x85, 0xed,
	                0xa9, 0x03, 0x5b, 0x65, 0x97, 0xea, 0x26, 0x74,
	                0xd7, 0xa7, 0xee, 0x7d, 0x4a, 0x53, 0x5e, 0xbd
	            ]),
	            this.Gq.parsePoint([
	                0xa7, 0x4e, 0xcb, 0x80, 0x73, 0x24, 0x96, 0xe8,
	                0xf6, 0xce, 0x72, 0xf4, 0x55, 0x69, 0x37, 0xc2,
	                0x37, 0xe1, 0x9e, 0xfa, 0xc7, 0x56, 0x7c, 0x15,
	                0x1f, 0x38, 0x6b, 0x65, 0x06, 0x56, 0xa2, 0x26
	            ], [
	                0x04, 0xf6, 0x61, 0x41, 0x53, 0x13, 0x28, 0x4d,
	                0x90, 0x44, 0x85, 0xe6, 0xf6, 0xdb, 0x8f, 0xe9,
	                0x47, 0x82, 0xb2, 0xba, 0x24, 0xc0, 0xcb, 0xa6,
	                0xca, 0x77, 0x55, 0x7e, 0xfc, 0xd8, 0xf0, 0x5e
	            ]),
	            this.Gq.parsePoint([
	                0xed, 0x0e, 0x96, 0x56, 0x69, 0x01, 0x7a, 0xa7,
	                0x1f, 0x34, 0x2e, 0xc8, 0xa0, 0x99, 0xbb, 0xf0,
	                0x1a, 0x0b, 0x9e, 0xab, 0x94, 0xf6, 0x26, 0x23,
	                0xec, 0xf9, 0x6b, 0xcc, 0x0e, 0x14, 0xe4, 0xab
	            ], [
	                0x24, 0x4b, 0xf1, 0x25, 0x52, 0x3e, 0xf2, 0x97,
	                0x8d, 0xb0, 0x60, 0x06, 0xcd, 0xa7, 0xcf, 0x3e,
	                0x4d, 0x58, 0x39, 0x77, 0x11, 0xd9, 0x28, 0x97,
	                0x60, 0x3d, 0xba, 0xe2, 0x9b, 0x82, 0x86, 0x4b
	            ]),
	            this.Gq.parsePoint([
	                0x06, 0x9b, 0x84, 0x3b, 0xdb, 0xf0, 0x17, 0xd4,
	                0x16, 0xa7, 0x67, 0xd1, 0x34, 0xe1, 0xc2, 0xd4,
	                0x97, 0xfa, 0xd2, 0xcd, 0xaa, 0xe3, 0x6b, 0x27,
	                0x53, 0x70, 0xff, 0x51, 0x2a, 0x34, 0xbf, 0xa7
	            ], [
	                0x3d, 0x3b, 0xe3, 0xd2, 0xe8, 0x6e, 0xb0, 0x7a,
	                0x87, 0x84, 0x9b, 0x2e, 0xf1, 0x6e, 0xe3, 0x03,
	                0x10, 0xb8, 0x6e, 0x63, 0xb3, 0x47, 0x81, 0x63,
	                0xfd, 0x06, 0xb6, 0x59, 0x2b, 0xbd, 0xe5, 0x45
	            ]),
	            this.Gq.parsePoint([
	                0x59, 0x2d, 0x48, 0x15, 0x8a, 0x63, 0x58, 0xa2,
	                0x90, 0x0d, 0x45, 0x3d, 0x79, 0xe8, 0x8d, 0x6b,
	                0xc2, 0x0b, 0x7f, 0xa8, 0xcb, 0x2b, 0xfc, 0xfc,
	                0xdf, 0xd0, 0x82, 0x96, 0x05, 0x25, 0xad, 0x83
	            ], [
	                0x72, 0x31, 0xc3, 0xd1, 0xf8, 0x6f, 0xcc, 0x1b,
	                0x6c, 0x9e, 0x8c, 0x16, 0xae, 0x45, 0xa9, 0x35,
	                0x08, 0xc9, 0xc4, 0x9e, 0x8a, 0x74, 0x5e, 0x64,
	                0xb0, 0x76, 0x36, 0xfc, 0x6b, 0x03, 0x10, 0x3f
	            ]),
	            this.Gq.parsePoint([
	                0x18, 0xff, 0xac, 0x75, 0x07, 0xb8, 0xf0, 0x22,
	                0xeb, 0xa9, 0x72, 0x2a, 0xea, 0x93, 0xc6, 0xca,
	                0x74, 0x70, 0x82, 0x5a, 0x78, 0x7c, 0x1f, 0x98,
	                0x2b, 0x08, 0x3d, 0xda, 0x04, 0x90, 0xed, 0x32
	            ], [
	                0x30, 0x4b, 0x83, 0x60, 0x4a, 0x94, 0xff, 0x8a,
	                0x27, 0x87, 0xb0, 0x47, 0xe8, 0x23, 0xe5, 0x0a,
	                0x64, 0xed, 0xca, 0x0b, 0x1d, 0xcc, 0xb9, 0x38,
	                0x11, 0x96, 0x59, 0x7a, 0x1c, 0x63, 0xb3, 0x62
	            ]),
	            this.Gq.parsePoint([
	                0xdd, 0xe5, 0xdf, 0xc2, 0x86, 0x7a, 0x61, 0xba,
	                0x2e, 0x04, 0x6d, 0xd5, 0x25, 0x76, 0xd3, 0xd3,
	                0x3a, 0x24, 0x17, 0x3e, 0x32, 0xd7, 0x16, 0xca,
	                0xf0, 0xd6, 0xbc, 0x4b, 0xd1, 0x19, 0x43, 0x74
	            ], [
	                0x79, 0xb6, 0xe3, 0x0b, 0x18, 0x22, 0xd6, 0x1e,
	                0xad, 0xe5, 0x9b, 0x0a, 0xb3, 0xed, 0xbe, 0x8f,
	                0x42, 0x91, 0xc8, 0xe0, 0x81, 0xdd, 0xce, 0xde,
	                0xff, 0x00, 0xbc, 0x32, 0xeb, 0xfc, 0x1a, 0x93
	            ]),
	            this.Gq.parsePoint([
	                0xe0, 0xf7, 0x2a, 0x8c, 0x71, 0x39, 0x5e, 0x19,
	                0x06, 0x3b, 0x0e, 0x09, 0xf9, 0x47, 0xf8, 0x6c,
	                0x06, 0xf4, 0xb3, 0x00, 0xc8, 0x1d, 0x3b, 0xbb,
	                0xc4, 0x8d, 0xcb, 0x21, 0x9a, 0xb9, 0x60, 0xaa
	            ], [
	                0x6f, 0x23, 0x1e, 0x0a, 0x53, 0x8c, 0x8f, 0x54,
	                0xc0, 0x66, 0xc9, 0x3e, 0x1a, 0xf8, 0x57, 0xbc,
	                0x3b, 0x1c, 0x41, 0x88, 0x02, 0x27, 0x4c, 0xbd,
	                0xf5, 0xe3, 0x87, 0xd8, 0x87, 0x36, 0xf5, 0x76
	            ]),
	            this.Gq.parsePoint([
	                0x38, 0x53, 0x88, 0x07, 0x8e, 0xa2, 0xb4, 0x79,
	                0x2d, 0xac, 0x8f, 0xbe, 0x0b, 0x47, 0x48, 0xb9,
	                0x98, 0x00, 0xca, 0x08, 0x66, 0x62, 0xfa, 0x8e,
	                0xab, 0xd6, 0x25, 0x96, 0xdd, 0x7e, 0x5c, 0x53
	            ], [
	                0x4d, 0x21, 0x12, 0x11, 0x1d, 0x5b, 0xf4, 0x7b,
	                0xae, 0xd1, 0xc4, 0xa2, 0x68, 0x8c, 0xfa, 0x61,
	                0x6e, 0x7b, 0xbb, 0x64, 0xd4, 0x12, 0xf1, 0x6b,
	                0x37, 0x12, 0x88, 0xbf, 0xe9, 0x57, 0xea, 0x61
	            ]),
	            this.Gq.parsePoint([
	                0xb1, 0x08, 0xaa, 0x3e, 0x8b, 0xf1, 0xf7, 0x07,
	                0xf6, 0xba, 0x95, 0x56, 0xaa, 0x0f, 0x18, 0x71,
	                0x51, 0x97, 0x34, 0xa6, 0x98, 0x20, 0x3f, 0x75,
	                0x32, 0x92, 0x54, 0x43, 0xb2, 0x02, 0x0c, 0xbd
	            ], [
	                0x5a, 0x75, 0xfa, 0xe7, 0xad, 0x0b, 0xe2, 0x35,
	                0x20, 0x73, 0x47, 0x79, 0xef, 0x11, 0xf3, 0x25,
	                0xdd, 0xe7, 0xa6, 0xed, 0xc6, 0x33, 0x36, 0xef,
	                0x9f, 0xb5, 0x86, 0x61, 0xfc, 0xcc, 0x46, 0xa5
	            ]),
	            this.Gq.parsePoint([
	                0x06, 0x05, 0xb3, 0x50, 0x5f, 0x77, 0xe7, 0x4b,
	                0x22, 0xea, 0x7e, 0x67, 0xc3, 0x33, 0x3f, 0xf3,
	                0xb7, 0xb7, 0x71, 0x73, 0x83, 0x89, 0xd3, 0x05,
	                0xaa, 0x59, 0x4d, 0x8f, 0x55, 0x02, 0x37, 0xdb
	            ], [
	                0x74, 0x87, 0xad, 0xb2, 0xe0, 0x7c, 0x3a, 0xb9,
	                0x2e, 0x13, 0x86, 0x54, 0x67, 0x90, 0xa0, 0x11,
	                0x49, 0x7e, 0xb9, 0xfb, 0x98, 0x46, 0x71, 0x6b,
	                0x04, 0x79, 0x3d, 0xce, 0xa4, 0x30, 0xc7, 0xab
	            ]),
	            this.Gq.parsePoint([
	                0xd8, 0x18, 0x83, 0xa9, 0xcf, 0x1d, 0xc3, 0x04,
	                0x3c, 0x44, 0xf9, 0xf0, 0xf9, 0xff, 0x50, 0x2c,
	                0xd0, 0x45, 0xe4, 0x29, 0x4c, 0x37, 0x5a, 0x30,
	                0xa8, 0xa6, 0x5a, 0xbc, 0x0d, 0xd2, 0x82, 0x64
	            ], [
	                0x1d, 0x75, 0xc9, 0x9e, 0xb4, 0x4e, 0x2d, 0x8b,
	                0x43, 0xa5, 0x3f, 0x69, 0xb6, 0x88, 0x1f, 0x96,
	                0x92, 0x94, 0x35, 0xe2, 0xb3, 0x85, 0x0a, 0x37,
	                0x01, 0xae, 0xd0, 0x26, 0xe8, 0x0a, 0x32, 0x91
	            ]),
	            this.Gq.parsePoint([
	                0x93, 0xec, 0x90, 0x87, 0x9c, 0xd2, 0xd8, 0x6a,
	                0x22, 0x76, 0xf4, 0x4b, 0x42, 0xdf, 0x73, 0x62,
	                0x83, 0xd2, 0x97, 0x47, 0x07, 0x59, 0xde, 0x0a,
	                0xf2, 0xc6, 0xc9, 0x2f, 0x16, 0x84, 0x82, 0xaf
	            ], [
	                0x1f, 0x45, 0xf4, 0x80, 0xa0, 0xec, 0x76, 0x07,
	                0x51, 0x66, 0x79, 0xc2, 0xbb, 0x9f, 0x67, 0x7a,
	                0x89, 0xd4, 0x50, 0xec, 0x46, 0x9a, 0xc9, 0x30,
	                0xa1, 0x0d, 0x21, 0x3c, 0x1e, 0xb2, 0xa9, 0xcf
	            ]),
	            this.Gq.parsePoint([
	                0x4e, 0x9e, 0x9e, 0xb8, 0xe2, 0x67, 0xc0, 0xd6,
	                0x17, 0x60, 0xec, 0xab, 0xc9, 0xac, 0x19, 0xdd,
	                0xac, 0x5d, 0xb9, 0x5c, 0x28, 0x33, 0x4e, 0xc9,
	                0x9d, 0x49, 0xd7, 0x4d, 0x40, 0xb6, 0x6d, 0xaf
	            ], [
	                0x5d, 0xd7, 0x1c, 0x92, 0xd3, 0x11, 0xec, 0x15,
	                0xd5, 0xe2, 0xe6, 0xd3, 0xb8, 0xd5, 0x13, 0x36,
	                0x41, 0x5a, 0x60, 0x8e, 0x14, 0x04, 0x8c, 0x86,
	                0xce, 0xec, 0x76, 0x4e, 0x6d, 0xe6, 0xdf, 0x49
	            ]),
	            this.Gq.parsePoint([
	                0xce, 0xb4, 0xca, 0x98, 0xf6, 0x20, 0x19, 0x59,
	                0x6b, 0x9b, 0xc6, 0x23, 0x4e, 0xa5, 0xc2, 0x02,
	                0x99, 0x90, 0xf0, 0x8d, 0x06, 0x8f, 0x27, 0xee,
	                0xf4, 0xfa, 0x7d, 0x98, 0x97, 0xbf, 0xaf, 0x62
	            ], [
	                0x41, 0x60, 0xfb, 0xdd, 0xaf, 0x29, 0x86, 0xf3,
	                0xa1, 0x1e, 0x29, 0xb5, 0x89, 0xb9, 0xd9, 0x1d,
	                0x8b, 0x15, 0xc5, 0xf8, 0xbb, 0xf0, 0x2f, 0x7f,
	                0x17, 0x5f, 0x6e, 0xf8, 0xe7, 0xc2, 0xb1, 0xa4
	            ]),
	            this.Gq.parsePoint([
	                0x80, 0xe8, 0x70, 0x67, 0x09, 0xbd, 0x25, 0xa8,
	                0x49, 0x37, 0x41, 0x7e, 0x2d, 0x6a, 0x6d, 0xaf,
	                0xa8, 0x3d, 0x37, 0x38, 0xdf, 0xb4, 0x2f, 0x8e,
	                0xef, 0xa0, 0xfb, 0x52, 0x47, 0xd6, 0x99, 0x85
	            ], [
	                0x6a, 0x8f, 0x2e, 0xa6, 0xb2, 0x30, 0x1e, 0x3a,
	                0xef, 0xbd, 0x82, 0x46, 0xf6, 0xeb, 0x97, 0xea,
	                0x0c, 0xe1, 0x15, 0x5c, 0xe0, 0xb7, 0x2c, 0x47,
	                0x1d, 0x01, 0xb0, 0xd0, 0xb8, 0x8d, 0xa2, 0xca
	            ]),
	            this.Gq.parsePoint([
	                0x13, 0xbd, 0x26, 0x06, 0x06, 0x67, 0xf8, 0xeb,
	                0x7e, 0x56, 0xe7, 0x82, 0x85, 0x4a, 0xf3, 0xb3,
	                0xe0, 0x10, 0xcf, 0x18, 0x25, 0xa6, 0x84, 0xbc,
	                0x72, 0xb2, 0x87, 0xea, 0x7b, 0x2c, 0x23, 0x4c
	            ], [
	                0x18, 0x71, 0xc1, 0x5a, 0xa6, 0xf8, 0xcc, 0x3a,
	                0xda, 0x2d, 0x4b, 0xf6, 0xbb, 0x2b, 0xc6, 0x29,
	                0x6c, 0xa6, 0x58, 0x7c, 0x12, 0x2d, 0xf3, 0xb4,
	                0x7a, 0x9f, 0xaa, 0x30, 0x25, 0x86, 0x3a, 0x8c
	            ]),
	            this.Gq.parsePoint([
	                0x7d, 0x5e, 0x69, 0xba, 0xce, 0x92, 0x0e, 0x8e,
	                0xd2, 0xd0, 0xb4, 0x3a, 0xd1, 0x48, 0x49, 0xd7,
	                0x1e, 0x26, 0x72, 0x9c, 0xb3, 0x7f, 0x00, 0x9a,
	                0xe1, 0x4e, 0x6d, 0x8a, 0x06, 0x5e, 0x90, 0x79
	            ], [
	                0x13, 0xd6, 0xc8, 0xd6, 0xae, 0x02, 0x73, 0xa1,
	                0x89, 0x01, 0x29, 0x77, 0x9f, 0xce, 0x34, 0xf0,
	                0xca, 0xf6, 0xf3, 0x53, 0xbf, 0xde, 0x9e, 0xe3,
	                0x37, 0x27, 0x86, 0x78, 0xc9, 0xb6, 0xe7, 0x58
	            ])
	        ];
	        this.gt = this.Gq.parsePoint([
	            0xe2, 0xab, 0x81, 0xde, 0xf5, 0x93, 0xe9, 0x99,
	            0xc9, 0x75, 0xa8, 0xa4, 0x86, 0x68, 0xb9, 0xa0,
	            0x7e, 0x55, 0x94, 0xcf, 0xd6, 0x8f, 0xac, 0x29,
	            0xf1, 0x7a, 0x81, 0x1c, 0xb2, 0x6b, 0x3e, 0x10
	        ], [
	            0x75, 0x63, 0x11, 0xf8, 0x96, 0xc5, 0x03, 0xec,
	            0xdb, 0x2f, 0x60, 0x8a, 0x1c, 0xcb, 0xfa, 0x37,
	            0x8a, 0x95, 0xeb, 0x45, 0x78, 0xe6, 0x5f, 0x19,
	            0x0f, 0x1a, 0x8b, 0x54, 0x4d, 0x20, 0xb0, 0x82
	        ]);
	    }
	}
	class P384ECGroupParams {
	    constructor() {
	        this.descGq = ECGroup.P384;
	        this.Gq = new Group(this.descGq);
	        this.oid = "1.3.6.1.4.1.311.75.1.2.2";
	        this.g = [
	            this.Gq.parsePoint([
	                0x4a, 0xae, 0x57, 0x9d, 0xd5, 0x6d, 0x78, 0x09,
	                0x0b, 0x99, 0x21, 0xf3, 0x1b, 0xf7, 0x29, 0xf0,
	                0x74, 0x12, 0x1a, 0x3a, 0xdf, 0xfa, 0x2d, 0x31,
	                0xd0, 0x12, 0x15, 0xbe, 0xee, 0x1d, 0xc4, 0xdf,
	                0x9d, 0xf4, 0x63, 0xfd, 0x5e, 0x2b, 0x8f, 0x6c,
	                0x6b, 0x0a, 0x42, 0x16, 0x25, 0x8a, 0xc8, 0x44
	            ], [
	                0x3c, 0x3b, 0x8a, 0x23, 0xc5, 0xd6, 0x6a, 0xa2,
	                0xf0, 0x96, 0x45, 0x21, 0x19, 0x0a, 0x92, 0x81,
	                0x45, 0x1e, 0x9a, 0xe3, 0xac, 0xe4, 0xb7, 0x37,
	                0x6e, 0x02, 0xd7, 0xb3, 0x94, 0x9e, 0x22, 0x74,
	                0xe8, 0x44, 0x8c, 0xad, 0xef, 0x7e, 0x51, 0x99,
	                0x17, 0x20, 0xb4, 0x9a, 0x45, 0xb0, 0x58, 0x05
	            ]),
	            this.Gq.parsePoint([
	                0x03, 0x2f, 0x08, 0x6e, 0xac, 0x7b, 0xeb, 0x55,
	                0xa0, 0xc9, 0x5e, 0x5a, 0xd9, 0x96, 0xe3, 0x9d,
	                0xde, 0x74, 0xb3, 0xb6, 0x6d, 0xfb, 0xc2, 0xb8,
	                0xf1, 0x25, 0x29, 0xd9, 0xdf, 0x4a, 0x2c, 0xb8,
	                0x4a, 0xa5, 0x4c, 0xe6, 0x9a, 0xb1, 0xfb, 0x22,
	                0xcd, 0x7f, 0xd7, 0x99, 0x67, 0xd2, 0x61, 0xc2
	            ], [
	                0x16, 0xbb, 0xf0, 0x78, 0x65, 0x4e, 0x39, 0x16,
	                0x80, 0xbd, 0xb5, 0x74, 0x95, 0x01, 0x8c, 0xc8,
	                0xfe, 0x05, 0x13, 0x0a, 0xbf, 0xda, 0xa8, 0x4a,
	                0xb4, 0xaf, 0x90, 0xd0, 0xd2, 0xd6, 0xc0, 0x1f,
	                0xfd, 0xa8, 0xbc, 0x96, 0xcf, 0xcb, 0x00, 0x16,
	                0xf3, 0xdb, 0x13, 0xd8, 0x0a, 0xe8, 0xa2, 0xd0
	            ]),
	            this.Gq.parsePoint([
	                0xd6, 0x58, 0x3a, 0xfe, 0x48, 0x31, 0x1b, 0xec,
	                0x5c, 0x90, 0x16, 0x68, 0x25, 0x31, 0xc9, 0x35,
	                0xcf, 0x3f, 0xa9, 0x8e, 0x33, 0xd5, 0x03, 0x35,
	                0x48, 0x20, 0xc9, 0x9f, 0xb2, 0xe9, 0x02, 0xea,
	                0xcd, 0xb4, 0x19, 0x44, 0x12, 0x03, 0xe2, 0x87,
	                0xb0, 0xd3, 0x3a, 0xdb, 0xbe, 0x91, 0x2e, 0x33
	            ], [
	                0x7f, 0x9e, 0x35, 0xc0, 0xc0, 0xda, 0xf2, 0xe6,
	                0x8e, 0xd1, 0x35, 0xeb, 0xc0, 0x79, 0x71, 0xd5,
	                0x8e, 0x0e, 0x6a, 0xc8, 0xda, 0x69, 0xf5, 0x4f,
	                0x0c, 0x09, 0x3e, 0x24, 0xdd, 0x3f, 0x62, 0x75,
	                0x1e, 0x81, 0x6b, 0x6f, 0x6e, 0x1f, 0xcb, 0x66,
	                0x22, 0x6c, 0x4f, 0x0b, 0x35, 0xf9, 0xac, 0xdc
	            ]),
	            this.Gq.parsePoint([
	                0x3e, 0xf8, 0x51, 0xb6, 0xe0, 0xa8, 0x4e, 0x24,
	                0xfc, 0x99, 0x9b, 0x05, 0x3c, 0xf6, 0xac, 0xf3,
	                0x2a, 0xdc, 0x94, 0x17, 0x84, 0xae, 0xf0, 0xde,
	                0x14, 0x82, 0x3e, 0xf7, 0xab, 0xbe, 0x7e, 0x7e,
	                0x49, 0xe7, 0xd8, 0x0c, 0xd3, 0x52, 0x95, 0xea,
	                0xdf, 0x33, 0x22, 0x65, 0xd4, 0xda, 0x16, 0x5f
	            ], [
	                0x18, 0x28, 0x99, 0xd3, 0x46, 0x52, 0x62, 0x6c,
	                0x74, 0x74, 0x98, 0x93, 0x66, 0xb1, 0xf1, 0x7a,
	                0xd4, 0xd9, 0xc8, 0x12, 0x86, 0x3a, 0x67, 0xbc,
	                0xdf, 0x7d, 0x85, 0xc0, 0xed, 0x59, 0xcb, 0x73,
	                0x20, 0x66, 0x3e, 0xbb, 0x8f, 0xff, 0x3d, 0x5f,
	                0x56, 0x32, 0xe0, 0xa7, 0x5e, 0x00, 0x99, 0x66
	            ]),
	            this.Gq.parsePoint([
	                0x0b, 0x83, 0x44, 0x03, 0x1a, 0x95, 0x8a, 0x37,
	                0x4d, 0xe8, 0xee, 0x07, 0x11, 0xc1, 0x55, 0x54,
	                0x40, 0x4b, 0xfe, 0xdc, 0xa8, 0x0e, 0x48, 0x89,
	                0x92, 0x2b, 0xdb, 0x0c, 0xeb, 0xad, 0x3a, 0x30,
	                0xc9, 0x22, 0xf5, 0x49, 0x2d, 0x2c, 0xe4, 0x88,
	                0x4b, 0xa1, 0xc7, 0x7b, 0x57, 0x2f, 0xa0, 0xbd
	            ], [
	                0x0d, 0x7d, 0x70, 0x7c, 0xec, 0x2e, 0xcb, 0xce,
	                0xd7, 0x6f, 0x32, 0xd4, 0x3c, 0xe7, 0xb5, 0x5c,
	                0xbd, 0x53, 0x27, 0x3f, 0x55, 0x60, 0x5b, 0x7b,
	                0x9b, 0xac, 0x8b, 0x3f, 0x52, 0x1b, 0xb1, 0x53,
	                0x96, 0x86, 0x96, 0x7b, 0xe1, 0x8b, 0x5a, 0xa4,
	                0x1a, 0x71, 0x65, 0xf7, 0x26, 0xab, 0x5d, 0xbb
	            ]),
	            this.Gq.parsePoint([
	                0xd8, 0x65, 0x19, 0x82, 0xf1, 0xcf, 0xab, 0x26,
	                0x72, 0x70, 0x21, 0x9a, 0xee, 0x25, 0x07, 0x36,
	                0xd5, 0x35, 0xc2, 0x89, 0xa3, 0x8c, 0x88, 0x5d,
	                0xf2, 0x8e, 0xeb, 0xf6, 0x0f, 0x76, 0x3a, 0x12,
	                0xa1, 0x66, 0x20, 0xac, 0xc5, 0x95, 0x69, 0x73,
	                0x08, 0xee, 0xd1, 0xdb, 0x05, 0xac, 0xd4, 0xf0
	            ], [
	                0x2f, 0xc4, 0x3a, 0x11, 0xb8, 0x28, 0xc8, 0x54,
	                0x6a, 0xb8, 0xc1, 0xc6, 0xae, 0xb4, 0x1a, 0x68,
	                0x57, 0xc4, 0x81, 0x59, 0x04, 0x17, 0xb6, 0x59,
	                0xac, 0x8b, 0xd3, 0xee, 0x53, 0xc7, 0x0f, 0xd3,
	                0xf7, 0xaa, 0x13, 0xf0, 0x65, 0x70, 0x16, 0x88,
	                0x23, 0xaf, 0xfc, 0xe8, 0x4a, 0x5e, 0x86, 0x1d
	            ]),
	            this.Gq.parsePoint([
	                0xe4, 0x2b, 0xc1, 0x76, 0xe1, 0x3b, 0xde, 0xcf,
	                0x2b, 0x31, 0x60, 0x18, 0xa2, 0x2c, 0xf9, 0x51,
	                0x02, 0xb7, 0x1a, 0x1f, 0xa8, 0xac, 0x1c, 0xfe,
	                0x14, 0xee, 0xc5, 0x4c, 0xad, 0x25, 0x6a, 0x9a,
	                0xb9, 0xb4, 0xa7, 0xa8, 0xef, 0x3c, 0xfd, 0xe3,
	                0x38, 0x4f, 0xe4, 0xa1, 0xbc, 0x11, 0xc2, 0xf4
	            ], [
	                0x4e, 0x26, 0x00, 0x27, 0x35, 0xc9, 0x26, 0x97,
	                0x87, 0x70, 0x57, 0x25, 0x60, 0x38, 0xe7, 0x93,
	                0x4c, 0x1d, 0x42, 0x81, 0x26, 0xf4, 0x1e, 0x77,
	                0x1b, 0x19, 0x08, 0x40, 0xdb, 0xac, 0x0f, 0x59,
	                0xbd, 0x5e, 0x07, 0x02, 0x25, 0x22, 0xb6, 0x38,
	                0xa2, 0x93, 0x3e, 0x14, 0x63, 0x39, 0xdc, 0xc6
	            ]),
	            this.Gq.parsePoint([
	                0xd7, 0x14, 0x10, 0xb3, 0xe3, 0xa2, 0x22, 0xaa,
	                0xfb, 0x7f, 0x53, 0xed, 0x4c, 0xd8, 0x29, 0x9e,
	                0x44, 0x27, 0x31, 0x20, 0x3b, 0xec, 0xf6, 0x43,
	                0xef, 0x81, 0xda, 0x37, 0x1d, 0x81, 0x42, 0x19,
	                0x1c, 0xf2, 0x5a, 0x27, 0x01, 0x95, 0x87, 0x29,
	                0x4d, 0x23, 0x87, 0x0c, 0x78, 0xfc, 0xa0, 0x49
	            ], [
	                0x5d, 0xc9, 0x80, 0x0a, 0xd0, 0xed, 0xa0, 0x33,
	                0xab, 0xe1, 0x34, 0xdd, 0xd8, 0x94, 0xf2, 0x96,
	                0xb5, 0xae, 0xbd, 0x44, 0x58, 0xee, 0x42, 0x54,
	                0xce, 0x70, 0xf8, 0x4d, 0xfb, 0x0d, 0xe1, 0x8f,
	                0xca, 0x99, 0xbf, 0x79, 0x5c, 0xa7, 0xe2, 0x08,
	                0x18, 0x2e, 0xf6, 0xc4, 0x6d, 0x7b, 0xd4, 0x94
	            ]),
	            this.Gq.parsePoint([
	                0x68, 0x87, 0x2b, 0x16, 0x4a, 0x6e, 0x9b, 0x8f,
	                0x99, 0x66, 0x8b, 0x5b, 0xfd, 0x4a, 0xc0, 0x77,
	                0x0d, 0xea, 0x64, 0xe3, 0x77, 0x32, 0xa3, 0x84,
	                0xbc, 0x39, 0xc3, 0x24, 0x84, 0xb8, 0x60, 0x91,
	                0xcd, 0x47, 0xdd, 0xea, 0xe5, 0x26, 0xb1, 0x80,
	                0x65, 0xe8, 0x66, 0x3e, 0x1e, 0xcb, 0x8b, 0x80
	            ], [
	                0x66, 0x60, 0x8a, 0xa7, 0xcf, 0x0a, 0xb5, 0x3c,
	                0x37, 0x50, 0x34, 0xdd, 0xe3, 0x97, 0x36, 0xdc,
	                0x81, 0xd6, 0x83, 0x1b, 0xc6, 0xee, 0x78, 0xc7,
	                0x14, 0xe0, 0x10, 0xaf, 0xa5, 0xc8, 0x54, 0x25,
	                0xa7, 0xed, 0x28, 0xef, 0x6f, 0x46, 0x2a, 0xeb,
	                0x4d, 0x79, 0x52, 0xea, 0xf4, 0x88, 0xd0, 0xc1
	            ]),
	            this.Gq.parsePoint([
	                0xa0, 0x4d, 0xec, 0xc7, 0xe9, 0xf0, 0xcf, 0x88,
	                0x93, 0x0a, 0xb2, 0x6c, 0x96, 0xd6, 0x95, 0x23,
	                0x76, 0xb4, 0xc3, 0xa3, 0xdb, 0x75, 0x25, 0x6e,
	                0xfd, 0xd4, 0x66, 0xf5, 0x1f, 0x7c, 0x01, 0x84,
	                0x1a, 0x5f, 0x4e, 0x6a, 0x9f, 0x11, 0x87, 0x7f,
	                0xf2, 0x86, 0xcb, 0xc7, 0x43, 0x06, 0xbb, 0xf1
	            ], [
	                0x18, 0xc8, 0x09, 0x28, 0xac, 0x20, 0x82, 0xc0,
	                0x4f, 0x30, 0x0d, 0x31, 0xb2, 0xe6, 0xd0, 0x0e,
	                0xe6, 0x87, 0x72, 0x5e, 0xb8, 0x6f, 0x0d, 0xc7,
	                0xc7, 0xa8, 0xfb, 0x95, 0x99, 0x3c, 0xea, 0xca,
	                0x8a, 0xfc, 0xe4, 0x80, 0xed, 0xc7, 0x27, 0x84,
	                0x2e, 0xfe, 0xd1, 0x48, 0x88, 0x2d, 0xba, 0xa6
	            ]),
	            this.Gq.parsePoint([
	                0xe9, 0x80, 0x2c, 0xe5, 0x36, 0x1d, 0xd7, 0x9e,
	                0xb1, 0x4f, 0x00, 0x4d, 0x1e, 0x2a, 0x7d, 0xab,
	                0x4c, 0xa5, 0x58, 0x62, 0xb9, 0x37, 0x59, 0x3c,
	                0x86, 0x03, 0x5f, 0xce, 0x0d, 0x3a, 0x49, 0xc1,
	                0xa1, 0x34, 0x7e, 0x9d, 0x89, 0xe9, 0x34, 0x8b,
	                0xf8, 0x46, 0x0f, 0xe6, 0x46, 0x68, 0xaa, 0xe7
	            ], [
	                0x29, 0x99, 0x29, 0x00, 0x81, 0x1b, 0x12, 0xc4,
	                0x2e, 0xfd, 0xe1, 0x23, 0xcf, 0x65, 0xb8, 0x0b,
	                0xb2, 0x49, 0xe4, 0x8e, 0x3f, 0x53, 0xe4, 0x47,
	                0x75, 0xcb, 0x1b, 0x36, 0x53, 0x6e, 0x28, 0x6b,
	                0x23, 0xe0, 0x8d, 0x4c, 0x59, 0xf5, 0x0d, 0xdd,
	                0x89, 0xb9, 0xdb, 0x4e, 0x01, 0x2a, 0x4f, 0x14
	            ]),
	            this.Gq.parsePoint([
	                0x85, 0x37, 0xb2, 0x9a, 0x8b, 0x60, 0xc6, 0x73,
	                0x94, 0xd3, 0x03, 0x78, 0xdb, 0x59, 0x0f, 0xc7,
	                0x04, 0xff, 0x36, 0x3a, 0x6c, 0x79, 0x01, 0xee,
	                0x29, 0xbb, 0x8b, 0x18, 0x3f, 0xdc, 0x8b, 0x0a,
	                0xea, 0xd5, 0xf4, 0x38, 0xe4, 0x43, 0x84, 0xd4,
	                0x1e, 0xd5, 0xf2, 0x6b, 0xe6, 0xa4, 0xc7, 0xe7
	            ], [
	                0x75, 0xc3, 0xbe, 0x29, 0x5e, 0x38, 0x81, 0x3b,
	                0x27, 0x22, 0xbc, 0xfc, 0xba, 0xd4, 0x91, 0xc6,
	                0x2b, 0xd8, 0x1a, 0x14, 0x38, 0x86, 0x4d, 0x8f,
	                0x54, 0xa4, 0x8a, 0x43, 0x8a, 0x6a, 0x55, 0x6c,
	                0x5c, 0xc6, 0xbd, 0x95, 0x49, 0xc2, 0x5c, 0xe7,
	                0xe3, 0x9d, 0x98, 0x61, 0xa3, 0x0b, 0x6e, 0x08
	            ]),
	            this.Gq.parsePoint([
	                0xe4, 0x6b, 0xe8, 0xff, 0xb1, 0xa6, 0x12, 0x77,
	                0x57, 0x4b, 0x4d, 0x4e, 0x75, 0x20, 0xbb, 0x28,
	                0xdf, 0x1a, 0xa9, 0x2b, 0x75, 0x39, 0x0b, 0xf6,
	                0xaa, 0x81, 0x98, 0x84, 0xa4, 0x7d, 0xb6, 0x7e,
	                0x0a, 0x5a, 0x3f, 0x75, 0x4c, 0xef, 0x6d, 0xc5,
	                0x7d, 0x07, 0x25, 0xc7, 0x96, 0x80, 0x6d, 0x85
	            ], [
	                0x1e, 0x0c, 0xfb, 0xc5, 0x09, 0x25, 0x82, 0xf7,
	                0x02, 0x00, 0x2f, 0xac, 0x85, 0xdd, 0x2f, 0x32,
	                0xef, 0x56, 0x8e, 0x00, 0x98, 0x01, 0xc3, 0xd7,
	                0x96, 0x11, 0xaa, 0x3a, 0xa0, 0xee, 0xbf, 0x2d,
	                0x55, 0x91, 0x01, 0x14, 0x45, 0x12, 0xfb, 0x2c,
	                0x1a, 0x59, 0x7f, 0x3f, 0x0b, 0x05, 0xf5, 0x43
	            ]),
	            this.Gq.parsePoint([
	                0xf6, 0xd6, 0xdf, 0x3c, 0x86, 0x7b, 0x88, 0x6a,
	                0x4b, 0xd3, 0x77, 0x56, 0x05, 0x6e, 0x72, 0x00,
	                0x9d, 0x2e, 0x26, 0x4c, 0xb2, 0x5d, 0xdd, 0x59,
	                0xc0, 0xb8, 0x3d, 0x4d, 0x0e, 0x40, 0x14, 0x4f,
	                0x64, 0x9f, 0x43, 0x57, 0xd4, 0x16, 0xa1, 0x77,
	                0x2f, 0x7a, 0x1e, 0x4e, 0x2b, 0xdd, 0xab, 0x15
	            ], [
	                0x06, 0xd9, 0xb5, 0x0e, 0x84, 0x82, 0x46, 0xf3,
	                0x10, 0xb9, 0x2f, 0x01, 0x83, 0x5d, 0x53, 0xdb,
	                0xee, 0x8e, 0x27, 0xf8, 0x83, 0xaa, 0x6d, 0x25,
	                0x49, 0xe5, 0x27, 0xfe, 0x78, 0x08, 0xa9, 0xcb,
	                0x61, 0x92, 0x31, 0x75, 0xa8, 0xee, 0xcd, 0x33,
	                0x28, 0x57, 0x4a, 0x3e, 0xd7, 0xbb, 0x59, 0xba
	            ]),
	            this.Gq.parsePoint([
	                0x38, 0x8a, 0x6c, 0xb5, 0x5c, 0x5d, 0x08, 0xbc,
	                0xea, 0xd8, 0x21, 0x1c, 0xfd, 0x20, 0xe3, 0x2c,
	                0x78, 0xeb, 0x6f, 0x06, 0xd7, 0x92, 0x10, 0x1a,
	                0x00, 0xc0, 0xd7, 0x57, 0x48, 0x00, 0x46, 0xf9,
	                0xc4, 0xaa, 0x5d, 0xf8, 0x82, 0x17, 0x6b, 0xbc,
	                0x8d, 0x83, 0x1f, 0x72, 0x81, 0x4a, 0x79, 0x0c
	            ], [
	                0x42, 0x7b, 0x89, 0x85, 0x18, 0x2f, 0x90, 0x36,
	                0x01, 0x9d, 0x28, 0x32, 0x56, 0x19, 0xb9, 0xca,
	                0x94, 0x42, 0x75, 0x08, 0x2b, 0xd2, 0xfd, 0x19,
	                0x85, 0x00, 0xc1, 0x7c, 0x9b, 0xb8, 0xae, 0x7d,
	                0x59, 0x1e, 0xfd, 0x64, 0xe1, 0x80, 0x70, 0xc4,
	                0xcf, 0x31, 0x64, 0xe0, 0x92, 0x6d, 0xfd, 0xcd
	            ]),
	            this.Gq.parsePoint([
	                0xf3, 0x0f, 0xbe, 0xec, 0x91, 0x29, 0x71, 0xdb,
	                0xaa, 0xd5, 0xed, 0x63, 0x3b, 0x5b, 0x2a, 0x37,
	                0x6a, 0xe6, 0x0e, 0x27, 0x86, 0xaf, 0x16, 0x96,
	                0x95, 0xaf, 0x00, 0xf6, 0xda, 0x9b, 0xbc, 0xfd,
	                0x9a, 0x43, 0x56, 0x40, 0x97, 0xc9, 0x02, 0x25,
	                0xc5, 0x4e, 0x2a, 0x63, 0xb9, 0xc0, 0x00, 0x4f
	            ], [
	                0x31, 0xfe, 0xb5, 0x90, 0x3c, 0xb5, 0x67, 0x9f,
	                0xe9, 0x68, 0x6f, 0x17, 0x30, 0x3e, 0x8b, 0xcf,
	                0x83, 0x35, 0xfa, 0x07, 0xf6, 0xfd, 0xe0, 0x6b,
	                0x70, 0x62, 0xe2, 0xd3, 0x37, 0xf7, 0x2c, 0x7a,
	                0xa1, 0xad, 0xee, 0x5f, 0xbf, 0x5c, 0xb3, 0x74,
	                0x28, 0x44, 0xf0, 0x7e, 0x02, 0xfd, 0x47, 0x6d
	            ]),
	            this.Gq.parsePoint([
	                0xbc, 0x56, 0x18, 0x7e, 0x62, 0xb3, 0xa3, 0xc2,
	                0x46, 0xdf, 0x01, 0xd8, 0xf8, 0x85, 0xc3, 0x4d,
	                0x54, 0xff, 0x81, 0x42, 0x4a, 0xbd, 0x1d, 0x22,
	                0x7b, 0x03, 0x3f, 0x06, 0xec, 0xce, 0xc6, 0x27,
	                0x8d, 0xc0, 0x75, 0x9a, 0x16, 0xd9, 0x0f, 0x0c,
	                0xc5, 0x16, 0x16, 0xc5, 0x0e, 0x9a, 0x88, 0x45
	            ], [
	                0x3a, 0x53, 0x2c, 0xd7, 0x4d, 0x1f, 0x73, 0xdc,
	                0x02, 0xbe, 0xfd, 0x8b, 0x00, 0x2d, 0xb3, 0x62,
	                0xeb, 0x13, 0x3b, 0x3d, 0x9c, 0xce, 0xc5, 0x45,
	                0x29, 0xf1, 0x5d, 0x73, 0x02, 0xda, 0x1d, 0x8b,
	                0x4c, 0x7b, 0x36, 0x65, 0x4e, 0x4f, 0x8d, 0x2a,
	                0x3e, 0x4d, 0xa5, 0xeb, 0x9b, 0x29, 0xa7, 0xe2
	            ]),
	            this.Gq.parsePoint([
	                0x89, 0x97, 0x72, 0x12, 0x6f, 0x98, 0x38, 0xec,
	                0x17, 0x89, 0x61, 0x50, 0x7c, 0xae, 0xd8, 0x25,
	                0x8b, 0x6f, 0x10, 0x2f, 0x5a, 0x77, 0x08, 0xba,
	                0xbf, 0x80, 0xdd, 0x1d, 0xcc, 0xdc, 0x70, 0x02,
	                0x1e, 0x4f, 0x41, 0xc2, 0xf7, 0x43, 0x8b, 0xeb,
	                0x67, 0xc9, 0xa2, 0xa9, 0xb4, 0xd5, 0x7f, 0x84
	            ], [
	                0x71, 0xb9, 0xa6, 0xfd, 0xb9, 0x1e, 0xbd, 0x0a,
	                0x29, 0x2b, 0xdb, 0x71, 0x83, 0x77, 0x30, 0x8e,
	                0xde, 0xda, 0x06, 0x3d, 0x07, 0xcb, 0x03, 0x4e,
	                0x1b, 0xc8, 0x6e, 0xa2, 0xf6, 0x5f, 0xa2, 0x0f,
	                0x09, 0x35, 0xc6, 0xc8, 0xc3, 0x78, 0xca, 0xee,
	                0xfe, 0x64, 0xdd, 0xbb, 0x3a, 0xdc, 0x79, 0xed
	            ]),
	            this.Gq.parsePoint([
	                0xcb, 0x2e, 0xbf, 0x80, 0x7f, 0x1e, 0x6f, 0xe4,
	                0x11, 0xdf, 0x68, 0x98, 0xcd, 0xf6, 0x52, 0xcb,
	                0xb9, 0xbd, 0xdf, 0x39, 0x47, 0x35, 0x50, 0x11,
	                0x42, 0x9d, 0x11, 0x1b, 0xb2, 0x61, 0x8d, 0xc4,
	                0x6d, 0xef, 0xca, 0x46, 0x9a, 0x09, 0xc1, 0x97,
	                0x48, 0xcf, 0x1d, 0x09, 0xaa, 0x82, 0x19, 0xbe
	            ], [
	                0x50, 0x23, 0x8a, 0x8b, 0x27, 0x07, 0xcd, 0xb8,
	                0x8c, 0x38, 0x1d, 0x57, 0x36, 0x9b, 0x4d, 0x78,
	                0x38, 0xd7, 0x89, 0x58, 0x76, 0xf9, 0xa3, 0xd8,
	                0x0a, 0x95, 0x56, 0xa5, 0xc7, 0x97, 0xa4, 0xd0,
	                0xdb, 0x83, 0x99, 0xfc, 0xd6, 0x57, 0xad, 0xd1,
	                0x93, 0x8b, 0x65, 0xc7, 0xaf, 0xad, 0x8a, 0x72
	            ]),
	            this.Gq.parsePoint([
	                0x95, 0xfa, 0x79, 0x5a, 0xa4, 0xf4, 0xc0, 0xda,
	                0x48, 0x64, 0x20, 0xfa, 0x94, 0x1b, 0x25, 0xd7,
	                0xf7, 0x0c, 0x80, 0x73, 0xb7, 0x8b, 0xcd, 0x88,
	                0x20, 0xd8, 0x14, 0x66, 0x89, 0xd8, 0x1e, 0x1d,
	                0xc2, 0xa4, 0x09, 0x8e, 0x86, 0xaf, 0xc2, 0x7b,
	                0x49, 0xc8, 0x6a, 0xef, 0xed, 0x1b, 0x0d, 0x61
	            ], [
	                0x62, 0x3d, 0x37, 0xc1, 0x3d, 0xcb, 0x6e, 0xa9,
	                0x57, 0x33, 0x72, 0x88, 0x8a, 0xf0, 0x8b, 0xea,
	                0xcf, 0x94, 0xc8, 0xdf, 0xfc, 0x2c, 0xb6, 0x15,
	                0x03, 0x0a, 0xe6, 0x12, 0xb0, 0xcf, 0x14, 0x78,
	                0x75, 0x1d, 0xc3, 0xb5, 0x6a, 0x66, 0xa5, 0x1d,
	                0xb4, 0xb9, 0x8e, 0x26, 0x4e, 0xb0, 0x16, 0xdd
	            ]),
	            this.Gq.parsePoint([
	                0x22, 0xf4, 0x33, 0x02, 0x0d, 0xc1, 0x29, 0xc7,
	                0xbe, 0x74, 0x55, 0x8e, 0xf9, 0xc2, 0x91, 0xf3,
	                0x93, 0x8e, 0x78, 0x17, 0xb4, 0x7d, 0x4b, 0x41,
	                0xa5, 0x92, 0x21, 0xd8, 0x5b, 0x10, 0xff, 0xd1,
	                0xb8, 0x15, 0x91, 0x9f, 0xb3, 0x71, 0x7e, 0x3e,
	                0x7e, 0x15, 0xe9, 0x3f, 0xb9, 0x7f, 0x6f, 0x7c
	            ], [
	                0x14, 0x45, 0x4c, 0xae, 0x0e, 0xec, 0xcb, 0xcc,
	                0x8e, 0x52, 0x15, 0x55, 0xfd, 0x2e, 0xc8, 0x22,
	                0xc2, 0x90, 0xc4, 0x64, 0x67, 0x1e, 0xa7, 0xaa,
	                0x99, 0xd5, 0x58, 0x90, 0x9f, 0xdc, 0xcc, 0xf6,
	                0x8e, 0x4d, 0x70, 0x95, 0xc4, 0x64, 0x7a, 0x16,
	                0xe4, 0x7f, 0x16, 0xc0, 0xb6, 0x88, 0x51, 0xc1
	            ]),
	            this.Gq.parsePoint([
	                0x45, 0x69, 0x82, 0xb2, 0x35, 0xd9, 0xd0, 0x13,
	                0xc9, 0x9b, 0x64, 0x09, 0x4d, 0x41, 0x29, 0x63,
	                0x1f, 0xb1, 0xc6, 0x21, 0x06, 0x28, 0x50, 0x5c,
	                0x74, 0x41, 0x33, 0xe6, 0xfa, 0x17, 0x5d, 0x14,
	                0x1f, 0xb4, 0xc0, 0x01, 0x05, 0xf8, 0x10, 0x28,
	                0x4c, 0x68, 0x80, 0xb4, 0x6a, 0x44, 0x06, 0xdf
	            ], [
	                0x52, 0xb8, 0x49, 0x82, 0x56, 0x51, 0x6a, 0x4f,
	                0xef, 0xde, 0x13, 0xb5, 0xa7, 0xbb, 0xd7, 0x2d,
	                0x3f, 0x19, 0xaa, 0x00, 0xb3, 0x62, 0x6d, 0xec,
	                0xdd, 0x9c, 0xd1, 0xff, 0x7d, 0x17, 0x5c, 0xf7,
	                0x44, 0xe2, 0x24, 0x16, 0xf3, 0x51, 0xf6, 0x2e,
	                0x5d, 0x01, 0xbe, 0x65, 0x1c, 0xa8, 0x27, 0x47
	            ]),
	            this.Gq.parsePoint([
	                0x45, 0x1f, 0x77, 0xcb, 0xcf, 0x22, 0xbe, 0xe6,
	                0xa4, 0x07, 0x28, 0x7e, 0xf9, 0xa3, 0x6f, 0x29,
	                0x3f, 0xa8, 0x22, 0xf3, 0x95, 0xf6, 0x4c, 0x2e,
	                0xdc, 0xcb, 0x9a, 0xb5, 0xf8, 0xee, 0x3f, 0xde,
	                0x86, 0xef, 0xdd, 0xcf, 0x33, 0x02, 0xe8, 0xe9,
	                0x29, 0x37, 0x32, 0xa0, 0x58, 0x33, 0x28, 0x16
	            ], [
	                0x77, 0x34, 0x01, 0xa1, 0x0f, 0xe5, 0x06, 0x9d,
	                0xbc, 0xc6, 0x87, 0x0c, 0xeb, 0x8b, 0x15, 0xd1,
	                0xcb, 0x35, 0x22, 0x7b, 0xd8, 0xaf, 0x7d, 0x70,
	                0xb6, 0x3d, 0x36, 0xe9, 0x56, 0x13, 0xde, 0xba,
	                0x2d, 0x60, 0x03, 0x83, 0x50, 0x27, 0x49, 0x3c,
	                0x04, 0x63, 0x0e, 0xdb, 0x27, 0x00, 0xb9, 0x65
	            ]),
	            this.Gq.parsePoint([
	                0xa4, 0xad, 0x50, 0xb7, 0xdb, 0xcf, 0xcd, 0xc4,
	                0x27, 0xe7, 0x2f, 0x85, 0x0a, 0x1b, 0xb0, 0x40,
	                0x28, 0x1c, 0x5f, 0x99, 0xb9, 0x14, 0x15, 0x1c,
	                0x47, 0xac, 0x48, 0xf9, 0xfb, 0x7b, 0x85, 0xa0,
	                0x58, 0x58, 0xf3, 0x03, 0x58, 0x8c, 0x57, 0xd2,
	                0xff, 0x66, 0xb5, 0x86, 0x71, 0x45, 0xfb, 0xdb
	            ], [
	                0x0a, 0x56, 0x43, 0x36, 0xb5, 0xe3, 0x7a, 0xac,
	                0x39, 0xba, 0xa0, 0x87, 0x8c, 0x6c, 0x50, 0xd3,
	                0xd3, 0x6f, 0x54, 0x09, 0xf1, 0x02, 0xf9, 0xb8,
	                0x68, 0x73, 0x28, 0x09, 0x45, 0x62, 0xca, 0x62,
	                0x88, 0xb2, 0xb6, 0x9f, 0xee, 0x43, 0x89, 0x1a,
	                0xd5, 0x61, 0xd3, 0x2e, 0xd4, 0xbb, 0x20, 0xf8
	            ]),
	            this.Gq.parsePoint([
	                0xf1, 0xb4, 0xf1, 0x32, 0xb3, 0xc2, 0x9a, 0x9e,
	                0x34, 0x67, 0xa0, 0x22, 0x08, 0x17, 0xf2, 0x58,
	                0x78, 0x43, 0xe7, 0x75, 0x43, 0xe8, 0x12, 0xec,
	                0x52, 0x4d, 0x7d, 0x41, 0x3c, 0x6c, 0x20, 0xc0,
	                0x3e, 0xc3, 0x9b, 0x55, 0x83, 0x62, 0x20, 0x71,
	                0x7d, 0xdd, 0x9a, 0xf4, 0x2a, 0xff, 0xe6, 0x67
	            ], [
	                0x34, 0x47, 0xa1, 0x34, 0x2d, 0x40, 0xa8, 0xc0,
	                0x94, 0x06, 0x03, 0x45, 0x10, 0x2e, 0x64, 0xb1,
	                0xb3, 0x87, 0x1b, 0x80, 0xef, 0x28, 0xd3, 0x27,
	                0x70, 0xf8, 0x49, 0xb5, 0x7e, 0x76, 0x96, 0x11,
	                0x8f, 0x59, 0x6b, 0x8b, 0x11, 0x9b, 0xab, 0xdd,
	                0x2d, 0x7c, 0xcf, 0x27, 0xb5, 0x5a, 0xcd, 0x17
	            ]),
	            this.Gq.parsePoint([
	                0x09, 0x70, 0x27, 0x9c, 0x58, 0x14, 0x7d, 0xd4,
	                0x0d, 0x2a, 0xaf, 0xeb, 0xce, 0x3e, 0x0b, 0xc1,
	                0x3e, 0xe4, 0xdd, 0xbb, 0x74, 0x69, 0x09, 0xcc,
	                0xe2, 0x84, 0x9b, 0xed, 0x98, 0xd8, 0xb7, 0xb3,
	                0x6e, 0xd9, 0x71, 0xa1, 0x7a, 0x8e, 0x75, 0xcd,
	                0xb5, 0xf3, 0xeb, 0xdc, 0x3e, 0x71, 0xb4, 0x7b
	            ], [
	                0x2c, 0xc1, 0x7a, 0xcd, 0xa0, 0x96, 0xb5, 0x63,
	                0x93, 0xde, 0x63, 0xc6, 0x6b, 0x23, 0x42, 0xa0,
	                0x3e, 0x2e, 0x50, 0x4f, 0x12, 0x39, 0x80, 0x01,
	                0xb8, 0xd9, 0x0f, 0xe1, 0x58, 0x1d, 0x26, 0x96,
	                0xbf, 0x86, 0x43, 0x46, 0x58, 0x54, 0xe0, 0xd9,
	                0xad, 0xe9, 0xee, 0x21, 0x45, 0xf3, 0xc0, 0x2f
	            ]),
	            this.Gq.parsePoint([
	                0x2b, 0x5e, 0x17, 0xc2, 0x19, 0xe4, 0xea, 0x95,
	                0xaf, 0x39, 0xb2, 0x4a, 0x20, 0xdc, 0x4d, 0x50,
	                0x86, 0x70, 0x7e, 0xd8, 0x06, 0x6b, 0xd2, 0x98,
	                0xe3, 0x04, 0x7d, 0x64, 0x59, 0x82, 0x3f, 0xf1,
	                0x02, 0xef, 0x61, 0x7d, 0x46, 0x70, 0xd5, 0x9e,
	                0x0e, 0xfb, 0x96, 0x5e, 0x17, 0x9b, 0x01, 0xa6
	            ], [
	                0x24, 0x20, 0x23, 0x56, 0x7c, 0x67, 0x0b, 0xcf,
	                0x21, 0xc9, 0xc2, 0xef, 0x69, 0xbb, 0x8b, 0x87,
	                0xd7, 0xa8, 0xdc, 0xd0, 0x34, 0xb6, 0x66, 0x06,
	                0x90, 0x08, 0x12, 0x39, 0x3e, 0xe9, 0x98, 0x9b,
	                0xc3, 0x7e, 0x25, 0xab, 0x67, 0x2a, 0x3e, 0xa4,
	                0xef, 0x3b, 0x02, 0x8f, 0x83, 0x49, 0x56, 0x23
	            ]),
	            this.Gq.parsePoint([
	                0x81, 0xfe, 0x66, 0xdc, 0x8e, 0x7c, 0x58, 0x3e,
	                0xd1, 0x52, 0x44, 0xb5, 0xd7, 0xec, 0x86, 0x97,
	                0x25, 0xbc, 0x35, 0x34, 0x6f, 0xf3, 0x06, 0x3e,
	                0x6a, 0x22, 0x48, 0x3e, 0x92, 0xd6, 0x70, 0x8b,
	                0x59, 0x8f, 0x41, 0xe4, 0x26, 0x1d, 0x4c, 0x52,
	                0xc8, 0x1f, 0xd7, 0x03, 0x85, 0x3c, 0x0b, 0x5d
	            ], [
	                0x23, 0xf7, 0x5a, 0x94, 0xe5, 0xf8, 0x64, 0x85,
	                0x06, 0x97, 0x61, 0x9c, 0xab, 0xb8, 0xb3, 0x4e,
	                0xff, 0x56, 0x9f, 0x29, 0xd8, 0x82, 0x75, 0xb7,
	                0xa7, 0xae, 0x1d, 0x77, 0x80, 0x9e, 0x3a, 0x5a,
	                0x42, 0x5c, 0x82, 0xb5, 0xbd, 0xb8, 0xd7, 0xaa,
	                0x75, 0xf9, 0x5c, 0x53, 0xa3, 0x7c, 0xf9, 0x60
	            ]),
	            this.Gq.parsePoint([
	                0x46, 0xe4, 0xd4, 0xbc, 0x62, 0x81, 0xd4, 0x94,
	                0x3e, 0x0b, 0x5c, 0xea, 0xd8, 0x6e, 0xb8, 0xf5,
	                0x82, 0x1b, 0xff, 0xd4, 0x28, 0x88, 0xb5, 0x79,
	                0xdb, 0x71, 0x71, 0xc8, 0x24, 0x16, 0xbc, 0xf8,
	                0x63, 0x18, 0x7d, 0x86, 0x81, 0x55, 0xb4, 0xa0,
	                0xae, 0x1f, 0x3e, 0x44, 0xcf, 0x71, 0x07, 0xaf
	            ], [
	                0x14, 0x64, 0x24, 0x6c, 0x54, 0xca, 0x3a, 0x8b,
	                0x70, 0xda, 0x3d, 0xa9, 0x3f, 0xfd, 0x88, 0x66,
	                0x33, 0x6e, 0x7a, 0xba, 0xda, 0x50, 0x9d, 0x39,
	                0x27, 0x6d, 0x08, 0x5a, 0x9c, 0x9d, 0xd5, 0x5c,
	                0x04, 0xff, 0xde, 0xf0, 0xc5, 0xec, 0x06, 0x98,
	                0x3a, 0xab, 0x0e, 0x63, 0xfc, 0x11, 0x86, 0xfd
	            ]),
	            this.Gq.parsePoint([
	                0xe3, 0xd3, 0x27, 0x37, 0x71, 0x44, 0xa4, 0x06,
	                0xff, 0x2d, 0x22, 0xfb, 0x26, 0xca, 0x63, 0x4d,
	                0x6a, 0x8a, 0x0e, 0xe4, 0xbb, 0x39, 0xaa, 0xd0,
	                0xb3, 0x5e, 0x66, 0x36, 0xac, 0xcc, 0xca, 0xf2,
	                0x0a, 0xca, 0x78, 0xfc, 0x1a, 0x02, 0xcc, 0x60,
	                0x48, 0x05, 0x33, 0x30, 0x34, 0x07, 0x8e, 0xf8
	            ], [
	                0x47, 0xec, 0x98, 0xd3, 0x18, 0xf8, 0x71, 0xcb,
	                0x6f, 0xe4, 0x91, 0xbf, 0xda, 0xf2, 0x61, 0xd8,
	                0x62, 0xac, 0x92, 0xea, 0x5d, 0x26, 0x9b, 0x94,
	                0x18, 0x75, 0xe6, 0x36, 0xdc, 0x5c, 0xe2, 0xcc,
	                0x74, 0x66, 0x90, 0x8a, 0x60, 0xaf, 0x47, 0x9a,
	                0xa2, 0xc7, 0x0f, 0x94, 0xba, 0x0a, 0xd3, 0x03
	            ]),
	            this.Gq.parsePoint([
	                0xbd, 0x42, 0x54, 0x97, 0x21, 0x9e, 0x2b, 0xca,
	                0x3b, 0x47, 0x62, 0x9b, 0x19, 0xf7, 0x9d, 0x4d,
	                0xcb, 0x27, 0x62, 0x84, 0xb4, 0x5c, 0x3f, 0x5a,
	                0xc9, 0xb4, 0x7b, 0x76, 0xb9, 0x0e, 0xce, 0x92,
	                0x35, 0x65, 0x5c, 0xf9, 0x57, 0xf7, 0x7a, 0xda,
	                0x90, 0x2d, 0xd1, 0x75, 0xe4, 0x94, 0xda, 0x91
	            ], [
	                0x29, 0x80, 0xe0, 0xc8, 0xd4, 0x4a, 0x32, 0x34,
	                0x52, 0x11, 0x55, 0x4b, 0xf1, 0xb7, 0xac, 0x1e,
	                0xde, 0xf0, 0xc5, 0xcc, 0x1a, 0x60, 0xd4, 0x2a,
	                0xd4, 0xe1, 0x9e, 0x9b, 0x9a, 0xaa, 0xe4, 0xcf,
	                0x1f, 0xbc, 0xa9, 0xeb, 0x01, 0xe1, 0x32, 0xdf,
	                0x66, 0xf8, 0x98, 0x57, 0xb9, 0x30, 0x30, 0x08
	            ]),
	            this.Gq.parsePoint([
	                0x2a, 0x6c, 0x57, 0x6d, 0xf2, 0xaf, 0x7b, 0x14,
	                0x05, 0xda, 0xad, 0xe9, 0xfb, 0x24, 0xbb, 0xfe,
	                0xb3, 0xfa, 0x9c, 0x55, 0x86, 0x03, 0x60, 0x88,
	                0xe0, 0x7d, 0x9d, 0xbd, 0x31, 0x55, 0xe9, 0xa9,
	                0x69, 0x22, 0xae, 0xe1, 0x85, 0xf7, 0x31, 0x57,
	                0x9c, 0x7d, 0x8c, 0xd1, 0xa7, 0xa3, 0x44, 0xe4
	            ], [
	                0x44, 0x91, 0x6f, 0xe5, 0xda, 0x07, 0xe5, 0xad,
	                0xfe, 0xf1, 0x83, 0x7d, 0x5d, 0x3f, 0xc2, 0xae,
	                0xdd, 0xd5, 0xb0, 0x5b, 0x9c, 0xd9, 0xd4, 0x07,
	                0x15, 0xfe, 0xa4, 0x42, 0x11, 0x48, 0x6d, 0x82,
	                0xce, 0x95, 0xa2, 0x72, 0x96, 0xb5, 0xab, 0x3a,
	                0x90, 0x1f, 0x63, 0xd5, 0x01, 0xf2, 0xb1, 0xf7
	            ]),
	            this.Gq.parsePoint([
	                0xe7, 0xe5, 0xb4, 0x2c, 0x72, 0x2f, 0xb4, 0x7b,
	                0xd9, 0x2c, 0xa5, 0x81, 0xc0, 0x5a, 0xa0, 0x0f,
	                0x1c, 0x18, 0xc0, 0xff, 0x65, 0x49, 0x39, 0xf1,
	                0x9c, 0xcc, 0xb6, 0xed, 0x3c, 0x4d, 0xf9, 0xf7,
	                0xb0, 0xa0, 0x3b, 0xb4, 0x95, 0xc4, 0x4c, 0xbb,
	                0xbc, 0xe9, 0x3f, 0x48, 0x95, 0x88, 0x26, 0x37
	            ], [
	                0x30, 0x92, 0xe3, 0x2a, 0xf3, 0x9c, 0x40, 0xc2,
	                0x4b, 0x5a, 0x11, 0x10, 0x0b, 0xe8, 0x10, 0x32,
	                0x9f, 0x05, 0x01, 0x6f, 0x79, 0x2f, 0xaf, 0x50,
	                0x87, 0x6f, 0x77, 0xf4, 0xf5, 0x61, 0xf1, 0x87,
	                0x66, 0xb0, 0x1d, 0xa4, 0x4f, 0xb2, 0xe5, 0x4e,
	                0x84, 0x94, 0x6f, 0x2a, 0x3c, 0x96, 0x70, 0xb0
	            ]),
	            this.Gq.parsePoint([
	                0xa6, 0x95, 0x9a, 0x68, 0xa6, 0xda, 0x7a, 0x46,
	                0x8d, 0x0e, 0xef, 0x82, 0x74, 0x92, 0xd3, 0x88,
	                0x8a, 0xf2, 0x81, 0x1d, 0x06, 0x27, 0xc1, 0x8a,
	                0xa9, 0x09, 0xdd, 0x0a, 0xe4, 0xb0, 0x20, 0xd1,
	                0x33, 0xe4, 0x8b, 0x91, 0x1b, 0x37, 0x7e, 0x05,
	                0xcc, 0xb7, 0x7f, 0xee, 0xea, 0x32, 0x66, 0x73
	            ], [
	                0x70, 0xed, 0xeb, 0x46, 0x7c, 0x18, 0xd1, 0x59,
	                0x47, 0x48, 0x24, 0xdf, 0xbe, 0x59, 0x42, 0x9b,
	                0x4f, 0xad, 0xc9, 0x7c, 0xfe, 0x3f, 0x84, 0x98,
	                0x63, 0x07, 0xb4, 0xba, 0x50, 0xfa, 0xf2, 0xc4,
	                0xb6, 0x0d, 0x73, 0xf2, 0xb3, 0x95, 0xb5, 0x95,
	                0xbb, 0x6e, 0xcd, 0xd9, 0x6a, 0x4f, 0xe3, 0xe9
	            ]),
	            this.Gq.parsePoint([
	                0x99, 0x38, 0x12, 0x7c, 0x58, 0xef, 0x9e, 0xfe,
	                0x69, 0xcc, 0x43, 0xad, 0x75, 0x8b, 0x3a, 0xf2,
	                0x3b, 0xff, 0xde, 0x84, 0xf7, 0x18, 0x2f, 0x09,
	                0x00, 0x95, 0xe1, 0x18, 0x83, 0x4b, 0x67, 0x08,
	                0x7e, 0xe7, 0x06, 0xb4, 0x64, 0x40, 0x32, 0x38,
	                0x89, 0x25, 0x3a, 0x22, 0x3e, 0xcf, 0xc8, 0x65
	            ], [
	                0x37, 0xf1, 0xc9, 0x42, 0x4f, 0x08, 0x60, 0xe3,
	                0xec, 0xe2, 0xf8, 0x10, 0x78, 0x00, 0xf6, 0xd8,
	                0x6c, 0x90, 0x9a, 0x9f, 0x44, 0x67, 0x9c, 0x35,
	                0x57, 0xec, 0xeb, 0x4b, 0x58, 0x14, 0xb4, 0xb3,
	                0x96, 0xbc, 0x8e, 0x9a, 0x9a, 0x78, 0xbb, 0xea,
	                0xb7, 0xc1, 0x31, 0x3f, 0x0a, 0x4b, 0xe3, 0x18
	            ]),
	            this.Gq.parsePoint([
	                0x60, 0xea, 0xe1, 0x69, 0xe1, 0x38, 0xdf, 0x49,
	                0x79, 0xde, 0xd5, 0x09, 0xba, 0xce, 0xed, 0x03,
	                0xe6, 0x34, 0x49, 0x10, 0xd3, 0x61, 0x35, 0xea,
	                0x66, 0x53, 0xef, 0xf5, 0x5c, 0x07, 0x6c, 0xfb,
	                0x54, 0xc1, 0xee, 0x9b, 0xc0, 0xb5, 0xe8, 0x12,
	                0x9c, 0x92, 0x9f, 0xda, 0x64, 0x3e, 0x82, 0xd9
	            ], [
	                0x65, 0x21, 0x02, 0x12, 0xca, 0x85, 0x21, 0xa0,
	                0xf9, 0x02, 0x20, 0x63, 0xc3, 0xd8, 0x16, 0x34,
	                0xa1, 0xb4, 0x64, 0x9b, 0x02, 0x65, 0x19, 0x87,
	                0xfc, 0xe2, 0xa8, 0x5e, 0x3f, 0xae, 0xa6, 0x03,
	                0x5b, 0xbf, 0xa2, 0x5e, 0x4d, 0xe4, 0x76, 0x95,
	                0xd7, 0xef, 0x0b, 0xe7, 0xc6, 0x55, 0x29, 0xf4
	            ]),
	            this.Gq.parsePoint([
	                0xab, 0x09, 0xb0, 0x48, 0x5b, 0xd7, 0xea, 0xe2,
	                0x4b, 0xf8, 0x2a, 0xca, 0xf4, 0x8c, 0xb3, 0x84,
	                0x8a, 0x84, 0x1f, 0xe3, 0x82, 0x6c, 0xa2, 0xbf,
	                0xd9, 0x1d, 0x2a, 0xfe, 0xdf, 0xbe, 0xef, 0x07,
	                0xa9, 0x1d, 0x1d, 0x35, 0xb7, 0xc4, 0x22, 0x44,
	                0x53, 0x15, 0xd7, 0x46, 0x66, 0xa2, 0xdc, 0x5b
	            ], [
	                0x6b, 0xe9, 0x10, 0x29, 0xfe, 0xd9, 0x01, 0x32,
	                0x98, 0x2e, 0x34, 0xf5, 0x81, 0xb8, 0x5c, 0xba,
	                0x8d, 0x69, 0x90, 0x62, 0xb7, 0x65, 0x78, 0x80,
	                0x86, 0x93, 0xf1, 0x34, 0xf2, 0x03, 0xfa, 0x86,
	                0x6a, 0x1f, 0xb2, 0xfa, 0xfc, 0x87, 0x77, 0x29,
	                0x2b, 0xb5, 0xc6, 0x2c, 0x13, 0x0a, 0x94, 0x10
	            ]),
	            this.Gq.parsePoint([
	                0xeb, 0xca, 0x9a, 0x02, 0x48, 0x2d, 0x74, 0x55,
	                0xd0, 0xe6, 0xaf, 0x49, 0x2e, 0x61, 0x1e, 0xfc,
	                0x90, 0x8c, 0x1f, 0xb8, 0x51, 0xb5, 0x8f, 0x33,
	                0x1b, 0x2a, 0xb0, 0x87, 0xa2, 0xd9, 0xb6, 0x48,
	                0xf3, 0x0f, 0x3f, 0x65, 0x53, 0x3f, 0x4c, 0x55,
	                0x09, 0x75, 0xbe, 0xb9, 0x16, 0x8b, 0x08, 0x49
	            ], [
	                0x68, 0x5d, 0xf7, 0xb2, 0xc2, 0x75, 0x7a, 0x5b,
	                0x5b, 0xa9, 0x3d, 0x91, 0x28, 0x63, 0x88, 0xf6,
	                0x57, 0xb8, 0x9b, 0xd1, 0x2e, 0x36, 0xc8, 0xde,
	                0x9c, 0x95, 0x81, 0x8a, 0xa4, 0xfd, 0x35, 0x7b,
	                0x4c, 0x14, 0xdf, 0x72, 0xa2, 0xbc, 0x41, 0x36,
	                0xfd, 0x94, 0x76, 0x16, 0x0a, 0xaf, 0x65, 0x1c
	            ]),
	            this.Gq.parsePoint([
	                0xda, 0xb7, 0x9f, 0xea, 0x35, 0xa2, 0x88, 0x3a,
	                0x43, 0xc0, 0x28, 0x52, 0xd2, 0x8d, 0xc8, 0xb7,
	                0xa0, 0x2d, 0x5f, 0x33, 0x1c, 0xf1, 0xa5, 0xb9,
	                0x61, 0xaa, 0x2b, 0x39, 0xa0, 0x36, 0x75, 0x6b,
	                0xfc, 0x80, 0xf5, 0x1f, 0x94, 0x57, 0x14, 0x20,
	                0x9b, 0x0b, 0xe8, 0x81, 0xbb, 0x82, 0xc1, 0xb6
	            ], [
	                0x4c, 0x2d, 0x06, 0x3d, 0x40, 0x5b, 0x45, 0x69,
	                0xaa, 0x6d, 0xc9, 0x29, 0x26, 0xe3, 0xfb, 0x36,
	                0x3b, 0x3f, 0xec, 0x76, 0x2d, 0x0c, 0x6f, 0x0d,
	                0xb2, 0x67, 0x07, 0x3c, 0xfe, 0x3f, 0x78, 0xba,
	                0xa2, 0xb8, 0xcb, 0x5d, 0x70, 0x00, 0xbc, 0x8f,
	                0xdb, 0x28, 0x1f, 0xf1, 0x48, 0xe6, 0x26, 0x76
	            ]),
	            this.Gq.parsePoint([
	                0x2e, 0xa5, 0x92, 0x5e, 0xed, 0xe0, 0x69, 0x6e,
	                0x05, 0xb5, 0x75, 0xd1, 0xca, 0x44, 0x66, 0xb1,
	                0xa7, 0x44, 0x90, 0xfc, 0x91, 0xd2, 0x12, 0x61,
	                0x25, 0x7e, 0x06, 0xc6, 0xc5, 0xd8, 0xd9, 0x58,
	                0xdc, 0x1b, 0x34, 0xa3, 0xc2, 0xd1, 0x46, 0x07,
	                0xed, 0xbc, 0x15, 0x19, 0x9e, 0xe3, 0x6e, 0x73
	            ], [
	                0x76, 0x8d, 0xb9, 0xae, 0x8d, 0xe6, 0xa9, 0xd5,
	                0x1b, 0x73, 0x25, 0xf1, 0x74, 0x71, 0xed, 0x64,
	                0x22, 0xb8, 0x97, 0x7f, 0xbd, 0xfe, 0xfe, 0xfd,
	                0xeb, 0x0d, 0x5e, 0xb2, 0x87, 0x9c, 0xf5, 0xb9,
	                0x9d, 0xe7, 0xa0, 0x6b, 0xee, 0xf3, 0x5d, 0x4d,
	                0x4b, 0x47, 0x1e, 0x3d, 0xae, 0x96, 0xae, 0x94
	            ]),
	            this.Gq.parsePoint([
	                0x5f, 0xc2, 0x71, 0x13, 0xe1, 0x0e, 0xb4, 0x15,
	                0x11, 0x88, 0x06, 0x86, 0x94, 0x90, 0x56, 0x9e,
	                0x9a, 0x42, 0xd4, 0xe3, 0xce, 0xb2, 0x27, 0xd8,
	                0x93, 0x6d, 0xce, 0xa2, 0x7c, 0xad, 0xb1, 0x6a,
	                0x86, 0xfe, 0x6c, 0x11, 0x6e, 0x60, 0x75, 0x1a,
	                0xfc, 0x53, 0x54, 0xf2, 0x9f, 0x98, 0x24, 0xdd
	            ], [
	                0x1c, 0x7e, 0x89, 0x0e, 0xa7, 0x6e, 0xca, 0xfe,
	                0x28, 0xb6, 0x54, 0x5a, 0x20, 0x05, 0xb5, 0xdf,
	                0x5f, 0xc2, 0x39, 0x18, 0xaa, 0x6d, 0x4c, 0x81,
	                0xf9, 0x68, 0x10, 0x8f, 0xf5, 0x65, 0xfb, 0xee,
	                0x01, 0x88, 0x2d, 0xee, 0x44, 0xb2, 0x3f, 0xb4,
	                0x24, 0x27, 0xd8, 0x94, 0x5f, 0x49, 0xf6, 0xf4
	            ]),
	            this.Gq.parsePoint([
	                0x19, 0xf7, 0x36, 0x91, 0x50, 0x14, 0xc1, 0x21,
	                0x61, 0x2f, 0xf0, 0xfb, 0xaa, 0x44, 0x79, 0xed,
	                0xba, 0x30, 0x84, 0x07, 0x36, 0xd0, 0x0f, 0x18,
	                0xd9, 0xc0, 0x8c, 0xfe, 0x17, 0x70, 0xae, 0xe9,
	                0x12, 0xb5, 0x16, 0xf8, 0x2a, 0x71, 0xf1, 0x76,
	                0x25, 0xbc, 0x10, 0xd5, 0x6e, 0xa7, 0x55, 0x86
	            ], [
	                0x1a, 0x5a, 0x31, 0x18, 0x94, 0xe9, 0x0d, 0x01,
	                0x9f, 0xa1, 0x54, 0xc6, 0x89, 0x07, 0x06, 0x8d,
	                0x1a, 0x29, 0x07, 0xe3, 0x3f, 0xd6, 0x83, 0x61,
	                0x4f, 0xa0, 0x2c, 0xe9, 0xe2, 0x2d, 0x4c, 0xf4,
	                0x0f, 0x9c, 0xb7, 0x0f, 0xfa, 0x74, 0x38, 0x83,
	                0x41, 0xe9, 0x06, 0x35, 0xa2, 0xe2, 0x60, 0xf4
	            ]),
	            this.Gq.parsePoint([
	                0x29, 0x76, 0x37, 0x35, 0xc7, 0xf5, 0x6b, 0xf6,
	                0xbd, 0x7a, 0x1b, 0x6a, 0x1f, 0x2f, 0x87, 0xbc,
	                0x7c, 0xd4, 0x85, 0x92, 0x27, 0x0a, 0xf4, 0x65,
	                0x97, 0x05, 0x31, 0xd6, 0xd9, 0xfa, 0x9a, 0x29,
	                0x9c, 0x40, 0x73, 0xc2, 0xef, 0x5e, 0xd3, 0xf9,
	                0x60, 0x5c, 0x7d, 0xd4, 0x33, 0xb2, 0x08, 0xbc
	            ], [
	                0x74, 0x84, 0xff, 0x65, 0x32, 0xc7, 0xfb, 0x29,
	                0x4e, 0xd4, 0x77, 0x4a, 0x62, 0x9a, 0xa2, 0xeb,
	                0xaf, 0xd0, 0x2b, 0x91, 0x6e, 0xcd, 0x91, 0x84,
	                0xc1, 0x34, 0xc7, 0x39, 0xcd, 0x2a, 0x59, 0x2a,
	                0x40, 0x98, 0x4c, 0xd2, 0x1a, 0x61, 0xc8, 0x80,
	                0x06, 0x7e, 0xef, 0x2c, 0x96, 0x0b, 0x23, 0xa2
	            ]),
	            this.Gq.parsePoint([
	                0x82, 0xde, 0xd0, 0x39, 0x57, 0x7f, 0x4e, 0x1d,
	                0xb3, 0x87, 0x22, 0x20, 0x0a, 0xdc, 0x9d, 0xee,
	                0xe4, 0x77, 0xc8, 0x92, 0x94, 0x84, 0x32, 0xea,
	                0x03, 0x82, 0xf3, 0xd3, 0x14, 0xdc, 0xcb, 0xb8,
	                0x94, 0x47, 0x18, 0xfb, 0xbf, 0x92, 0xc3, 0x1a,
	                0x89, 0xa8, 0xc1, 0x0d, 0xaa, 0x77, 0x8a, 0xb0
	            ], [
	                0x25, 0x81, 0x02, 0x80, 0xfc, 0xf2, 0x80, 0x9f,
	                0xb8, 0xe4, 0x6e, 0xa5, 0xf7, 0x5f, 0x9c, 0x8c,
	                0xd4, 0xae, 0x3e, 0x56, 0x0a, 0xaf, 0xb5, 0xa0,
	                0xfe, 0x8b, 0xce, 0x7d, 0x8a, 0xc2, 0x81, 0x1e,
	                0x71, 0x3f, 0xdf, 0xca, 0x7c, 0x28, 0x14, 0x84,
	                0x1e, 0x64, 0xad, 0xc3, 0x2b, 0xfb, 0x66, 0x2d
	            ]),
	            this.Gq.parsePoint([
	                0x1b, 0x41, 0x50, 0x2e, 0xcd, 0x20, 0x81, 0x7d,
	                0x3c, 0x85, 0xe7, 0x00, 0x4e, 0x66, 0x96, 0x38,
	                0xc7, 0x25, 0xd1, 0x15, 0x8a, 0xa8, 0x03, 0xd1,
	                0x05, 0xab, 0xbf, 0x85, 0x95, 0x51, 0x85, 0x59,
	                0x8b, 0xd3, 0x16, 0xfb, 0xbc, 0x1e, 0x9d, 0xa4,
	                0xb0, 0xab, 0x46, 0x7e, 0x34, 0x17, 0x2d, 0x41
	            ], [
	                0x0e, 0x37, 0x08, 0xf7, 0x21, 0xdc, 0x69, 0xf9,
	                0x2a, 0xf8, 0x11, 0x77, 0x6f, 0xb1, 0xe2, 0x48,
	                0x02, 0x51, 0xb2, 0x04, 0xf5, 0xb1, 0xcd, 0xf4,
	                0xad, 0xaa, 0xed, 0x66, 0xb0, 0x69, 0x8b, 0xd9,
	                0xfa, 0x66, 0x62, 0x3c, 0x5b, 0xf0, 0x56, 0xbe,
	                0xe3, 0x4f, 0x8c, 0xba, 0x26, 0x94, 0x4a, 0x7c
	            ]),
	            this.Gq.parsePoint([
	                0x4a, 0xe5, 0x76, 0xa4, 0x16, 0x41, 0xac, 0x9c,
	                0xee, 0x68, 0xd7, 0x61, 0x68, 0xca, 0x2d, 0xd3,
	                0xa5, 0xa8, 0xa1, 0xc2, 0xd1, 0xb0, 0x38, 0x2d,
	                0xf8, 0xc4, 0xbf, 0x77, 0x00, 0x8b, 0xe3, 0xb2,
	                0x2d, 0x16, 0xbf, 0xa9, 0xda, 0x4a, 0x5a, 0x1c,
	                0xd2, 0x77, 0xa3, 0x13, 0x69, 0xad, 0x04, 0xfe
	            ], [
	                0x53, 0xc8, 0xce, 0x7a, 0x42, 0xd2, 0xb8, 0xd5,
	                0xb9, 0x40, 0x95, 0x93, 0x1a, 0x00, 0x5b, 0xd3,
	                0x20, 0x59, 0x39, 0x55, 0xe6, 0x41, 0xb9, 0xd4,
	                0x11, 0x02, 0xf8, 0x1f, 0x34, 0x46, 0x5e, 0xd9,
	                0x67, 0xd6, 0x99, 0x92, 0xb7, 0x81, 0x0e, 0x0b,
	                0x53, 0x68, 0xe1, 0x1f, 0xa9, 0xbf, 0x4b, 0xc2
	            ]),
	            this.Gq.parsePoint([
	                0xe2, 0xab, 0x87, 0x53, 0xb1, 0x1e, 0xc3, 0x52,
	                0xfb, 0xdc, 0x31, 0x81, 0x9a, 0xf1, 0x93, 0x7c,
	                0x1d, 0x72, 0x2d, 0x10, 0x0b, 0x6d, 0x8a, 0x0a,
	                0x9d, 0xfe, 0xaf, 0x5b, 0xfe, 0x26, 0x1f, 0x78,
	                0x80, 0x1a, 0x0b, 0x80, 0xa2, 0x02, 0x8c, 0x76,
	                0x7e, 0x57, 0x90, 0xce, 0xa9, 0x4e, 0xca, 0x1d
	            ], [
	                0x04, 0xd7, 0xc7, 0x10, 0x08, 0xa5, 0x0d, 0x8b,
	                0x5f, 0x16, 0x9d, 0x23, 0xd5, 0x82, 0x16, 0x24,
	                0xf6, 0x87, 0x9d, 0x3d, 0x69, 0x24, 0x21, 0x8a,
	                0x94, 0xbb, 0xf8, 0xd6, 0x97, 0x25, 0x77, 0x07,
	                0x73, 0xaa, 0x87, 0xee, 0x4c, 0xef, 0x01, 0xce,
	                0x6e, 0x29, 0x43, 0x52, 0x49, 0x11, 0x7f, 0x6f
	            ]),
	            this.Gq.parsePoint([
	                0x37, 0x58, 0x8b, 0x4a, 0xca, 0x0f, 0xc5, 0xab,
	                0xf5, 0x29, 0x04, 0x60, 0x72, 0xe2, 0x33, 0xf7,
	                0x7c, 0x4b, 0x63, 0xd9, 0x7d, 0x2a, 0x33, 0x80,
	                0x0c, 0x10, 0x62, 0xc1, 0x19, 0x6c, 0x53, 0x09,
	                0x8e, 0x11, 0xf6, 0x43, 0xce, 0xc1, 0xc5, 0x4a,
	                0xba, 0xa6, 0xa9, 0xb2, 0x7d, 0x1d, 0xeb, 0x7b
	            ], [
	                0x0c, 0x19, 0xce, 0xcb, 0x06, 0xa2, 0xdc, 0x7d,
	                0x0a, 0xe7, 0x6c, 0xe2, 0xc4, 0x50, 0x18, 0x05,
	                0x25, 0xe3, 0xdd, 0x02, 0xb7, 0x6d, 0x80, 0x97,
	                0xed, 0x44, 0x0b, 0xc8, 0xd9, 0x41, 0x05, 0xe6,
	                0xb6, 0xae, 0x57, 0xcc, 0xf3, 0x3c, 0x90, 0x2a,
	                0x40, 0xc4, 0x5f, 0xbc, 0xff, 0xd6, 0x06, 0x9f
	            ]),
	            this.Gq.parsePoint([
	                0xff, 0xed, 0xb2, 0xa5, 0x73, 0x5c, 0x6e, 0xab,
	                0x4d, 0x3a, 0x26, 0xab, 0x3f, 0x71, 0x6a, 0xd3,
	                0x65, 0x2f, 0x1f, 0xa7, 0x04, 0xea, 0x4c, 0x5f,
	                0x06, 0x4e, 0x09, 0xdf, 0x59, 0xe0, 0x64, 0xfe,
	                0x9a, 0xab, 0x89, 0xb6, 0x11, 0xd0, 0x52, 0x44,
	                0x24, 0xb2, 0xec, 0x4d, 0x35, 0x41, 0x35, 0x67
	            ], [
	                0x8a, 0xf9, 0x13, 0xbc, 0xe6, 0x0e, 0x84, 0xea,
	                0x81, 0xc3, 0xd7, 0xaa, 0x63, 0x7d, 0x40, 0x77,
	                0xe9, 0xa5, 0xcc, 0x4f, 0xa6, 0xa8, 0x01, 0xda,
	                0xd9, 0xde, 0xa6, 0x9a, 0x56, 0xca, 0xce, 0x6f,
	                0xa3, 0x8b, 0x89, 0x1e, 0x3d, 0xfa, 0x07, 0xf2,
	                0xc6, 0xbf, 0xa4, 0x5c, 0x48, 0x0f, 0x42
	            ]),
	            this.Gq.parsePoint([
	                0xe5, 0x1a, 0x94, 0xf1, 0xbb, 0x05, 0x60, 0x52,
	                0xf4, 0x68, 0xe2, 0xf2, 0x1b, 0xbc, 0x5a, 0xd2,
	                0xf6, 0x72, 0xed, 0x3f, 0x83, 0x7d, 0xe0, 0x89,
	                0xbd, 0x59, 0xa9, 0xc7, 0x5a, 0x7b, 0xfb, 0x97,
	                0xfb, 0x87, 0x10, 0x3f, 0xff, 0x41, 0x5f, 0xb1,
	                0x94, 0xee, 0x8b, 0x57, 0xf2, 0xdc, 0xdb, 0x25
	            ], [
	                0x1b, 0x5f, 0x77, 0x0e, 0xbc, 0x9f, 0x67, 0x41,
	                0xf9, 0x7d, 0x4e, 0x82, 0x7b, 0xfd, 0x6a, 0xcc,
	                0x59, 0x2a, 0xce, 0x08, 0x10, 0x7d, 0xb2, 0x6f,
	                0x3e, 0xb4, 0x28, 0xee, 0x18, 0xcd, 0x19, 0x7e,
	                0x72, 0xb9, 0x49, 0xe6, 0x17, 0x25, 0x45, 0xdf,
	                0xde, 0xe0, 0x46, 0x45, 0x57, 0x1a, 0x3d, 0xc7
	            ])
	        ];
	        this.gt = this.Gq.parsePoint([
	            0xae, 0x14, 0x1e, 0x91, 0x57, 0x8a, 0x26, 0x67,
	            0xf7, 0xb7, 0x90, 0x61, 0xe0, 0xa0, 0xf5, 0xb9,
	            0xe4, 0x59, 0xde, 0x30, 0x38, 0xc6, 0x97, 0x75,
	            0x3d, 0x2f, 0x7e, 0xe1, 0xc0, 0x8a, 0x66, 0x23,
	            0x16, 0xda, 0x0d, 0x04, 0xc5, 0xd2, 0x11, 0x5c,
	            0xfc, 0xbe, 0xd0, 0x03, 0xe5, 0x1b, 0x8e, 0x38
	        ], [
	            0x4d, 0x4d, 0x60, 0xf7, 0x66, 0x51, 0x83, 0x48,
	            0x3c, 0x8b, 0xfb, 0x46, 0x6c, 0x36, 0xbf, 0x1e,
	            0x14, 0x83, 0x7a, 0x77, 0x53, 0xa0, 0xdd, 0x1d,
	            0xcc, 0x03, 0x6d, 0x91, 0xaf, 0x53, 0xc1, 0x0c,
	            0xfe, 0x76, 0x5a, 0xc6, 0x19, 0x08, 0x47, 0xd2,
	            0xf6, 0x68, 0x3b, 0x78, 0xe1, 0xe0, 0x9f, 0x0c
	        ]);
	    }
	}
	class P521ECGroupParams {
	    constructor() {
	        this.descGq = ECGroup.P521;
	        this.Gq = new Group(this.descGq);
	        this.oid = "1.3.6.1.4.1.311.75.1.2.3";
	        this.g = [
	            this.Gq.parsePoint([
	                0x01, 0x67, 0x5b, 0x76, 0xe4, 0xf2, 0x1c, 0xef,
	                0xb1, 0x1f, 0xfe, 0x81, 0xf3, 0x13, 0x7c, 0x19,
	                0xe6, 0x99, 0x92, 0xd1, 0x44, 0x03, 0x3f, 0x23,
	                0xf3, 0x93, 0x0d, 0x1d, 0x5b, 0x01, 0x3c, 0xa8,
	                0x16, 0x98, 0xa1, 0x55, 0xf2, 0x29, 0x85, 0x00,
	                0xca, 0xee, 0xe3, 0x6b, 0x13, 0xce, 0xf5, 0x2c,
	                0xa1, 0xc4, 0x21, 0x28, 0x6a, 0xe5, 0x9f, 0x68,
	                0x68, 0x4c, 0x85, 0x78, 0x62, 0x8b, 0xa1, 0x27,
	                0x3b, 0x65
	            ], [
	                0xc6, 0x31, 0xe6, 0x0a, 0xbc, 0xbd, 0x97, 0x01,
	                0x36, 0x20, 0x1e, 0x5a, 0x8e, 0x43, 0x59, 0xf8,
	                0xcd, 0x31, 0x69, 0xcc, 0x39, 0x64, 0x56, 0xb9,
	                0xa1, 0x2d, 0x04, 0x31, 0x7b, 0x3b, 0xee, 0x9a,
	                0xa2, 0x7a, 0xc8, 0xfd, 0x84, 0xe6, 0x7a, 0x61,
	                0x93, 0x4c, 0x63, 0xd1, 0xd9, 0x5c, 0xd3, 0xf8,
	                0x90, 0x03, 0xfd, 0xb5, 0x7b, 0xfc, 0xbb, 0x71,
	                0xf8, 0x11, 0xfe, 0xb5, 0x96, 0xda, 0xed, 0x7e,
	                0x3a
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xe5, 0x65, 0xee, 0x28, 0x01, 0xf3, 0xd8,
	                0x22, 0x66, 0x47, 0x77, 0xb0, 0x8b, 0x43, 0xf2,
	                0xe5, 0x0b, 0x60, 0xaa, 0x66, 0x9e, 0xaf, 0x98,
	                0x70, 0xb3, 0x7f, 0xe8, 0xf7, 0x37, 0x73, 0xb8,
	                0xf9, 0x2e, 0xbe, 0x0c, 0x05, 0x19, 0xf4, 0x94,
	                0xbf, 0x93, 0x8d, 0x55, 0x07, 0x2d, 0xbe, 0xa5,
	                0x93, 0x95, 0x03, 0x6e, 0x5c, 0x0b, 0xa6, 0x8b,
	                0x88, 0x5a, 0xd2, 0xab, 0xb4, 0x7c, 0x64, 0x02,
	                0xb4, 0x63
	            ], [
	                0x72, 0x33, 0xdb, 0xf7, 0x46, 0xdd, 0x2c, 0x2b,
	                0xf6, 0x2a, 0x86, 0x0f, 0x36, 0x45, 0x0c, 0xaf,
	                0x29, 0x5d, 0x88, 0xd3, 0x95, 0x52, 0x1d, 0x73,
	                0x56, 0xc9, 0x60, 0xf6, 0x55, 0x78, 0xfc, 0xc8,
	                0x2c, 0x29, 0xd6, 0xc0, 0x66, 0xf2, 0xc4, 0xa0,
	                0xf5, 0x48, 0xf8, 0x6c, 0xc1, 0xbc, 0x7e, 0xa1,
	                0x2e, 0xa7, 0xd3, 0x4c, 0xe2, 0x41, 0xd1, 0x98,
	                0xf9, 0x54, 0xd9, 0x8c, 0x4f, 0x66, 0x78, 0x78,
	                0xbd
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x63, 0xe4, 0x1f, 0x82, 0xb9, 0xd7, 0x56,
	                0xc7, 0x74, 0xaa, 0x84, 0xa2, 0x08, 0x9e, 0x7d,
	                0xab, 0x68, 0xa6, 0x44, 0x54, 0x91, 0x2d, 0x90,
	                0xe3, 0xcf, 0x37, 0xf9, 0x62, 0x3f, 0xbd, 0x7c,
	                0x74, 0x02, 0x41, 0x7f, 0x66, 0xae, 0x17, 0x51,
	                0x9d, 0xb4, 0xc6, 0xc6, 0x98, 0xbd, 0x85, 0x3d,
	                0xbf, 0xea, 0x2f, 0xd3, 0xec, 0x78, 0xef, 0xe8,
	                0x87, 0xd1, 0xbd, 0x88, 0x7c, 0xdd, 0xbb, 0xa0,
	                0xbb, 0x06
	            ], [
	                0xb0, 0x81, 0x1b, 0xd8, 0x2a, 0xca, 0x45, 0x9f,
	                0x96, 0x9c, 0xb5, 0xe4, 0x64, 0x2e, 0x5b, 0x67,
	                0xb5, 0x2d, 0xfc, 0x96, 0x74, 0xe2, 0xba, 0x3d,
	                0x24, 0xec, 0xe8, 0x62, 0xfe, 0x79, 0xac, 0x51,
	                0x3e, 0xf6, 0x5e, 0x8c, 0x9d, 0x3f, 0x73, 0xbb,
	                0x28, 0xc8, 0x4f, 0x20, 0xd6, 0xb4, 0x57, 0xc1,
	                0x94, 0x14, 0x36, 0xe0, 0xf2, 0x80, 0xbc, 0xd7,
	                0x61, 0x23, 0xf7, 0x39, 0x7a, 0xf3, 0xa0, 0xfb,
	                0x8c
	            ]),
	            this.Gq.parsePoint([
	                0x1b, 0xc6, 0x8e, 0x0c, 0xcc, 0xd3, 0xe2, 0xf0,
	                0x62, 0x75, 0x89, 0x10, 0x62, 0x46, 0x31, 0x7f,
	                0xb7, 0x33, 0x46, 0xfe, 0xb9, 0x16, 0xe2, 0xca,
	                0x61, 0x3c, 0x38, 0x82, 0x54, 0xdd, 0x6f, 0x0f,
	                0x62, 0x1a, 0x9a, 0x5f, 0x56, 0xca, 0xc2, 0x5c,
	                0x35, 0x34, 0x90, 0xf4, 0x32, 0xe9, 0xdc, 0xa7,
	                0x6e, 0xf5, 0xa2, 0xff, 0xb1, 0x85, 0x1d, 0xf8,
	                0x92, 0x08, 0x2c, 0x6d, 0x58, 0x3f, 0x4e, 0xaa,
	                0x31
	            ], [
	                0x42, 0x5a, 0xbc, 0x21, 0xdb, 0x65, 0x8c, 0xb7,
	                0xd3, 0x32, 0x5d, 0x74, 0x90, 0xd5, 0x37, 0x25,
	                0x58, 0xf7, 0x62, 0x00, 0x13, 0x69, 0x25, 0x0b,
	                0x80, 0x86, 0xe4, 0xd4, 0x97, 0x07, 0x06, 0xeb,
	                0x4b, 0x51, 0xbf, 0x76, 0xc6, 0x43, 0xaa, 0x57,
	                0xbf, 0xa3, 0xce, 0x5f, 0x6b, 0x78, 0x31, 0xe8,
	                0xc1, 0x67, 0xff, 0x29, 0xe2, 0xc6, 0x95, 0x8b,
	                0x52, 0x86, 0xbd, 0xe4, 0xf5, 0xf3, 0x20, 0xeb,
	                0xeb
	            ]),
	            this.Gq.parsePoint([
	                0x65, 0x11, 0x0b, 0x80, 0xb2, 0xf3, 0xba, 0x19,
	                0xab, 0x7f, 0x5a, 0x6f, 0xbf, 0xf5, 0x63, 0x3b,
	                0xb6, 0xb3, 0x14, 0x85, 0x63, 0xbd, 0x1a, 0x29,
	                0xac, 0x1b, 0xb9, 0xd7, 0x48, 0x80, 0x0d, 0x4f,
	                0x28, 0xf0, 0x4d, 0xee, 0x10, 0xe8, 0x8f, 0x86,
	                0xaf, 0xbe, 0xab, 0x7e, 0x10, 0xfc, 0xcf, 0xf6,
	                0x99, 0x03, 0xd3, 0x3f, 0x7c, 0xbe, 0xf6, 0xfd,
	                0xdf, 0x65, 0x15, 0x96, 0x78, 0x2c, 0xd7, 0x6c,
	                0x57
	            ], [
	                0xef, 0xa9, 0xbb, 0x04, 0xc1, 0xda, 0x53, 0xc5,
	                0xd9, 0xa7, 0xe9, 0xa2, 0x6d, 0x33, 0xb6, 0x41,
	                0x61, 0x3c, 0xd3, 0x74, 0x28, 0x47, 0x5f, 0xdc,
	                0xf8, 0x21, 0x94, 0x8c, 0x45, 0x72, 0xdb, 0x44,
	                0x4f, 0x99, 0x7f, 0x90, 0x76, 0x81, 0xf0, 0xc4,
	                0x66, 0x2d, 0x8b, 0x08, 0xb5, 0x2d, 0x04, 0xa1,
	                0x09, 0x21, 0x54, 0x36, 0xb0, 0xa3, 0xe4, 0x8f,
	                0x00, 0x96, 0x3b, 0x99, 0xc4, 0x90, 0xe8, 0xfa,
	                0x39
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xf9, 0xff, 0x75, 0xfe, 0x4c, 0xa3, 0xf2,
	                0xb6, 0x5f, 0x66, 0x85, 0xa2, 0x3f, 0x62, 0x01,
	                0xed, 0x46, 0x0e, 0x59, 0xd5, 0x17, 0x29, 0x04,
	                0x05, 0xaf, 0xc7, 0xf7, 0x97, 0xaf, 0x27, 0x2a,
	                0x06, 0xf4, 0x50, 0x97, 0x17, 0xd1, 0x89, 0x00,
	                0x5c, 0xe9, 0x3b, 0xe3, 0x32, 0x13, 0x21, 0x84,
	                0xed, 0x4f, 0xf6, 0x67, 0x97, 0x66, 0xe6, 0x17,
	                0x26, 0x7e, 0x9d, 0x77, 0x01, 0x74, 0xe9, 0x39,
	                0x8b, 0x02
	            ], [
	                0xe8, 0x7e, 0xbc, 0x53, 0x59, 0x51, 0xba, 0x18,
	                0xb9, 0xde, 0xff, 0xd8, 0x08, 0xe9, 0x7b, 0x33,
	                0x7c, 0xc4, 0xec, 0x0b, 0x29, 0x44, 0xae, 0xaa,
	                0xec, 0xd3, 0x49, 0x34, 0x51, 0x0f, 0xee, 0x96,
	                0x06, 0xec, 0x6f, 0xf2, 0x8b, 0x4c, 0x49, 0xcc,
	                0x0b, 0xb6, 0xe8, 0xc5, 0x0c, 0x2a, 0xbd, 0xc9,
	                0x52, 0xae, 0x95, 0xf6, 0x84, 0x02, 0x7b, 0x15,
	                0xa1, 0x0d, 0x64, 0xe7, 0x6c, 0xc6, 0x14, 0xf5,
	                0xe5
	            ]),
	            this.Gq.parsePoint([
	                0xca, 0x01, 0x2f, 0x9a, 0x52, 0xa6, 0x8e, 0x79,
	                0xad, 0x2e, 0x8e, 0x23, 0x82, 0x89, 0xb5, 0x2f,
	                0x7d, 0xb5, 0xc3, 0x7b, 0x7e, 0x50, 0xf1, 0xff,
	                0x00, 0xd2, 0xe4, 0x12, 0x2f, 0xe4, 0xb9, 0x29,
	                0xd6, 0x17, 0x5a, 0x95, 0xd7, 0xf2, 0x4c, 0x9e,
	                0x22, 0x06, 0x9d, 0x49, 0xeb, 0x9d, 0xe2, 0xa1,
	                0x1b, 0xd3, 0x83, 0x2f, 0xd9, 0xd4, 0x6d, 0xa0,
	                0xed, 0xd0, 0xdb, 0xa0, 0x88, 0x6f, 0xb3, 0x30,
	                0xa5
	            ], [
	                0x25, 0x5a, 0xd2, 0xcf, 0x14, 0x40, 0xe3, 0x12,
	                0x10, 0xf3, 0x8f, 0xa7, 0x0f, 0xfc, 0xdc, 0xf6,
	                0x32, 0xe5, 0x3f, 0xb8, 0x07, 0x2f, 0xb0, 0xea,
	                0x5e, 0xf1, 0x1b, 0x6c, 0x59, 0x0e, 0x0a, 0xa8,
	                0x16, 0x16, 0x3b, 0xa2, 0x88, 0x14, 0x86, 0x54,
	                0xbf, 0xb5, 0x4b, 0x71, 0xa4, 0xe3, 0x87, 0xd3,
	                0xc6, 0x3e, 0x8e, 0x4c, 0x12, 0xf5, 0x47, 0x9d,
	                0x45, 0x29, 0xf9, 0xfc, 0x0b, 0x2c, 0x93, 0x59,
	                0xf6
	            ]),
	            this.Gq.parsePoint([
	                0x1f, 0xfa, 0x43, 0x8f, 0xf0, 0x48, 0xba, 0x53,
	                0x9c, 0xeb, 0x37, 0xe2, 0x33, 0x4e, 0xca, 0x04,
	                0xc8, 0x2a, 0xf7, 0xe9, 0xbe, 0x21, 0x0c, 0xe5,
	                0x15, 0x72, 0xdb, 0x53, 0xcb, 0x41, 0xe9, 0xb3,
	                0x26, 0xb9, 0xa4, 0x14, 0x8a, 0x24, 0x99, 0x1e,
	                0x66, 0x08, 0xfd, 0x75, 0x3b, 0x2f, 0x34, 0xad,
	                0xfe, 0x13, 0xab, 0x87, 0xe6, 0x2d, 0xc8, 0xf0,
	                0x77, 0xe5, 0xba, 0xef, 0x43, 0x7f, 0x58, 0xf6,
	                0x0d
	            ], [
	                0x9f, 0x70, 0xff, 0x23, 0xa4, 0x66, 0x18, 0xa3,
	                0x4b, 0xa0, 0x00, 0xe7, 0x90, 0x54, 0x4b, 0xa1,
	                0xbe, 0xbb, 0x18, 0xf9, 0xf9, 0x97, 0x4f, 0x7e,
	                0x1e, 0x08, 0x44, 0xa5, 0x5b, 0x9a, 0x27, 0x01,
	                0x83, 0xa1, 0xb6, 0xbb, 0x90, 0x5b, 0xa8, 0x76,
	                0x81, 0xf9, 0xaa, 0x63, 0xcb, 0x39, 0xb5, 0x7f,
	                0xaa, 0xc9, 0xbb, 0x93, 0x3e, 0x95, 0x26, 0xb8,
	                0x91, 0xb2, 0x10, 0x99, 0x91, 0xc2, 0x59, 0xfb,
	                0xc2
	            ]),
	            this.Gq.parsePoint([
	                0x30, 0x1c, 0xb6, 0x07, 0x5d, 0x05, 0x6b, 0xc6,
	                0x5e, 0x6a, 0xe3, 0x01, 0xc0, 0x76, 0x75, 0x2e,
	                0x07, 0xef, 0x2d, 0x21, 0xf1, 0x82, 0xce, 0xde,
	                0x42, 0xab, 0x6f, 0x56, 0xf0, 0x89, 0xdb, 0x5d,
	                0x50, 0x66, 0x0f, 0x91, 0x1a, 0x7f, 0x85, 0x79,
	                0x73, 0x37, 0xa1, 0xa9, 0x50, 0x56, 0xd4, 0x61,
	                0x3b, 0xa7, 0x5c, 0x7d, 0x69, 0xa5, 0xbc, 0xba,
	                0xec, 0x23, 0x62, 0xe9, 0x4c, 0x65, 0x96, 0x45,
	                0x65
	            ], [
	                0x2d, 0xee, 0x2d, 0xcd, 0x02, 0xae, 0x5e, 0x3d,
	                0x50, 0x34, 0x0b, 0x38, 0x86, 0xdb, 0x25, 0xc0,
	                0x53, 0x6e, 0xad, 0xeb, 0x28, 0x7d, 0x22, 0xab,
	                0x85, 0x24, 0xfd, 0xf3, 0x2d, 0x40, 0xd2, 0x01,
	                0x9a, 0x92, 0x02, 0xf9, 0xda, 0x8f, 0xa0, 0x79,
	                0x27, 0x52, 0xda, 0xfa, 0x23, 0xa0, 0x42, 0xc0,
	                0x84, 0xf4, 0xd0, 0x8c, 0xe0, 0x79, 0x2f, 0x46,
	                0x00, 0x3b, 0xf4, 0x77, 0xf0, 0xa8, 0x6c, 0xac,
	                0x85
	            ]),
	            this.Gq.parsePoint([
	                0x40, 0x7f, 0xc8, 0xe9, 0x84, 0xc8, 0x46, 0x01,
	                0xf3, 0xe4, 0x19, 0x52, 0xfe, 0xc1, 0x61, 0x42,
	                0x30, 0x17, 0xe0, 0x73, 0xd3, 0x37, 0x83, 0xff,
	                0x05, 0xa5, 0x0e, 0x0a, 0x11, 0xb9, 0x4c, 0x4e,
	                0xbe, 0xd0, 0xc8, 0xd7, 0x67, 0x1e, 0x51, 0x80,
	                0xf9, 0x93, 0xb1, 0xe9, 0xd1, 0xe3, 0x57, 0xd2,
	                0x91, 0x77, 0x27, 0x1e, 0xb2, 0x9e, 0xfb, 0x96,
	                0xcd, 0xef, 0x4e, 0xdf, 0x9d, 0x8c, 0x6b, 0x74,
	                0x40
	            ], [
	                0x43, 0x1d, 0xf6, 0x9b, 0x02, 0x20, 0x04, 0xca,
	                0xf4, 0xc7, 0x1e, 0xce, 0x51, 0x69, 0x32, 0x02,
	                0xb5, 0x10, 0xf4, 0x02, 0x07, 0xe4, 0x85, 0x6e,
	                0x94, 0x09, 0x82, 0x15, 0xc0, 0x1f, 0x55, 0xc1,
	                0x9a, 0x07, 0x28, 0xc7, 0x48, 0x1c, 0xdf, 0xc2,
	                0x4b, 0x2f, 0x80, 0xd1, 0xd2, 0x29, 0xec, 0xda,
	                0xc1, 0xf4, 0xd8, 0x3e, 0x8c, 0x46, 0x6c, 0xd3,
	                0x58, 0x6f, 0x4e, 0x0d, 0x13, 0xff, 0x25, 0xe9,
	                0x88
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xdb, 0xac, 0x6b, 0xe0, 0x86, 0x07, 0x87,
	                0xde, 0xf0, 0x3f, 0xfc, 0x54, 0x72, 0xdc, 0x23,
	                0xfa, 0x06, 0xb1, 0x5a, 0xf0, 0x1c, 0xbf, 0x8b,
	                0xee, 0x8f, 0x5a, 0x0e, 0x71, 0xae, 0x28, 0xb5,
	                0xec, 0xac, 0x96, 0xfd, 0xa8, 0x2e, 0x85, 0x74,
	                0x74, 0x1c, 0x21, 0x9f, 0xa6, 0x2d, 0x31, 0xaf,
	                0xd6, 0x58, 0xbb, 0x95, 0x78, 0xd5, 0x9b, 0x27,
	                0x9d, 0xf0, 0x94, 0x90, 0x63, 0x12, 0x26, 0x65,
	                0xcf, 0xb3
	            ], [
	                0x36, 0xda, 0x1a, 0x1f, 0xbf, 0xa6, 0x5c, 0x4e,
	                0xe9, 0x1d, 0x83, 0x6c, 0x2f, 0x42, 0x4a, 0xb2,
	                0x84, 0x5c, 0xd6, 0xeb, 0x79, 0x62, 0x50, 0x06,
	                0x65, 0xf7, 0x45, 0xc7, 0xa8, 0x3c, 0x4d, 0xa9,
	                0x9e, 0x07, 0xcf, 0x2f, 0x57, 0xd9, 0x9e, 0x57,
	                0x69, 0xbf, 0xa7, 0x0b, 0xdb, 0xde, 0x84, 0xed,
	                0xe5, 0x62, 0x50, 0x4b, 0x8e, 0x84, 0xb2, 0xc1,
	                0xe1, 0x59, 0xf0, 0xdb, 0xb9, 0xeb, 0x58, 0x54,
	                0x9b
	            ]),
	            this.Gq.parsePoint([
	                0xed, 0xa6, 0x25, 0xde, 0x05, 0x83, 0x40, 0x21,
	                0x3a, 0x85, 0x9d, 0xf9, 0x74, 0x81, 0xc0, 0x62,
	                0x23, 0x33, 0x7a, 0xb4, 0x2e, 0x45, 0x59, 0x9b,
	                0xb5, 0x43, 0x19, 0x60, 0xd3, 0xb9, 0xc4, 0x33,
	                0xd8, 0x7e, 0x6d, 0xf0, 0x1b, 0xdc, 0x89, 0x5a,
	                0x3c, 0x10, 0x0c, 0xf5, 0xbd, 0x35, 0x7e, 0x42,
	                0xd4, 0xcd, 0xbb, 0x9e, 0xeb, 0x47, 0xe1, 0x92,
	                0x98, 0x02, 0xc2, 0x0e, 0xfc, 0x65, 0xe9, 0xe0,
	                0x44
	            ], [
	                0xc9, 0x0a, 0x0e, 0xfa, 0x16, 0xc0, 0xbb, 0x69,
	                0x8e, 0x2b, 0x67, 0xb5, 0xbd, 0x49, 0x8a, 0x02,
	                0xd8, 0x69, 0x5c, 0x73, 0xf2, 0x62, 0x6a, 0x96,
	                0xdd, 0x85, 0x37, 0x1d, 0xc8, 0xd2, 0x36, 0xaf,
	                0x6f, 0x23, 0x42, 0x93, 0xd0, 0x96, 0x22, 0xaa,
	                0x10, 0x58, 0x85, 0x9b, 0x36, 0x96, 0x1f, 0xd5,
	                0x9f, 0x5e, 0x28, 0xcb, 0x48, 0x0c, 0x20, 0x26,
	                0x24, 0xbe, 0xf4, 0x31, 0x86, 0xfc, 0xcd, 0x39,
	                0x6e
	            ]),
	            this.Gq.parsePoint([
	                0x05, 0xf8, 0xa4, 0x99, 0xb9, 0x3c, 0x10, 0xc4,
	                0x9e, 0x1e, 0x29, 0xac, 0x7b, 0xa4, 0x26, 0x71,
	                0xfb, 0x46, 0xae, 0x8d, 0x03, 0x20, 0xba, 0xcb,
	                0x5f, 0x01, 0x8f, 0x45, 0x0a, 0x58, 0x77, 0xc0,
	                0xc6, 0x36, 0x56, 0xee, 0xd3, 0xc8, 0x04, 0x3b,
	                0xfe, 0x12, 0xc9, 0x34, 0x6a, 0x6a, 0xe1, 0xf8,
	                0x1d, 0xdb, 0x90, 0xf9, 0x6a, 0x0f, 0xae, 0xf9,
	                0xde, 0xf3, 0xa9, 0x86, 0xbe, 0xcc, 0xa8, 0x56,
	                0xfd
	            ], [
	                0x63, 0x49, 0x5d, 0x5e, 0xca, 0x21, 0xf2, 0x70,
	                0xe3, 0xd5, 0x99, 0xfe, 0xf3, 0x49, 0x22, 0x30,
	                0xec, 0xa6, 0x4c, 0x71, 0x2b, 0xb3, 0x10, 0x0b,
	                0x14, 0xf4, 0xae, 0x2b, 0x62, 0x18, 0xab, 0x68,
	                0x35, 0x55, 0x78, 0xca, 0x73, 0xa2, 0x6a, 0xf4,
	                0xc8, 0x02, 0x02, 0x1f, 0x3a, 0x29, 0x9c, 0x84,
	                0xd3, 0x43, 0xaa, 0xef, 0x23, 0x7c, 0x1a, 0xd2,
	                0x05, 0x03, 0x53, 0x2a, 0x46, 0x8d, 0xbe, 0xf9,
	                0xa5
	            ]),
	            this.Gq.parsePoint([
	                0xaa, 0x86, 0xfc, 0xd1, 0x1c, 0xb4, 0xe5, 0x15,
	                0x60, 0x21, 0xf5, 0x11, 0xc2, 0x14, 0x5d, 0xf1,
	                0x98, 0xd8, 0xfc, 0x07, 0xe4, 0x37, 0xf7, 0x49,
	                0x56, 0x04, 0xef, 0xd3, 0x87, 0x10, 0x0d, 0x6a,
	                0xc3, 0x38, 0x93, 0x4e, 0x43, 0x07, 0x37, 0x6f,
	                0xeb, 0x1b, 0x9c, 0xd2, 0x31, 0xf7, 0xe7, 0x4e,
	                0x1f, 0xf7, 0x68, 0x16, 0x51, 0x89, 0x44, 0x2d,
	                0x6a, 0x85, 0x18, 0x58, 0xdb, 0x44, 0xc3, 0x94,
	                0x2f
	            ], [
	                0x46, 0xe3, 0x45, 0x90, 0x6c, 0x1f, 0xa9, 0x61,
	                0xa7, 0x0c, 0xec, 0x67, 0x1f, 0xe9, 0x84, 0xad,
	                0x62, 0x92, 0x6e, 0x26, 0xaf, 0x0e, 0x49, 0xdb,
	                0xaf, 0x78, 0x08, 0x1b, 0xd4, 0xc8, 0x0a, 0xf1,
	                0x42, 0x6c, 0xb3, 0x97, 0xe9, 0xd4, 0x14, 0xb7,
	                0xc2, 0xe8, 0x30, 0x05, 0xbe, 0x4a, 0xb1, 0x57,
	                0x1f, 0x28, 0x43, 0xac, 0xd4, 0x83, 0x4d, 0x16,
	                0x0b, 0x38, 0xf4, 0x70, 0x4c, 0x1c, 0x2d, 0x1a,
	                0x37
	            ]),
	            this.Gq.parsePoint([
	                0x60, 0xba, 0x95, 0x38, 0x7d, 0x52, 0xd6, 0xf4,
	                0x22, 0x5f, 0xf4, 0xc2, 0x40, 0xc4, 0xeb, 0x06,
	                0x1d, 0x6d, 0xa6, 0x01, 0x94, 0x67, 0xf4, 0xa8,
	                0x45, 0x84, 0xfa, 0xe8, 0xe6, 0x85, 0xea, 0xec,
	                0x07, 0x8f, 0x00, 0x64, 0xc6, 0xfc, 0x0b, 0x5b,
	                0x5e, 0x47, 0x9b, 0xda, 0x8b, 0x19, 0x50, 0x8f,
	                0x64, 0xaa, 0x6f, 0x6b, 0xd3, 0x21, 0xba, 0x3b,
	                0xb5, 0x59, 0x9b, 0x1f, 0xda, 0x0b, 0xcf, 0x0f,
	                0x42
	            ], [
	                0xd0, 0xfa, 0xd9, 0x20, 0x1e, 0x63, 0x4b, 0x41,
	                0xf0, 0xb9, 0xfc, 0x75, 0x97, 0xb7, 0x7b, 0x2f,
	                0xe4, 0x87, 0xe1, 0x2b, 0x83, 0x36, 0x9f, 0xe7,
	                0xff, 0x0b, 0x65, 0xab, 0xdd, 0xac, 0x92, 0xa0,
	                0x2d, 0xeb, 0x1a, 0xc5, 0x4c, 0x8d, 0x6e, 0x0f,
	                0x5e, 0x55, 0x25, 0x84, 0x30, 0xff, 0x61, 0x8f,
	                0xd1, 0xcb, 0xf0, 0x39, 0x49, 0x0a, 0x03, 0xe2,
	                0x6e, 0x61, 0x10, 0x4d, 0x80, 0x9d, 0xe4, 0x1e,
	                0x45
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xec, 0xae, 0x88, 0x27, 0xa7, 0xb0, 0x94,
	                0x7d, 0xaa, 0x18, 0x5e, 0x92, 0x90, 0x0e, 0x5c,
	                0x5e, 0xf2, 0x5d, 0xec, 0x1f, 0x08, 0x21, 0xb8,
	                0xa6, 0x97, 0x4b, 0xda, 0x81, 0x92, 0xc0, 0x7b,
	                0x3a, 0x3c, 0x67, 0x69, 0xad, 0xfd, 0xb8, 0x57,
	                0xc7, 0x3c, 0x96, 0x74, 0xea, 0xd2, 0x6a, 0x3b,
	                0x57, 0xa5, 0x6f, 0xa6, 0xc1, 0x5a, 0x47, 0x32,
	                0xc4, 0xbd, 0x63, 0x06, 0x1e, 0x1c, 0xb8, 0xd7,
	                0x2e, 0xa2
	            ], [
	                0x75, 0xd0, 0x1f, 0x5d, 0x3b, 0x38, 0x8a, 0x16,
	                0x54, 0x6b, 0xc8, 0x3e, 0xfa, 0x7f, 0x97, 0x43,
	                0x2f, 0xd0, 0x07, 0x1e, 0xc7, 0xe5, 0x92, 0x93,
	                0x23, 0x2b, 0xe9, 0xc6, 0xaa, 0x48, 0xd1, 0xae,
	                0x5f, 0xa7, 0x4b, 0xa0, 0xdd, 0x8b, 0x99, 0xeb,
	                0x84, 0x09, 0xb5, 0x4d, 0x6d, 0x81, 0x1d, 0x16,
	                0x4a, 0xf4, 0x30, 0x85, 0xef, 0x86, 0x0a, 0x3a,
	                0x27, 0x77, 0x7c, 0x03, 0x36, 0x24, 0xa8, 0xf6,
	                0x69
	            ]),
	            this.Gq.parsePoint([
	                0xb4, 0x1a, 0x80, 0xd0, 0xcd, 0xae, 0x1d, 0x86,
	                0xbf, 0x03, 0x21, 0xa9, 0xad, 0xe6, 0xbf, 0x3c,
	                0xc1, 0xd6, 0x0b, 0xbc, 0x32, 0xa8, 0xcd, 0x8a,
	                0xd2, 0x32, 0xc8, 0x22, 0x8e, 0x9c, 0x15, 0xe7,
	                0x5c, 0xc3, 0x72, 0xd6, 0xca, 0x6e, 0x5a, 0xe7,
	                0x0d, 0xe5, 0xfe, 0x52, 0x02, 0x88, 0x39, 0x38,
	                0xb4, 0x2d, 0xf2, 0x23, 0x66, 0x43, 0x56, 0x9c,
	                0x0e, 0xe6, 0xa7, 0x3e, 0x09, 0x64, 0x54, 0x8c,
	                0x1d
	            ], [
	                0x44, 0xbb, 0x4e, 0xa0, 0x65, 0x9a, 0x27, 0xe6,
	                0x12, 0xac, 0x00, 0x88, 0x79, 0x49, 0x40, 0x0f,
	                0xb8, 0xf4, 0x1c, 0x9e, 0xb5, 0xda, 0xff, 0x89,
	                0xb5, 0xee, 0x4c, 0xe9, 0x79, 0xfa, 0x1d, 0x73,
	                0xb5, 0xea, 0xda, 0x1f, 0x60, 0x37, 0xc8, 0xe0,
	                0x16, 0xe4, 0x4c, 0x1c, 0x8a, 0x4f, 0x9d, 0xc2,
	                0xaf, 0x48, 0x7c, 0xd9, 0x2a, 0x19, 0xf4, 0x50,
	                0xbd, 0x71, 0xbb, 0x4d, 0x72, 0x3e, 0x9d, 0x04,
	                0xa9
	            ]),
	            this.Gq.parsePoint([
	                0xd7, 0xea, 0x7e, 0x80, 0x45, 0x29, 0xf3, 0xa0,
	                0x88, 0x9f, 0xec, 0xa6, 0x32, 0xcc, 0x69, 0x07,
	                0xa2, 0x43, 0x89, 0xbc, 0x0b, 0xa1, 0xee, 0x0f,
	                0x64, 0x8d, 0x52, 0xe0, 0xc0, 0xd9, 0x17, 0x44,
	                0x35, 0x9c, 0xa9, 0x45, 0xe0, 0x29, 0x42, 0x04,
	                0xa9, 0xd8, 0xa9, 0x05, 0x6c, 0xfc, 0x16, 0xa0,
	                0x13, 0x84, 0xf4, 0x3c, 0x7b, 0x0f, 0xe2, 0x07,
	                0xf3, 0x7a, 0x81, 0xad, 0x15, 0x84, 0x55, 0x83,
	                0x1b
	            ], [
	                0x85, 0xfa, 0x66, 0xee, 0xde, 0x6d, 0x45, 0x2d,
	                0x4c, 0x80, 0xfb, 0x92, 0x43, 0xbb, 0xbc, 0xd5,
	                0x50, 0x0d, 0x7c, 0x37, 0xa8, 0x7a, 0xc6, 0x87,
	                0xa4, 0x9c, 0xa0, 0x20, 0xbb, 0xf0, 0x00, 0x15,
	                0xac, 0xd5, 0xd4, 0x27, 0xb2, 0xe2, 0x0e, 0x73,
	                0x3a, 0x05, 0x84, 0x9c, 0xc1, 0x3d, 0x2c, 0x20,
	                0x45, 0xc5, 0x33, 0x3d, 0x7e, 0xc1, 0x0c, 0xc8,
	                0xf2, 0xa6, 0x3f, 0x63, 0xfe, 0x78, 0x1c, 0xbd,
	                0x42
	            ]),
	            this.Gq.parsePoint([
	                0x6c, 0xe8, 0x7f, 0x9f, 0x5b, 0x5b, 0x6f, 0xa0,
	                0xfb, 0xc5, 0x1c, 0x2e, 0x3a, 0x20, 0x11, 0x53,
	                0x0b, 0xf2, 0x16, 0xcc, 0x03, 0xcd, 0xea, 0x0c,
	                0x35, 0x27, 0x33, 0xa0, 0xda, 0xb6, 0xef, 0xa7,
	                0xff, 0x77, 0xef, 0xb2, 0x16, 0x98, 0xd6, 0xa2,
	                0xa3, 0x06, 0x97, 0xe3, 0x5b, 0x12, 0x8c, 0x6e,
	                0xe2, 0xa0, 0x2e, 0xbc, 0x94, 0x6b, 0x7d, 0x01,
	                0xd6, 0xae, 0xf9, 0xc4, 0x38, 0x1c, 0x12, 0x92,
	                0x5f
	            ], [
	                0xd6, 0x03, 0x10, 0x16, 0x60, 0x32, 0x50, 0x13,
	                0x5e, 0x19, 0xf6, 0xbb, 0x80, 0x86, 0xb7, 0x51,
	                0x9d, 0x22, 0x3b, 0x08, 0x3e, 0xb8, 0x33, 0xf4,
	                0xee, 0xdb, 0x01, 0x8c, 0x5a, 0x82, 0x6c, 0xe2,
	                0x09, 0x29, 0x25, 0xb6, 0x8f, 0x8b, 0x3c, 0x82,
	                0x57, 0x68, 0xb5, 0x87, 0xe7, 0x40, 0x0c, 0x57,
	                0xbe, 0x2c, 0xbd, 0x5a, 0xf2, 0xda, 0x4d, 0x9a,
	                0xdb, 0xfd, 0xae, 0x09, 0x64, 0x1f, 0x3e, 0xb6,
	                0xc2
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x07, 0x4f, 0x17, 0x16, 0xca, 0x1d, 0xf0,
	                0x0f, 0x49, 0x49, 0x0c, 0x85, 0xf9, 0xc4, 0xbe,
	                0x23, 0x8a, 0xe3, 0x52, 0x9e, 0xc6, 0xb2, 0xc4,
	                0x9b, 0xad, 0xcf, 0x70, 0x2f, 0x90, 0xb4, 0xbc,
	                0xcf, 0x91, 0x51, 0x46, 0xfb, 0xcf, 0xa0, 0x7c,
	                0xf2, 0x04, 0x98, 0x67, 0x7e, 0x82, 0xf4, 0x75,
	                0x72, 0xbe, 0xd9, 0xe2, 0xbb, 0x58, 0x54, 0x68,
	                0xa9, 0x64, 0x7d, 0xf1, 0xaa, 0x65, 0xb1, 0x0b,
	                0x4b, 0xee
	            ], [
	                0xe3, 0x73, 0x5d, 0x88, 0x1a, 0x47, 0x13, 0x98,
	                0xc8, 0x55, 0x4e, 0xcf, 0x7d, 0x25, 0xf5, 0xc8,
	                0x71, 0x90, 0xc6, 0xde, 0x1a, 0x04, 0xb5, 0xc1,
	                0x3e, 0xd1, 0x68, 0xe2, 0x37, 0x86, 0x91, 0x26,
	                0x6f, 0xb9, 0x8f, 0x5b, 0xd5, 0xf3, 0x36, 0x0c,
	                0xb6, 0x69, 0xcd, 0x9a, 0x4d, 0xb3, 0x2f, 0x42,
	                0xf6, 0x02, 0x51, 0x5a, 0x74, 0x2d, 0xfe, 0xc7,
	                0xad, 0xa8, 0x42, 0xd5, 0x95, 0xda, 0x6c, 0x6e,
	                0x3d
	            ]),
	            this.Gq.parsePoint([
	                0x4e, 0x0a, 0xa3, 0xb9, 0xc2, 0xe7, 0x14, 0x73,
	                0x86, 0xfa, 0x7b, 0xed, 0x54, 0x3e, 0xbd, 0xd4,
	                0x15, 0xe8, 0xc3, 0x32, 0x13, 0xc1, 0x5e, 0x28,
	                0xaa, 0x8a, 0x00, 0x3e, 0x5d, 0xb3, 0x78, 0xe8,
	                0x0c, 0xb1, 0xda, 0xee, 0x60, 0x02, 0xa5, 0x14,
	                0xa6, 0x73, 0x9c, 0x8f, 0x61, 0x8d, 0x71, 0x10,
	                0x4d, 0xbc, 0xc9, 0xd1, 0x6c, 0x71, 0x91, 0xee,
	                0x65, 0xc9, 0x67, 0xcc, 0x30, 0x68, 0xe7, 0x1f,
	                0x24
	            ], [
	                0x08, 0x43, 0x7e, 0x93, 0xbf, 0x86, 0xdb, 0xd0,
	                0xea, 0xba, 0x38, 0x3e, 0xf3, 0x07, 0xdd, 0xb9,
	                0x8d, 0x27, 0xae, 0x63, 0xe7, 0x90, 0x33, 0x8e,
	                0x85, 0xb2, 0x78, 0x16, 0x80, 0xab, 0x0b, 0xbf,
	                0xe1, 0x71, 0x24, 0x78, 0x56, 0x8e, 0x12, 0xac,
	                0xed, 0xb9, 0x76, 0xa8, 0xf3, 0x8a, 0x25, 0x5c,
	                0x87, 0x0a, 0xc5, 0xf9, 0x7f, 0x45, 0x14, 0x1c,
	                0x09, 0x77, 0x46, 0x37, 0x70, 0x47, 0x92, 0x71,
	                0x65
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x26, 0xb1, 0xe6, 0x05, 0xe3, 0xba, 0xe4,
	                0x56, 0xc9, 0x86, 0xad, 0xdb, 0x6e, 0xba, 0x0f,
	                0x75, 0x02, 0x29, 0xb3, 0xf9, 0x71, 0x23, 0x5e,
	                0xa8, 0x27, 0xa2, 0xe1, 0x6f, 0x45, 0xf3, 0xa9,
	                0x38, 0x76, 0x5a, 0xf0, 0xa0, 0x81, 0x2f, 0xa2,
	                0xaf, 0x01, 0x99, 0xe2, 0xe1, 0x80, 0x16, 0x79,
	                0xe4, 0x3a, 0x1e, 0xf9, 0x42, 0x17, 0x32, 0x59,
	                0x5d, 0xba, 0x7e, 0x71, 0xd9, 0xf6, 0xd6, 0x8c,
	                0x30, 0xcf
	            ], [
	                0xfb, 0x86, 0x40, 0xe4, 0x9a, 0x5f, 0xa0, 0x9c,
	                0x4f, 0xcd, 0xf2, 0xc3, 0x76, 0x11, 0xfc, 0x39,
	                0x7f, 0x5f, 0x7b, 0x59, 0x91, 0x70, 0x9c, 0xc6,
	                0x78, 0x3b, 0x92, 0x88, 0x5e, 0xe9, 0x79, 0x84,
	                0x74, 0x44, 0x51, 0xb5, 0x33, 0xd5, 0x71, 0x0c,
	                0x8b, 0x80, 0x1d, 0x5e, 0x29, 0xce, 0x2e, 0x37,
	                0x3f, 0xc3, 0x25, 0xf3, 0x29, 0xa7, 0x50, 0x2d,
	                0x50, 0x3f, 0x42, 0x3e, 0xb2, 0xa3, 0xa9, 0xd4,
	                0x28
	            ]),
	            this.Gq.parsePoint([
	                0x80, 0x94, 0xe9, 0x4e, 0x19, 0x83, 0xa7, 0x61,
	                0x1a, 0x0c, 0xd6, 0x24, 0xd9, 0x4c, 0xfa, 0x1b,
	                0x3c, 0x1e, 0x18, 0xeb, 0xd2, 0x76, 0x7f, 0x4f,
	                0x41, 0x46, 0xc5, 0x73, 0xdf, 0x36, 0x82, 0x81,
	                0x69, 0x3d, 0xdf, 0xa5, 0x26, 0x21, 0x7a, 0x0d,
	                0x93, 0x5d, 0x22, 0x56, 0xa5, 0x26, 0xc8, 0x0f,
	                0xe5, 0x41, 0x80, 0xd6, 0x3b, 0x44, 0xc5, 0xa3,
	                0xc4, 0x4a, 0x52, 0x8b, 0xb2, 0x11, 0xd0, 0xd4,
	                0x0b
	            ], [
	                0x2c, 0x57, 0xee, 0xff, 0xc5, 0x12, 0xd8, 0x30,
	                0xef, 0xf9, 0x0f, 0x8a, 0xa4, 0x1f, 0x86, 0x71,
	                0x57, 0x92, 0x6a, 0xe5, 0x37, 0x27, 0xb3, 0x65,
	                0x1d, 0x29, 0x6a, 0x67, 0x03, 0x87, 0x8f, 0x96,
	                0x73, 0x8f, 0xb3, 0x08, 0xf8, 0x5c, 0xb1, 0x53,
	                0x0b, 0x39, 0xed, 0x24, 0xcc, 0xb6, 0x0e, 0xaa,
	                0xef, 0x80, 0xaa, 0x22, 0xf1, 0xca, 0x5e, 0x9a,
	                0xc7, 0x94, 0x11, 0x0a, 0xc6, 0xcd, 0x04, 0x8d,
	                0xa9
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xdd, 0xc9, 0xa9, 0x91, 0xf6, 0x18, 0x0a,
	                0xbe, 0xfa, 0xae, 0x93, 0x51, 0xed, 0xce, 0x52,
	                0x4d, 0xb8, 0xb0, 0xd7, 0xe4, 0x27, 0xc3, 0xeb,
	                0xa5, 0x88, 0x17, 0xa5, 0x08, 0x39, 0x6f, 0x2d,
	                0xbf, 0x6e, 0x1a, 0x75, 0x43, 0x62, 0x7e, 0x05,
	                0xc3, 0xbb, 0xe6, 0x5d, 0xfe, 0x40, 0xd0, 0xb3,
	                0x31, 0x89, 0x40, 0x1e, 0xf1, 0x9a, 0xb1, 0xb1,
	                0x6f, 0xf3, 0x3b, 0xbc, 0x44, 0x3a, 0x5f, 0xe5,
	                0x47, 0xf9
	            ], [
	                0xfa, 0x05, 0xcc, 0xbe, 0x21, 0xe0, 0xbb, 0xa1,
	                0x88, 0x81, 0xdc, 0x66, 0x2a, 0xb2, 0x9f, 0x3d,
	                0x9c, 0x96, 0x11, 0x0b, 0x2a, 0xb6, 0x0f, 0xa5,
	                0x50, 0x32, 0x21, 0x37, 0x7a, 0xcf, 0xb0, 0x48,
	                0x51, 0x47, 0x9a, 0x96, 0x12, 0xda, 0xb9, 0x94,
	                0xda, 0x56, 0x72, 0x57, 0x1d, 0xc5, 0xc4, 0x39,
	                0x3f, 0x75, 0xb2, 0xc8, 0x4a, 0xab, 0x3f, 0xa6,
	                0xa0, 0xc4, 0x49, 0x7f, 0x0e, 0x55, 0xb1, 0x2c,
	                0xb2
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xeb, 0x90, 0x35, 0x84, 0x06, 0x30, 0xac,
	                0x6f, 0xd0, 0xa3, 0x01, 0x73, 0xa9, 0x47, 0x93,
	                0xf7, 0xe8, 0x1f, 0x34, 0x45, 0x5e, 0x2e, 0x1a,
	                0x60, 0x0f, 0xde, 0xc0, 0x9b, 0xb6, 0x63, 0x61,
	                0x63, 0xc6, 0xc4, 0xb2, 0x41, 0x75, 0xb5, 0x60,
	                0x53, 0xe6, 0x7c, 0x3e, 0x37, 0x4d, 0x35, 0x73,
	                0x9b, 0xe3, 0x18, 0x19, 0xcd, 0xe7, 0xbe, 0xfc,
	                0x42, 0xeb, 0xc3, 0xae, 0xa0, 0xab, 0xdd, 0x03,
	                0xef, 0xc7
	            ], [
	                0xda, 0x55, 0x65, 0xb4, 0xf6, 0x16, 0xdc, 0xe1,
	                0x8b, 0xe9, 0x65, 0x7f, 0x38, 0x6f, 0x0c, 0x27,
	                0x92, 0xfc, 0xf0, 0xf6, 0x02, 0xc6, 0xac, 0xf8,
	                0x4f, 0xcb, 0xc9, 0x76, 0xbb, 0x27, 0x6d, 0x6d,
	                0x84, 0x97, 0x78, 0x75, 0xdc, 0x12, 0xf8, 0x87,
	                0x65, 0x4a, 0xc7, 0xc2, 0x87, 0x3c, 0x3a, 0xef,
	                0xf1, 0xc0, 0xd4, 0x5c, 0xdd, 0xce, 0x4c, 0xd6,
	                0x33, 0x28, 0x59, 0x8a, 0x67, 0xb0, 0xb2, 0x22,
	                0xbf
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x2a, 0x8c, 0x69, 0x5c, 0x84, 0x96, 0x14,
	                0xe9, 0xa6, 0xa1, 0xd4, 0xb3, 0x98, 0x8b, 0x6a,
	                0x56, 0xbb, 0xce, 0xb7, 0x80, 0xd1, 0xcd, 0x2b,
	                0x2b, 0xe3, 0x37, 0xb1, 0x72, 0x0a, 0x27, 0x93,
	                0x6f, 0xb0, 0x5e, 0xcf, 0xa2, 0x1a, 0xac, 0x9e,
	                0x99, 0xb7, 0x03, 0x1b, 0xda, 0x94, 0x21, 0xb5,
	                0xb3, 0xb9, 0x55, 0x5b, 0xaa, 0xda, 0xc9, 0x6b,
	                0xab, 0xce, 0x8a, 0x7e, 0xe4, 0xe1, 0xe2, 0x65,
	                0x75, 0x27
	            ], [
	                0x0c, 0x2c, 0x28, 0x76, 0x3f, 0xd1, 0xe3, 0x92,
	                0xd0, 0x7a, 0xe2, 0xed, 0x96, 0x99, 0x12, 0xdb,
	                0x6c, 0x78, 0xb8, 0xbb, 0xfa, 0x21, 0x6e, 0x56,
	                0x52, 0xc6, 0xfb, 0x47, 0x73, 0x1e, 0xc4, 0x55,
	                0x93, 0x8d, 0xa2, 0x5c, 0x17, 0xfb, 0x58, 0x2e,
	                0xa5, 0x02, 0x28, 0x10, 0x30, 0x84, 0x97, 0x26,
	                0xf4, 0x78, 0xca, 0xd1, 0xa8, 0xb5, 0x6b, 0xe9,
	                0x21, 0xa9, 0x0b, 0x53, 0x61, 0x0b, 0x62, 0xa0,
	                0x9c
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x30, 0xb2, 0x74, 0x65, 0xad, 0x69, 0xc6,
	                0x73, 0x2c, 0xda, 0x11, 0x80, 0x50, 0xcd, 0xdd,
	                0xa2, 0x88, 0x1a, 0x08, 0x70, 0xf1, 0xee, 0x9c,
	                0xeb, 0xd8, 0x1a, 0x56, 0x56, 0x75, 0x5c, 0xb6,
	                0xb0, 0x80, 0xa4, 0x28, 0x93, 0x8b, 0xae, 0xd1,
	                0xf7, 0xd6, 0x77, 0x2a, 0x8f, 0x55, 0x92, 0x34,
	                0xfb, 0xa2, 0x0f, 0xd3, 0x00, 0xf9, 0x1d, 0x88,
	                0xcf, 0xf9, 0x9b, 0x79, 0x4f, 0x1f, 0xad, 0x64,
	                0x79, 0xd4
	            ], [
	                0x8c, 0x65, 0x73, 0xa8, 0x9d, 0x9b, 0x48, 0xd9,
	                0xee, 0x84, 0x74, 0xd7, 0x47, 0x52, 0x6b, 0xcd,
	                0x74, 0xb2, 0x0d, 0x54, 0x5c, 0x42, 0xab, 0x75,
	                0x50, 0xd6, 0xf4, 0x90, 0x61, 0xfc, 0xcb, 0x09,
	                0x57, 0x9c, 0x39, 0xe6, 0x70, 0xbc, 0x04, 0xbe,
	                0x08, 0x20, 0xbd, 0x2f, 0xc3, 0x9a, 0x54, 0x11,
	                0x48, 0x60, 0x41, 0xba, 0x94, 0xe4, 0xb4, 0x05,
	                0x6a, 0x19, 0x6b, 0x07, 0x6a, 0x22, 0x2b, 0xe0,
	                0x1b
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x2c, 0xae, 0xae, 0x62, 0xf4, 0x2d, 0x13,
	                0x14, 0x1f, 0xc2, 0x8b, 0xf5, 0x23, 0x2f, 0x95,
	                0xdb, 0xe9, 0xdc, 0xd7, 0x21, 0xb2, 0x59, 0x90,
	                0x41, 0x50, 0x7d, 0xa3, 0xa5, 0xc1, 0x46, 0x7a,
	                0x19, 0xfa, 0x46, 0x9b, 0xa0, 0x91, 0x40, 0x10,
	                0x66, 0x22, 0xe6, 0x77, 0x71, 0xf3, 0x32, 0xe1,
	                0x9b, 0x3c, 0x17, 0x3a, 0xfd, 0x1e, 0x23, 0xd8,
	                0x45, 0xdb, 0x96, 0x00, 0xbe, 0x07, 0x55, 0xf8,
	                0x5e, 0xf6
	            ], [
	                0xec, 0x2f, 0x91, 0x95, 0xd2, 0xbf, 0x0f, 0x74,
	                0x9f, 0x1a, 0x73, 0xdc, 0x13, 0xb7, 0x61, 0x89,
	                0x24, 0xb3, 0xd3, 0x79, 0xdb, 0x21, 0x29, 0x13,
	                0x71, 0x88, 0xb9, 0xe8, 0xe5, 0x53, 0x35, 0xc0,
	                0x96, 0xd6, 0x3a, 0x27, 0xf5, 0xbb, 0x02, 0xf5,
	                0xb4, 0xf5, 0xac, 0xd7, 0xc5, 0xc4, 0xba, 0x9a,
	                0x7b, 0xfb, 0xf8, 0xbe, 0xaf, 0x1c, 0x37, 0x47,
	                0xd9, 0x4a, 0xb2, 0xfc, 0x5f, 0x13, 0x10, 0xfe,
	                0xd8
	            ]),
	            this.Gq.parsePoint([
	                0xc2, 0x18, 0x2b, 0xa6, 0xe8, 0x20, 0xe8, 0xad,
	                0x89, 0xac, 0x8f, 0x62, 0x55, 0x21, 0x60, 0xab,
	                0xca, 0xbd, 0xd1, 0x47, 0xe6, 0x3f, 0x76, 0x9a,
	                0xdc, 0x69, 0xa6, 0x23, 0xeb, 0xec, 0x89, 0x10,
	                0x2a, 0xa8, 0x3d, 0xfa, 0x2d, 0x6d, 0x6a, 0xf6,
	                0x26, 0x3b, 0x49, 0x7a, 0x71, 0x50, 0x61, 0x0e,
	                0xba, 0x6a, 0xd9, 0x82, 0x97, 0xa2, 0x78, 0xeb,
	                0x81, 0xd6, 0x62, 0xc2, 0xde, 0xf3, 0x8d, 0xe0,
	                0x40
	            ], [
	                0x9a, 0xe7, 0xe0, 0x67, 0x15, 0x72, 0x61, 0x9b,
	                0x73, 0x0b, 0x33, 0xab, 0xdc, 0x8c, 0x9a, 0x46,
	                0x08, 0xd6, 0x41, 0xe1, 0x63, 0x45, 0x63, 0x10,
	                0xbe, 0x94, 0xcf, 0x55, 0xae, 0x4c, 0x92, 0x5c,
	                0x6f, 0xe6, 0x3a, 0x08, 0x1f, 0xb1, 0x41, 0x9b,
	                0x66, 0xc3, 0xa8, 0xfc, 0x19, 0x9e, 0x7e, 0xcb,
	                0x11, 0x4a, 0x9b, 0xde, 0xb1, 0x3e, 0xe7, 0xac,
	                0xf3, 0xac, 0x7e, 0xdd, 0x43, 0xf7, 0x22, 0x35,
	                0x18
	            ]),
	            this.Gq.parsePoint([
	                0x51, 0x7c, 0x31, 0x26, 0x55, 0x63, 0x5d, 0x41,
	                0xdf, 0x5e, 0xfe, 0x8f, 0x8a, 0xf3, 0x06, 0x77,
	                0xe0, 0xe3, 0xcf, 0x5a, 0xdd, 0x48, 0xaa, 0xb1,
	                0x57, 0xf4, 0x5d, 0xff, 0x62, 0x15, 0xcd, 0xcf,
	                0x5f, 0x5c, 0x1a, 0xd4, 0xdc, 0x34, 0x74, 0xbc,
	                0xdd, 0x40, 0x1b, 0xfa, 0x8b, 0x77, 0x10, 0x3b,
	                0x20, 0xc9, 0xc2, 0x89, 0x25, 0xa1, 0x8e, 0xbf,
	                0xea, 0xcd, 0x8d, 0x2b, 0x0a, 0x1d, 0x52, 0xd4,
	                0x8d
	            ], [
	                0x5d, 0x68, 0x30, 0xd3, 0x3c, 0x7e, 0xdf, 0x55,
	                0x4d, 0x9f, 0x14, 0xc9, 0xe6, 0xee, 0x50, 0x29,
	                0x66, 0xf8, 0x33, 0xa1, 0xc5, 0xef, 0x50, 0x6b,
	                0x6e, 0xf4, 0x4b, 0x91, 0x71, 0x66, 0x4e, 0x99,
	                0xe5, 0xcc, 0x1c, 0x8b, 0x09, 0xd7, 0x04, 0xff,
	                0x9e, 0x72, 0xd0, 0xc6, 0x0e, 0x1f, 0x7c, 0xe6,
	                0xe6, 0xf8, 0x98, 0x9a, 0x88, 0xa0, 0x3b, 0x1c,
	                0x30, 0x07, 0x34, 0xf0, 0x94, 0xc2, 0xc5, 0x62,
	                0x4c
	            ]),
	            this.Gq.parsePoint([
	                0x6f, 0x20, 0x17, 0xda, 0x1d, 0x5c, 0x88, 0x27,
	                0x45, 0x84, 0x75, 0x2c, 0x8a, 0xb8, 0xc7, 0xef,
	                0x8a, 0xe7, 0xf6, 0xa9, 0xec, 0xeb, 0x3a, 0x8b,
	                0x3b, 0x9a, 0xf1, 0x6b, 0x5e, 0x03, 0x47, 0xb0,
	                0x1f, 0xa6, 0x62, 0xb0, 0xdb, 0x27, 0xfb, 0xab,
	                0x75, 0x74, 0x9a, 0xe6, 0x83, 0x57, 0x13, 0x5f,
	                0x3d, 0xd2, 0x54, 0x4d, 0x2e, 0x1a, 0x7d, 0x95,
	                0x94, 0xbf, 0xd7, 0xd7, 0xdd, 0xf9, 0xd6, 0x9c,
	                0x25
	            ], [
	                0xd6, 0x21, 0x95, 0xe1, 0x4e, 0x6b, 0x29, 0x65,
	                0x41, 0x47, 0xdb, 0x19, 0xd0, 0x2c, 0xd7, 0x33,
	                0x81, 0x02, 0x0d, 0x7a, 0x55, 0x59, 0x88, 0x0e,
	                0x3e, 0x2f, 0x41, 0x34, 0x3e, 0xf3, 0x9b, 0xd2,
	                0x9b, 0x61, 0x3d, 0x8b, 0x55, 0xae, 0x33, 0xd5,
	                0x59, 0xdf, 0x36, 0xa1, 0x7d, 0x1f, 0xa4, 0xda,
	                0xe0, 0xb5, 0xa3, 0x52, 0xf4, 0x59, 0x16, 0x8f,
	                0x94, 0xd0, 0xa5, 0xb4, 0x56, 0x14, 0x70, 0x27,
	                0x2c
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xf6, 0x66, 0x42, 0x5f, 0xa8, 0xbd, 0xe9,
	                0x8b, 0xff, 0x13, 0x81, 0x61, 0x79, 0x6c, 0x12,
	                0xe0, 0xe1, 0xe4, 0x85, 0xea, 0xda, 0xcd, 0x0e,
	                0xd5, 0xad, 0xab, 0x17, 0xba, 0x92, 0xb3, 0xa2,
	                0x93, 0x28, 0xfe, 0x05, 0x71, 0x96, 0xd6, 0x7a,
	                0x03, 0x6c, 0x92, 0x2f, 0x08, 0x74, 0x36, 0xe9,
	                0x81, 0x87, 0xa4, 0x25, 0xb9, 0x22, 0x6a, 0xe7,
	                0x5a, 0x0a, 0x91, 0xb8, 0x48, 0xad, 0xa6, 0x7a,
	                0x9b, 0xe0
	            ], [
	                0xb7, 0x8d, 0x81, 0x52, 0xba, 0xae, 0x1f, 0xe2,
	                0x90, 0x18, 0x35, 0x64, 0xec, 0x0c, 0xde, 0xdd,
	                0xef, 0x62, 0x49, 0x22, 0x0b, 0x98, 0x6d, 0xf8,
	                0xbb, 0xf3, 0xcb, 0x9a, 0x04, 0x7f, 0x06, 0x62,
	                0x79, 0xd3, 0xcd, 0x07, 0x3b, 0x5d, 0x8f, 0x18,
	                0x50, 0x8a, 0x17, 0xf7, 0xaf, 0xcc, 0xf4, 0x07,
	                0x58, 0x32, 0x4f, 0xe2, 0x51, 0xc5, 0x4e, 0x2b,
	                0xbf, 0xdd, 0x2b, 0xe1, 0x6d, 0xdc, 0xd3, 0x5a,
	                0xcc
	            ]),
	            this.Gq.parsePoint([
	                0x1c, 0x78, 0xaa, 0x54, 0x76, 0xf6, 0xcc, 0x9b,
	                0x6d, 0x22, 0xc3, 0xa2, 0x58, 0xbe, 0xbc, 0x1d,
	                0xf2, 0xce, 0x2e, 0x39, 0x1d, 0xc7, 0x75, 0xb8,
	                0x14, 0xce, 0xce, 0x94, 0xf6, 0x4f, 0xed, 0x29,
	                0xc0, 0xc9, 0xa4, 0x0a, 0xe7, 0xb7, 0x8f, 0x21,
	                0x81, 0xaf, 0x16, 0x3d, 0xec, 0x83, 0x18, 0x67,
	                0x84, 0x93, 0xd1, 0xb9, 0x85, 0x26, 0x06, 0xe5,
	                0x8f, 0x96, 0x37, 0x54, 0x65, 0x21, 0x41, 0xcd,
	                0x1b
	            ], [
	                0x3e, 0x4c, 0x46, 0x81, 0x42, 0xcc, 0x1b, 0x6f,
	                0xb6, 0x41, 0x17, 0xc6, 0x69, 0x7f, 0x29, 0xc3,
	                0x36, 0xfd, 0xb2, 0x72, 0xa4, 0x83, 0x64, 0x23,
	                0x39, 0xd8, 0x38, 0x22, 0x06, 0x03, 0xe1, 0x1d,
	                0x4c, 0x6d, 0xc8, 0x0b, 0x7b, 0x1e, 0x5d, 0x13,
	                0x21, 0xab, 0x11, 0xa0, 0x2d, 0x7d, 0x81, 0xa2,
	                0x5a, 0x14, 0xee, 0xd5, 0x80, 0x8c, 0x7a, 0x09,
	                0x54, 0x81, 0xc7, 0xb9, 0x21, 0x6d, 0x07, 0x65,
	                0x80
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x4b, 0xe3, 0x06, 0xc2, 0xa3, 0x0c, 0x0b,
	                0x90, 0xa7, 0x41, 0xa3, 0x7d, 0xe3, 0x82, 0xb5,
	                0x65, 0xa0, 0x78, 0x74, 0x71, 0xdb, 0xd3, 0x72,
	                0x6f, 0x3a, 0xde, 0xde, 0x7a, 0xb1, 0xfd, 0xae,
	                0x81, 0xbe, 0x59, 0x5a, 0xd9, 0x5e, 0x66, 0xd7,
	                0xe2, 0xdc, 0xf5, 0x38, 0x75, 0x18, 0xba, 0xdd,
	                0xe3, 0x12, 0x8e, 0x18, 0xf3, 0x2b, 0xc1, 0x98,
	                0xcb, 0x70, 0x0f, 0xa3, 0xb8, 0xb0, 0xfc, 0xf3,
	                0x87, 0x9b
	            ], [
	                0xc8, 0x67, 0xc1, 0x21, 0xcb, 0xb3, 0x42, 0x53,
	                0xc6, 0xd4, 0xed, 0x65, 0xc7, 0x0b, 0xe2, 0x2d,
	                0x16, 0x17, 0xb6, 0x90, 0x0c, 0xab, 0xce, 0xe9,
	                0x28, 0xe7, 0x6b, 0x93, 0xbd, 0x16, 0xba, 0x13,
	                0xd4, 0x93, 0xd1, 0xc7, 0x1e, 0x62, 0x70, 0x94,
	                0xdd, 0x14, 0xd6, 0xa1, 0xb2, 0xcb, 0xae, 0xa6,
	                0x45, 0x05, 0xcc, 0x55, 0x24, 0x9c, 0x97, 0x86,
	                0x97, 0x17, 0x03, 0x50, 0x27, 0x23, 0xdb, 0xeb,
	                0x23
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xf9, 0x73, 0x25, 0xc4, 0x55, 0xdd, 0x3b,
	                0x04, 0xd5, 0x8a, 0x79, 0xc7, 0x6d, 0x80, 0xe4,
	                0x19, 0xd6, 0xe7, 0x58, 0x27, 0x84, 0x7a, 0x4b,
	                0x51, 0x48, 0xcc, 0x32, 0x7c, 0x34, 0x0d, 0xe6,
	                0x67, 0x0a, 0xef, 0xe5, 0x99, 0x88, 0xc1, 0xb6,
	                0x14, 0x9a, 0xd3, 0x9d, 0x59, 0x49, 0x8a, 0xfe,
	                0x43, 0x4f, 0xac, 0x28, 0x6f, 0x51, 0x96, 0x7d,
	                0xe9, 0xe1, 0x26, 0xe5, 0xa2, 0x3a, 0x31, 0x06,
	                0x1c, 0x82
	            ], [
	                0x1a, 0xa4, 0x22, 0xac, 0x52, 0xf5, 0x08, 0x43,
	                0x93, 0xf4, 0x64, 0x07, 0x68, 0xed, 0xf0, 0xc2,
	                0x85, 0x8f, 0x79, 0x08, 0x6f, 0x92, 0x4c, 0xe3,
	                0xc1, 0x80, 0xb7, 0xf1, 0x1d, 0x91, 0xc8, 0xd4,
	                0x23, 0x5f, 0x9f, 0x74, 0x57, 0x59, 0x3e, 0xc8,
	                0x21, 0xdd, 0xa0, 0x6a, 0x10, 0x79, 0x2b, 0xd6,
	                0x9e, 0xc3, 0x41, 0xba, 0x84, 0xb1, 0x26, 0x08,
	                0x34, 0x2c, 0xc7, 0x15, 0xd1, 0xcd, 0x34, 0x2f,
	                0xfc
	            ]),
	            this.Gq.parsePoint([
	                0xaf, 0x4b, 0x0e, 0x42, 0x74, 0x00, 0xa8, 0x64,
	                0xaf, 0x89, 0x9a, 0x2a, 0x56, 0xcf, 0x65, 0x0e,
	                0xf4, 0xd4, 0xa8, 0x66, 0x58, 0x86, 0x02, 0x7b,
	                0xbc, 0xce, 0x7c, 0x10, 0x04, 0xdd, 0x72, 0x5e,
	                0xb4, 0xbb, 0x62, 0xd1, 0xb7, 0x3c, 0x5e, 0x28,
	                0x5c, 0xf2, 0xae, 0xd3, 0xcd, 0x49, 0x0c, 0x06,
	                0xff, 0x2a, 0x16, 0x13, 0xeb, 0x66, 0x1f, 0x8c,
	                0x0a, 0x86, 0x73, 0x8c, 0xae, 0xa2, 0xf5, 0xd4,
	                0xd9
	            ], [
	                0x34, 0x94, 0xaa, 0x6e, 0x02, 0xe8, 0x14, 0x3a,
	                0x85, 0x7a, 0xfc, 0x9a, 0x6c, 0x79, 0xe8, 0x6c,
	                0x31, 0xbb, 0x5d, 0xe7, 0xa0, 0x1b, 0xfc, 0xca,
	                0x4a, 0x57, 0x57, 0x2f, 0xef, 0x37, 0x3a, 0x34,
	                0x36, 0xe3, 0x22, 0x99, 0x44, 0xcc, 0xa1, 0x5e,
	                0x52, 0x65, 0x28, 0xa2, 0x2b, 0x0f, 0xb1, 0xa3,
	                0x51, 0x56, 0x95, 0xa8, 0xe4, 0xdf, 0x14, 0x18,
	                0x8f, 0x81, 0xc5, 0x55, 0xe7, 0x80, 0x7a, 0x3f,
	                0x78
	            ]),
	            this.Gq.parsePoint([
	                0x35, 0x93, 0x98, 0x49, 0x17, 0x82, 0x4d, 0xf5,
	                0xc9, 0x47, 0x02, 0xcf, 0xd7, 0xb0, 0x5b, 0x3e,
	                0xb1, 0xab, 0xf7, 0x3c, 0xba, 0xb6, 0x2a, 0x43,
	                0xdf, 0x96, 0x71, 0xdf, 0x61, 0x26, 0xa1, 0x65,
	                0xa2, 0x72, 0x7d, 0x27, 0x99, 0x7a, 0x2b, 0x91,
	                0x1d, 0xc1, 0x52, 0x8f, 0xe4, 0x22, 0x63, 0x47,
	                0x7c, 0xe2, 0xe8, 0xee, 0x8b, 0xf1, 0xec, 0x22,
	                0xc9, 0x32, 0x45, 0x9a, 0xda, 0xa3, 0x75, 0x8e,
	                0x0d
	            ], [
	                0x3e, 0x00, 0x09, 0x55, 0xd5, 0x68, 0xb3, 0x35,
	                0xff, 0x04, 0xc7, 0xf0, 0x11, 0xf8, 0xb0, 0xae,
	                0xae, 0x2e, 0xbd, 0x06, 0x6f, 0x85, 0xbd, 0xe6,
	                0x88, 0x82, 0xfb, 0x84, 0x0d, 0x05, 0xb2, 0x91,
	                0xc9, 0x4f, 0x26, 0x6e, 0x82, 0x66, 0x4f, 0x23,
	                0x9b, 0x96, 0x8a, 0xcb, 0x22, 0x04, 0x11, 0xb5,
	                0x46, 0xd4, 0x6c, 0xb6, 0xce, 0x72, 0xd9, 0x8c,
	                0xd7, 0xa6, 0xde, 0xc5, 0x4e, 0x24, 0x69, 0xb6,
	                0x32
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x93, 0x20, 0xc9, 0x93, 0x9d, 0xf2, 0x47,
	                0x11, 0xf9, 0x84, 0x4f, 0x03, 0x12, 0xaa, 0xb8,
	                0x0e, 0x44, 0x76, 0x99, 0xe4, 0xd0, 0x72, 0xa2,
	                0xd9, 0xe8, 0x0a, 0x29, 0xda, 0xfe, 0x86, 0xca,
	                0xf0, 0x58, 0xfa, 0xb3, 0xa8, 0xa8, 0xd4, 0x97,
	                0x55, 0x15, 0x86, 0x4c, 0x2b, 0x93, 0x1c, 0x7f,
	                0x7d, 0xb3, 0xb2, 0x5f, 0x2f, 0x5f, 0x9e, 0x5f,
	                0x8b, 0x53, 0x15, 0xa6, 0x81, 0xb3, 0x93, 0xb0,
	                0x8a, 0x7f
	            ], [
	                0xab, 0x49, 0x05, 0x0e, 0xa4, 0x99, 0x25, 0xfc,
	                0x1c, 0xb8, 0x6a, 0xce, 0xdf, 0x42, 0x19, 0x65,
	                0x9b, 0x24, 0x90, 0xe9, 0x1b, 0x09, 0xf4, 0x25,
	                0xbf, 0xf0, 0x51, 0x60, 0x0a, 0x9e, 0x31, 0x46,
	                0x4e, 0x2e, 0xa9, 0x69, 0x74, 0x54, 0x5b, 0x7c,
	                0x74, 0x58, 0x38, 0xa7, 0x5a, 0x49, 0xc8, 0x8b,
	                0xca, 0xcd, 0x83, 0x7a, 0xc8, 0x95, 0x7f, 0xc1,
	                0x4f, 0x71, 0x1d, 0xea, 0x93, 0x07, 0x0f, 0x3d,
	                0x99
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x2b, 0xa5, 0xb5, 0x32, 0xac, 0xb5, 0xce,
	                0xee, 0x9c, 0x91, 0xa3, 0x25, 0x69, 0x57, 0x86,
	                0xbf, 0x7e, 0x18, 0x42, 0xb8, 0x31, 0xf8, 0xda,
	                0x30, 0xd3, 0x60, 0xd4, 0x28, 0xae, 0x53, 0x3e,
	                0xf2, 0xd1, 0x07, 0x1e, 0x81, 0x31, 0xf7, 0xa7,
	                0xa7, 0x29, 0xbc, 0x2e, 0xd1, 0x9a, 0xe0, 0xc1,
	                0x29, 0xb8, 0xab, 0x03, 0x77, 0xfb, 0x55, 0xe0,
	                0x19, 0xe6, 0x49, 0x32, 0xeb, 0x28, 0xf8, 0x0b,
	                0x93, 0x34
	            ], [
	                0x80, 0x3c, 0x8e, 0xbe, 0xaa, 0x49, 0x3d, 0x6f,
	                0xcb, 0x35, 0x6f, 0xb2, 0x56, 0x2b, 0x79, 0xd3,
	                0xa3, 0x76, 0xb5, 0xbc, 0xbf, 0x9b, 0x22, 0xbb,
	                0xee, 0x75, 0x61, 0x10, 0x75, 0xf7, 0xb7, 0xab,
	                0x16, 0x66, 0x6a, 0xbd, 0x97, 0xbe, 0x5b, 0x7e,
	                0xcb, 0x33, 0x88, 0x41, 0xfe, 0x77, 0xec, 0xe1,
	                0x35, 0xf4, 0xe2, 0xe4, 0xb8, 0x3a, 0xca, 0xfd,
	                0x71, 0xe7, 0x04, 0x52, 0x7a, 0x84, 0x78, 0x94,
	                0x68
	            ]),
	            this.Gq.parsePoint([
	                0xa0, 0x92, 0xee, 0xde, 0xd1, 0x85, 0xfa, 0x76,
	                0x82, 0xef, 0x7e, 0x4b, 0x2a, 0x19, 0x8a, 0x4e,
	                0xa0, 0x43, 0xa5, 0xeb, 0xa6, 0x2b, 0x44, 0x79,
	                0xa8, 0x65, 0x7d, 0x66, 0xd9, 0xda, 0xb7, 0xc5,
	                0xde, 0x65, 0xe4, 0x76, 0x42, 0xdc, 0xc6, 0x2e,
	                0x2a, 0x56, 0x1e, 0xb4, 0x94, 0xf1, 0xe2, 0x74,
	                0x8c, 0xdc, 0x79, 0x2f, 0x01, 0x14, 0xc7, 0x7f,
	                0x52, 0xb7, 0xd7, 0xc5, 0xf5, 0xc4, 0xb0, 0x58,
	                0x83
	            ], [
	                0xd7, 0x4a, 0x59, 0x4a, 0x66, 0x1d, 0x40, 0xea,
	                0x62, 0x97, 0x02, 0xdd, 0x12, 0x47, 0x80, 0x8f,
	                0xb2, 0x88, 0xdd, 0x50, 0x40, 0xe5, 0x41, 0x0d,
	                0x7d, 0x6b, 0x04, 0x59, 0x1e, 0x39, 0x69, 0x6b,
	                0xf2, 0x99, 0x95, 0xa3, 0x52, 0x39, 0x28, 0x41,
	                0x3d, 0x74, 0x6a, 0xcf, 0x2c, 0xdb, 0x55, 0xc4,
	                0x0a, 0xa0, 0x84, 0xcb, 0x65, 0xa2, 0x89, 0xbd,
	                0xfc, 0x85, 0x01, 0xfd, 0xcc, 0xb4, 0x02, 0x09,
	                0xf9
	            ]),
	            this.Gq.parsePoint([
	                0xef, 0x45, 0x1e, 0x11, 0x0d, 0xaf, 0x9d, 0x5e,
	                0x39, 0x1a, 0x53, 0x59, 0x93, 0x4a, 0x9f, 0x69,
	                0x69, 0x51, 0x7f, 0x43, 0x8c, 0x7b, 0xea, 0x18,
	                0x3d, 0x5e, 0x96, 0x29, 0x0d, 0xdc, 0xe1, 0x20,
	                0x87, 0x3e, 0x45, 0x48, 0x6d, 0x0c, 0x41, 0xc8,
	                0x87, 0xc4, 0x83, 0xb4, 0x66, 0x1d, 0xfb, 0x48,
	                0xd8, 0xd7, 0x2c, 0x0f, 0xb8, 0x9e, 0x87, 0xe3,
	                0x9c, 0x8a, 0x37, 0x16, 0xe9, 0xcd, 0xc7, 0x6d,
	                0xdd
	            ], [
	                0xef, 0xa5, 0xc6, 0x8d, 0x14, 0xde, 0x0e, 0xff,
	                0x1d, 0x72, 0x90, 0x05, 0xe2, 0x6e, 0x74, 0xf4,
	                0x9f, 0x8b, 0xc0, 0x83, 0x12, 0x4a, 0x43, 0x2a,
	                0xe1, 0x8d, 0xd5, 0x13, 0x1c, 0x04, 0x77, 0x6f,
	                0x59, 0xa3, 0xf9, 0x32, 0x74, 0xc5, 0x17, 0x7f,
	                0x3c, 0x91, 0xa2, 0x01, 0x60, 0x65, 0x7a, 0x11,
	                0x4f, 0x5b, 0xc0, 0xdb, 0xcc, 0x5c, 0x80, 0x69,
	                0x98, 0x4e, 0x34, 0x13, 0x20, 0x41, 0x2a, 0xdf,
	                0x1a
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x18, 0x71, 0x3f, 0xa1, 0x1a, 0x53, 0xa2,
	                0x4b, 0x33, 0xf9, 0xe1, 0x56, 0xce, 0xcf, 0x8b,
	                0x41, 0x58, 0x74, 0x79, 0x45, 0x08, 0xfe, 0x54,
	                0x38, 0xf8, 0xc4, 0xda, 0xe1, 0x38, 0x66, 0x6a,
	                0x5b, 0x88, 0x8e, 0x8e, 0x99, 0x43, 0x8d, 0xab,
	                0xc1, 0x55, 0x56, 0x46, 0x57, 0x47, 0x11, 0x6a,
	                0xc4, 0x72, 0xad, 0x95, 0xd2, 0x92, 0x0f, 0xe9,
	                0xb3, 0x6f, 0x30, 0xbe, 0x09, 0x63, 0xd7, 0xe0,
	                0xdb, 0x12
	            ], [
	                0x95, 0x4b, 0xea, 0x5f, 0x61, 0xe4, 0xa9, 0xd8,
	                0xd0, 0x93, 0xd1, 0xb9, 0xd6, 0xab, 0x52, 0xb2,
	                0xfa, 0xc8, 0xb7, 0x86, 0x55, 0x80, 0x20, 0x10,
	                0xcf, 0x5e, 0xd9, 0x74, 0x59, 0x86, 0x42, 0x71,
	                0xef, 0x4c, 0x34, 0xd8, 0x04, 0x4c, 0x26, 0xc7,
	                0x76, 0x3d, 0xe3, 0x28, 0xe5, 0x09, 0xef, 0x0a,
	                0x68, 0xc1, 0x17, 0x31, 0x30, 0xad, 0x63, 0x01,
	                0xb2, 0x0c, 0x3b, 0xc8, 0xf8, 0xf2, 0x6a, 0xd2,
	                0x96
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x21, 0x0b, 0x8e, 0xfd, 0x90, 0xf3, 0xb9,
	                0xec, 0x0d, 0x8f, 0x3f, 0x82, 0xf6, 0x87, 0x8a,
	                0xbf, 0x54, 0xa8, 0x8f, 0xf0, 0x68, 0x72, 0x06,
	                0x4e, 0xb7, 0xf4, 0xe9, 0x03, 0xb5, 0x30, 0x94,
	                0x5c, 0x5a, 0x7f, 0x0b, 0xe3, 0xb3, 0x0d, 0x00,
	                0x48, 0x01, 0x70, 0x0a, 0xe3, 0xdd, 0x25, 0x32,
	                0x7f, 0x4b, 0xc2, 0x86, 0x08, 0xbe, 0x51, 0x2f,
	                0x80, 0x0a, 0x84, 0x54, 0xdf, 0x8d, 0x15, 0x06,
	                0x9a, 0x18
	            ], [
	                0x8e, 0x6e, 0xfc, 0x12, 0xaa, 0xd5, 0x47, 0xb3,
	                0xe0, 0x8d, 0x39, 0xf7, 0xa7, 0x9e, 0x9b, 0x03,
	                0x46, 0x16, 0xf0, 0x98, 0x17, 0x5f, 0x71, 0x65,
	                0x61, 0xb7, 0x92, 0x7a, 0xb1, 0x15, 0xa5, 0x4b,
	                0xe4, 0xfd, 0xec, 0xd3, 0x84, 0x5f, 0x7f, 0x53,
	                0x58, 0x82, 0x8f, 0x17, 0x5b, 0x83, 0xed, 0x25,
	                0xef, 0x24, 0x92, 0xc8, 0x72, 0x96, 0xd6, 0xd8,
	                0x9e, 0xcb, 0x98, 0x81, 0x10, 0x4b, 0xe9, 0xbe,
	                0x7d
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0xfb, 0xd7, 0x8c, 0x94, 0xec, 0x52, 0xe5,
	                0xd7, 0x69, 0x39, 0x2c, 0xf0, 0x84, 0xc5, 0xe6,
	                0x29, 0xb2, 0x9c, 0xf6, 0xe3, 0xbb, 0xa7, 0xf3,
	                0xcd, 0x0c, 0x61, 0x2c, 0x2f, 0x61, 0x0c, 0xe3,
	                0x88, 0xbb, 0x72, 0xa9, 0xc7, 0xd4, 0xdd, 0xc3,
	                0xf5, 0x61, 0x20, 0x86, 0xcb, 0x42, 0xbf, 0x34,
	                0x0f, 0x1e, 0x4a, 0xc7, 0x32, 0x4c, 0x73, 0x59,
	                0xef, 0x33, 0x51, 0x09, 0x5c, 0xb0, 0x0a, 0x7a,
	                0x30, 0x4e
	            ], [
	                0x99, 0xdd, 0x83, 0xd1, 0xb4, 0xc0, 0xb2, 0x71,
	                0xf5, 0x1c, 0x48, 0x51, 0xb2, 0x36, 0xff, 0x7b,
	                0x7e, 0x86, 0x62, 0x66, 0x80, 0x68, 0x47, 0x96,
	                0x19, 0x37, 0xef, 0x20, 0xae, 0xcc, 0x98, 0x81,
	                0x22, 0xc0, 0x76, 0x03, 0x26, 0x74, 0xbe, 0x51,
	                0x3a, 0xa0, 0x39, 0x46, 0x16, 0x34, 0x77, 0xdd,
	                0xd2, 0x05, 0x94, 0x5b, 0x39, 0x17, 0xd1, 0xa3,
	                0xfc, 0xcc, 0xa2, 0xba, 0x9d, 0x42, 0x05, 0xaf,
	                0xf7
	            ]),
	            this.Gq.parsePoint([
	                0xec, 0xea, 0xda, 0xe3, 0x60, 0x7e, 0xa6, 0xaa,
	                0x2b, 0x65, 0x4f, 0xf6, 0x7f, 0x0c, 0x15, 0x69,
	                0xac, 0xc3, 0x23, 0xba, 0x3e, 0x6d, 0xcc, 0x5a,
	                0xf8, 0xec, 0xea, 0x30, 0xbb, 0xa4, 0x35, 0xbe,
	                0x1a, 0x62, 0x9a, 0x74, 0xd9, 0xe2, 0x37, 0x36,
	                0xfb, 0x93, 0xf3, 0xbe, 0xaf, 0xcf, 0xed, 0x2d,
	                0x36, 0xd5, 0x9e, 0x23, 0x31, 0x7b, 0xd0, 0xfd,
	                0x1f, 0x95, 0x9b, 0xd4, 0x58, 0x6e, 0x79, 0xf8,
	                0x9e
	            ], [
	                0xf9, 0x73, 0x56, 0x28, 0xa3, 0x82, 0xe2, 0xad,
	                0x84, 0xfd, 0x1b, 0xad, 0xeb, 0xcf, 0x6c, 0x9e,
	                0xe5, 0xe3, 0x97, 0x89, 0x39, 0x1d, 0xe6, 0xbf,
	                0xb4, 0x09, 0xb0, 0xad, 0xac, 0xc1, 0x73, 0x10,
	                0x50, 0x54, 0x11, 0x8b, 0x44, 0x3c, 0xb4, 0xed,
	                0xa2, 0x32, 0x42, 0x8f, 0x44, 0x13, 0x18, 0x3a,
	                0x56, 0x48, 0x6d, 0x07, 0x3b, 0x84, 0xa5, 0x6d,
	                0x89, 0xcb, 0x72, 0x1e, 0xc9, 0x85, 0xeb, 0xc7,
	                0x51
	            ]),
	            this.Gq.parsePoint([
	                0xd2, 0x25, 0xf3, 0x9d, 0x10, 0x60, 0x0c, 0xc7,
	                0x61, 0xc1, 0x7f, 0xe1, 0x5a, 0xce, 0x8b, 0xba,
	                0xdc, 0x77, 0x6a, 0xba, 0x28, 0xbc, 0xba, 0xe4,
	                0x82, 0xd1, 0x5f, 0x79, 0xfe, 0x38, 0xdd, 0x0b,
	                0xc2, 0xc9, 0xbd, 0xe1, 0x2d, 0x6e, 0xe2, 0x50,
	                0x48, 0x9d, 0x0e, 0x7a, 0x23, 0x48, 0x87, 0x11,
	                0x85, 0x7f, 0xb9, 0x13, 0xde, 0x74, 0x44, 0x16,
	                0x76, 0xfd, 0x3c, 0x98, 0xda, 0x4e, 0x8f, 0xd8,
	                0xf6
	            ], [
	                0x97, 0xb3, 0xf4, 0x35, 0xc0, 0x04, 0x16, 0xa5,
	                0x95, 0x86, 0xe7, 0x59, 0x31, 0x28, 0xc1, 0x2b,
	                0x73, 0x47, 0x23, 0xaa, 0x88, 0x7f, 0x98, 0xa0,
	                0xb4, 0x82, 0xd1, 0x8d, 0x38, 0x70, 0x7b, 0xb9,
	                0x33, 0xe4, 0xb4, 0xbc, 0xcc, 0xdc, 0x71, 0x07,
	                0x5f, 0x51, 0x74, 0xe8, 0xf2, 0x13, 0x3b, 0x74,
	                0xb5, 0x44, 0xb2, 0x9a, 0x79, 0x6b, 0x4f, 0xd8,
	                0xb7, 0x83, 0x66, 0x4a, 0xf1, 0xd3, 0x65, 0x9e,
	                0x99
	            ]),
	            this.Gq.parsePoint([
	                0xdb, 0xcc, 0x8b, 0xb8, 0x8c, 0x00, 0xc5, 0x31,
	                0x89, 0x0b, 0xcc, 0x22, 0xa2, 0xf2, 0x21, 0xb8,
	                0xca, 0x91, 0x6b, 0x9c, 0x32, 0x4c, 0x08, 0x1c,
	                0x71, 0x23, 0xe5, 0xca, 0x66, 0x06, 0x9e, 0x0b,
	                0xca, 0xc9, 0x1e, 0x09, 0xbf, 0x95, 0xfa, 0xe7,
	                0xd1, 0x5f, 0x8a, 0xac, 0xaa, 0x17, 0x26, 0xd7,
	                0x0a, 0xc0, 0x30, 0x57, 0xf7, 0xd8, 0x6f, 0x0e,
	                0x27, 0x37, 0x6c, 0xcc, 0x1f, 0xcd, 0x7b, 0x8c,
	                0x7e
	            ], [
	                0x2d, 0x40, 0x01, 0x61, 0x5d, 0x62, 0x5d, 0x51,
	                0x26, 0x3a, 0x6f, 0x7b, 0xf2, 0x63, 0xc0, 0xe2,
	                0x1c, 0x65, 0x68, 0x64, 0xbd, 0x9b, 0x39, 0x5c,
	                0x17, 0x34, 0x36, 0x6c, 0xe3, 0x75, 0x51, 0x8c,
	                0x05, 0x8a, 0x34, 0xe7, 0x48, 0x11, 0xc1, 0x4c,
	                0xa0, 0x72, 0x27, 0xba, 0xa0, 0xbd, 0x0b, 0x59,
	                0xc9, 0x53, 0x56, 0xf4, 0x7f, 0x44, 0xf3, 0x90,
	                0xc6, 0xa4, 0xd1, 0x6c, 0x4a, 0x6e, 0x0c, 0x6f,
	                0xec
	            ]),
	            this.Gq.parsePoint([
	                0x01, 0x04, 0x5c, 0xad, 0x53, 0x5d, 0x92, 0x36,
	                0xd5, 0x46, 0xd0, 0xa1, 0x38, 0x5a, 0x3e, 0xa4,
	                0x1e, 0x65, 0x86, 0xee, 0x0a, 0x76, 0xc6, 0xff,
	                0x5b, 0x81, 0xcc, 0x88, 0x7c, 0xb5, 0x8e, 0xa2,
	                0x59, 0xe5, 0x52, 0x14, 0xc8, 0x28, 0x91, 0x60,
	                0xdc, 0x19, 0x21, 0xc4, 0x12, 0xe4, 0x15, 0x8b,
	                0xe0, 0xcb, 0x54, 0xb8, 0x06, 0x41, 0xcb, 0x65,
	                0x7c, 0x87, 0x3a, 0x5c, 0xa8, 0x4e, 0xf0, 0xe5,
	                0xbc, 0x5a
	            ], [
	                0x56, 0xec, 0x9f, 0x00, 0xa5, 0xbd, 0x39, 0xa7,
	                0x85, 0x78, 0x36, 0x23, 0x5a, 0x83, 0xf2, 0x4b,
	                0x21, 0xff, 0x89, 0xb8, 0x54, 0x84, 0xc8, 0xa7,
	                0x95, 0xfe, 0x3e, 0x3b, 0xae, 0xed, 0x85, 0x32,
	                0xee, 0x2b, 0x94, 0x19, 0x8c, 0x98, 0x82, 0x03,
	                0x5c, 0x77, 0xb1, 0xe7, 0x50, 0x85, 0xc5, 0xcb,
	                0x93, 0x6d, 0xf3, 0x06, 0x3e, 0x71, 0x73, 0x59,
	                0x2e, 0x27, 0x49, 0x09, 0x9a, 0x62, 0x24, 0x7d,
	                0x6d
	            ]),
	            this.Gq.parsePoint([
	                0x8b, 0x7a, 0xf7, 0x37, 0x8c, 0xea, 0xe8, 0x5d,
	                0x55, 0x0b, 0xda, 0x52, 0xec, 0x67, 0x44, 0x13,
	                0x3b, 0xc0, 0xed, 0x59, 0x3d, 0x61, 0x2a, 0x47,
	                0x18, 0xa4, 0x3b, 0x0f, 0x85, 0xb0, 0x57, 0xf7,
	                0x9f, 0x43, 0x46, 0x29, 0xb1, 0x70, 0xd2, 0x03,
	                0xa5, 0x7a, 0xc4, 0xc0, 0x06, 0xdc, 0x4c, 0x87,
	                0xb5, 0xc9, 0x2f, 0xa7, 0xd4, 0xaf, 0x37, 0xd5,
	                0xe3, 0x65, 0x1a, 0x14, 0x15, 0x31, 0xfc, 0x15,
	                0x1a
	            ], [
	                0x09, 0x44, 0x0c, 0x62, 0x16, 0xb4, 0x61, 0x07,
	                0xb2, 0x53, 0xc4, 0x0b, 0xd7, 0x0f, 0xc5, 0xfc,
	                0x96, 0xfe, 0x9b, 0x88, 0x6c, 0xf3, 0x29, 0x40,
	                0x95, 0x8a, 0x80, 0x24, 0xc0, 0x85, 0x95, 0xf9,
	                0x0a, 0x6d, 0x78, 0x3f, 0x40, 0xa4, 0x8b, 0x1e,
	                0xa9, 0xbb, 0xc8, 0xe0, 0xad, 0xbb, 0x8e, 0x4d,
	                0x87, 0x30, 0x0a, 0xca, 0x7f, 0x71, 0x2a, 0x80,
	                0x20, 0xb0, 0xc4, 0x3d, 0x3b, 0x1f, 0xd7, 0x94,
	                0xb1
	            ]),
	            this.Gq.parsePoint([
	                0x63, 0x10, 0x5a, 0x1f, 0xf0, 0x44, 0x9d, 0x4d,
	                0x5d, 0x78, 0x83, 0x95, 0xee, 0x71, 0x41, 0xfd,
	                0x5c, 0x44, 0xfd, 0x02, 0x27, 0xb3, 0xbd, 0xc3,
	                0x2b, 0x9e, 0x9d, 0x26, 0xbe, 0x5c, 0x7b, 0x79,
	                0x45, 0xfa, 0xf8, 0xab, 0x24, 0x7e, 0xed, 0x6e,
	                0x50, 0xcb, 0x82, 0x4a, 0xbe, 0x7f, 0x5c, 0x4b,
	                0x7e, 0xd9, 0xed, 0x72, 0x58, 0x92, 0xd2, 0x77,
	                0xad, 0xa4, 0x62, 0xbb, 0x4e, 0x72, 0xdd, 0x5e,
	                0x6d
	            ], [
	                0xcb, 0x02, 0x80, 0xe5, 0xe9, 0x29, 0x3d, 0x2d,
	                0xb0, 0x8d, 0x25, 0xca, 0xad, 0x1e, 0x7b, 0x49,
	                0xaa, 0x52, 0xfc, 0x85, 0x4f, 0xa4, 0x94, 0x02,
	                0xe0, 0x5e, 0x4b, 0x6f, 0xbc, 0xf0, 0xef, 0xc1,
	                0x76, 0x48, 0x34, 0xc1, 0xc4, 0xca, 0x13, 0xa3,
	                0x6c, 0xa2, 0x0e, 0x8b, 0x8f, 0x57, 0xbd, 0x77,
	                0xac, 0xa8, 0xf5, 0x2b, 0xe0, 0x6b, 0xd9, 0xa6,
	                0x92, 0x9f, 0x93, 0xca, 0x17, 0x2d, 0x3d, 0x86,
	                0xd0
	            ]),
	            this.Gq.parsePoint([
	                0xd0, 0xbf, 0xc6, 0x9d, 0x95, 0x7f, 0x2f, 0xc3,
	                0x8e, 0x51, 0x70, 0xac, 0x3a, 0xae, 0x81, 0x11,
	                0x0d, 0xcc, 0x7a, 0x07, 0x7c, 0x00, 0x94, 0xdd,
	                0xd2, 0x9f, 0xf1, 0x20, 0x57, 0xfc, 0xaf, 0x56,
	                0xe8, 0xd0, 0x14, 0xd0, 0x16, 0x99, 0x8e, 0x44,
	                0x71, 0x0d, 0xb3, 0xfd, 0xf7, 0x2d, 0xa6, 0x5e,
	                0x31, 0xcd, 0x66, 0x5a, 0xbc, 0xb3, 0x53, 0x08,
	                0xa6, 0xb0, 0xac, 0x5f, 0x18, 0xb3, 0xff, 0xb6,
	                0xf7
	            ], [
	                0xbf, 0xab, 0xa1, 0xb7, 0xea, 0x54, 0x55, 0x2b,
	                0x93, 0x8c, 0xe8, 0x9d, 0x09, 0x07, 0x79, 0x7f,
	                0x5f, 0x55, 0xdd, 0x08, 0x1c, 0xa3, 0xfb, 0x5c,
	                0xf0, 0x1f, 0x26, 0x06, 0xd4, 0x64, 0xe3, 0x6e,
	                0x3a, 0x37, 0xe0, 0x50, 0xcf, 0xa0, 0xfb, 0x9c,
	                0xee, 0xe0, 0x35, 0x36, 0x70, 0x7c, 0x6d, 0x11,
	                0x76, 0x65, 0xb3, 0xb1, 0xe8, 0x34, 0x4d, 0x66,
	                0x93, 0x9b, 0x29, 0x79, 0x20, 0x04, 0x47, 0x50,
	                0x53
	            ])
	        ];
	        this.gt = this.Gq.parsePoint([
	            0xd0, 0xbf, 0xc6, 0x9d, 0x95, 0x7f, 0x2f, 0xc3,
	            0x8e, 0x51, 0x70, 0xac, 0x3a, 0xae, 0x81, 0x11,
	            0x0d, 0xcc, 0x7a, 0x07, 0x7c, 0x00, 0x94, 0xdd,
	            0xd2, 0x9f, 0xf1, 0x20, 0x57, 0xfc, 0xaf, 0x56,
	            0xe8, 0xd0, 0x14, 0xd0, 0x16, 0x99, 0x8e, 0x44,
	            0x71, 0x0d, 0xb3, 0xfd, 0xf7, 0x2d, 0xa6, 0x5e,
	            0x31, 0xcd, 0x66, 0x5a, 0xbc, 0xb3, 0x53, 0x08,
	            0xa6, 0xb0, 0xac, 0x5f, 0x18, 0xb3, 0xff, 0xb6,
	            0xf7
	        ], [
	            0xbf, 0xab, 0xa1, 0xb7, 0xea, 0x54, 0x55, 0x2b,
	            0x93, 0x8c, 0xe8, 0x9d, 0x09, 0x07, 0x79, 0x7f,
	            0x5f, 0x55, 0xdd, 0x08, 0x1c, 0xa3, 0xfb, 0x5c,
	            0xf0, 0x1f, 0x26, 0x06, 0xd4, 0x64, 0xe3, 0x6e,
	            0x3a, 0x37, 0xe0, 0x50, 0xcf, 0xa0, 0xfb, 0x9c,
	            0xee, 0xe0, 0x35, 0x36, 0x70, 0x7c, 0x6d, 0x11,
	            0x76, 0x65, 0xb3, 0xb1, 0xe8, 0x34, 0x4d, 0x66,
	            0x93, 0x9b, 0x29, 0x79, 0x20, 0x04, 0x47, 0x50,
	            0x53
	        ]);
	    }
	}
	function getEcGroup(descGq) {
	    if (descGq == ECGroup.P256) {
	        return new P256ECGroupParams();
	    }
	    else if (descGq == ECGroup.P384) {
	        return new P384ECGroupParams();
	    }
	    else if (descGq == ECGroup.P521) {
	        return new P521ECGroupParams();
	    }
	    else {
	        throw "invalid group:" + descGq;
	    }
	}

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	function hexToBytes(hex) {
	    if (hex.startsWith('0x')) {
	        hex = hex.substring(2, hex.length);
	    }
	    if (hex.length % 2 == 1) {
	        // odd-length string, prepend 0
	        hex = '0' + hex;
	    }
	    const bytes = new Uint8Array(hex.length / 2);
	    for (let i = 0; i < hex.length; i += 2) {
	        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
	    }
	    return bytes;
	}
	function bytesToHex(bytes) {
	    let hex = '';
	    for (let i = 0; i < bytes.length; i++) {
	        hex += bytes[i].toString(16).padStart(2, '0');
	    }
	    return hex;
	}
	function checkUnsignedInt(n) {
	    if (!Array.isArray(n)) {
	        n = [n];
	    }
	    n.forEach(n => {
	        if (!Number.isInteger(n) || n < 0) {
	            throw `invalid integer ${n}`;
	        }
	    });
	}
	function arrayEqual(a, b) {
	    if (a === b)
	        return true;
	    if (a == null || b == null)
	        return false;
	    if (a.length !== b.length)
	        return false;
	    for (let i = 0; i < a.length; ++i) {
	        if (a[i] !== b[i])
	            return false;
	    }
	    return true;
	}
	function base64urlToBytes(b64) {
	    return Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
	}
	function bytesToBase64url(a) {
	    return btoa(String.fromCharCode(...a)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
	}
	function stringToBytes(s) {
	    return new TextEncoder().encode(s);
	}
	function bytesToString(a) {
	    return new TextDecoder().decode(a);
	}

	var utils = /*#__PURE__*/Object.freeze({
		__proto__: null,
		arrayEqual: arrayEqual,
		base64urlToBytes: base64urlToBytes,
		bytesToBase64url: bytesToBase64url,
		bytesToHex: bytesToHex,
		bytesToString: bytesToString,
		checkUnsignedInt: checkUnsignedInt,
		hexToBytes: hexToBytes,
		stringToBytes: stringToBytes
	});

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	var ECGroup;
	(function (ECGroup) {
	    ECGroup["P256"] = "P-256";
	    ECGroup["P384"] = "P-384";
	    ECGroup["P521"] = "P-521"; //"1.3.6.1.4.1.311.75.1.2.3"
	})(ECGroup || (ECGroup = {}));
	/**
	 * IssuerParams
	 *
	 * @export
	 * @class IssuerParams
	 */
	class IssuerParams {
	    /**
	     * Private constructor that Creates an instance of IssuerParams.
	     * Use IssuerParams.create() factory to create a new IssuerParams instance.
	     * @param {Uint8Array} UIDP
	     * @param {ECGroup} descGq
	     * @param {string} UIDH
	     * @param {GroupElement[]} g
	     * @param {Byte[]} e
	     * @param {Uint8Array} S
	     * @param {Group} Gq
	     * @param {Uint8Array} P
	     * @memberof IssuerParams
	     * @private
	     * @constructor
	     */
	    constructor(UIDP, descGq, UIDH, g, e, S, Gq, P) {
	        this.UIDP = UIDP;
	        this.descGq = descGq;
	        this.UIDH = UIDH;
	        this.g = g;
	        this.e = e;
	        this.S = S;
	        this.Gq = Gq;
	        this.P = P;
	    }
	    /**
	     * Static factory method to create a new instance of IssuerParams
	     *
	     * @example ```
	     * const params = await IssuerParams(...)
	     * ```
	     * @param {Uint8Array} UIDP
	     * @param {ECGroup} descGq
	     * @param {string} UIDH
	     * @param {GroupElement[]} g
	     * @param {Byte[]} e
	     * @param {Uint8Array} S
	     * @return {*}  {Promise<IssuerParams>}
	     * @memberof IssuerParams
	     * @public
	     * @static
	     * @async
	    */
	    static async create(UIDP, descGq, UIDH, g, e, S) {
	        const Gq = new Group(descGq);
	        const hash = Gq.getHash();
	        hash.update(UIDP);
	        Gq.updateHash(hash);
	        hash.update(g);
	        hash.update(e);
	        hash.update(S);
	        const P = await hash.digest();
	        return new IssuerParams(UIDP, descGq, UIDH, g, e, S, Gq, P);
	    }
	    // c.f. spec section 2.3.1
	    verify() {
	        // no need to verify Gq and the generators, since only the recommended ones are supported
	        // verify g0
	        if (this.g[0].equals(this.Gq.getIdentity()) ||
	            !this.Gq.isValid(this.g[0])) {
	            throw 'invalid g0';
	        }
	    }
	}
	// Create Issuer parameters. If UIDP is empty, it will be set to the hash of the other variables
	// c.f. spec section 2.3.1
	async function createIssuerKeyAndParams(descGq, n, e = undefined, S = new Uint8Array(), issKeyPair, UIDP) {
	    if (n < 0 || n > 50) {
	        throw "n must be between 0 and 50";
	    }
	    if (!e) {
	        e = new Array(n).fill(new Byte(1));
	    }
	    if (e.length != n) {
	        throw "wrong length for e: " + e.length;
	    }
	    const groupParams = getEcGroup(descGq);
	    const Gq = groupParams.Gq;
	    const Zq = Gq.Zq;
	    // generate the Issuer key pair
	    let y0;
	    let g0;
	    if (issKeyPair == undefined) {
	        y0 = Zq.getRandomElement(true);
	        g0 = groupParams.Gq.modExp(Gq.g, y0);
	    }
	    else {
	        y0 = Zq.getElement(issKeyPair.y0);
	        g0 = Gq.getElement(issKeyPair.g0);
	    }
	    // g = [g0, g1, ... gn, gt]
	    const g = groupParams.g.slice(0, n); // keep only n generators
	    g.unshift(g0);
	    g.push(groupParams.gt);
	    if (!UIDP) {
	        // UIDP not define, let's set it to the hash of the other fields
	        const hash = new Hash(descGq);
	        hash.update(g);
	        hash.update(e);
	        hash.update(S);
	        UIDP = await hash.digest();
	    }
	    return {
	        ip: await IssuerParams.create(UIDP, descGq, groupToHash(descGq), g, e, S),
	        y0: y0
	    };
	}
	// c.f. spec section 2.3.5
	async function computeXt(ip, TI) {
	    const H = ip.Gq.getHash();
	    H.update(new Byte(1));
	    // const p = await ip.P;
	    H.update(ip.P);
	    H.update(TI);
	    return ip.Gq.Zq.getElement(await H.digest());
	}
	// c.f. spec section 2.3.5
	async function computeXi(i, ip, Ai) {
	    const e_i = ip.e[i - 1].b[0]; // e_i is 0-based
	    if (e_i === 1) {
	        const H = ip.Gq.getHash();
	        return ip.Gq.Zq.getElement(await H.digest(Ai));
	    }
	    else if (e_i === 0) {
	        // verify that 0 <= A < q
	        const x = ip.Gq.Zq.getElement(Ai);
	        return x;
	    }
	    else {
	        throw `invalid e[i] index: ${i}`;
	    }
	}
	// c.f. spec section 2.3.6
	async function verifyTokenSignature(ip, upt) {
	    const Gq = ip.Gq;
	    const Zq = Gq.Zq;
	    if (upt.h.equals(Gq.getIdentity())) {
	        throw `invalid token`;
	    }
	    const H = Gq.getHash();
	    H.update(upt.h);
	    H.update(upt.PI);
	    H.update(upt.sZp);
	    const exponents = [upt.sRp, Zq.negate(upt.sCp)];
	    H.update(Gq.multiModExp([Gq.g, ip.g[0]], exponents));
	    H.update(Gq.multiModExp([upt.h, upt.sZp], exponents));
	    const value = Zq.getElement(await H.digest());
	    if (!upt.sCp.equals(value)) {
	        throw `invalid token`;
	    }
	}
	// c.f. spec section 2.3.7
	async function computeTokenId(Gq, upt) {
	    const H = Gq.getHash();
	    H.update(upt.h);
	    H.update(upt.sZp);
	    H.update(upt.sCp);
	    H.update(upt.sRp);
	    return await H.digest();
	}
	async function computePresentationChallenge(Gq, upt, a, D, xInD, m, md) {
	    const UIDT = await computeTokenId(Gq, upt);
	    let H = Gq.getHash();
	    H.update(UIDT);
	    H.update(a);
	    H.update(D);
	    H.update(xInD);
	    H.update([]); // <C>
	    H.update([]); // {cTilda in C}
	    H.update([]); // {aTilda in C}
	    H.update(0); // p
	    H.update(null); // ap
	    H.update(null); // Ps
	    H.update(m);
	    const cp = await H.digest();
	    H = Gq.getHash();
	    H.update([cp, md]);
	    return {
	        UIDT: UIDT,
	        c: Gq.Zq.getElement(await H.digest())
	    };
	}
	class IssuanceParticipant {
	    constructor(n) {
	        checkUnsignedInt(n);
	        this.n = n;
	    }
	    async computeGamma(A, ip, TI) {
	        const Gq = ip.Gq;
	        const x = await Promise.all(A.map(async (a, i, array) => computeXi(i + 1, ip, a)));
	        x.unshift(Gq.Zq.ONE);
	        const xt = await computeXt(ip, TI);
	        x.push(xt);
	        const gamma = Gq.multiModExp(ip.g, x);
	        return gamma;
	    }
	}
	class Prover extends IssuanceParticipant {
	    constructor(ip, TI, PI, n) {
	        super(n);
	        this.h = [];
	        this.t1 = [];
	        this.t2 = [];
	        this.sigmaZPrime = [];
	        this.sigmaAPrime = [];
	        this.sigmaBPrime = [];
	        this.sigmaCPrime = [];
	        this.ip = ip;
	        const Gq = ip.Gq;
	        const Zq = Gq.Zq;
	        this.TI = TI;
	        this.PI = PI;
	        // precomputation (NOTE: could move this out to its own function)
	        this.alpha = Zq.getRandomElements(n, true);
	        this.beta1 = Zq.getRandomElements(n);
	        this.beta2 = Zq.getRandomElements(n);
	    }
	    /**
	     * Static Factory for creating instances of Prover
	     *
	     * @static
	     * @param {IssuerParams} ip
	     * @param {Uint8Array[]} A
	     * @param {Uint8Array} TI
	     * @param {Uint8Array} PI
	     * @param {number} n
	     * @return {*}  {Promise<Prover>}
	     * @memberof Prover
	     */
	    static async create(ip, A, TI, PI, n) {
	        const prover = new Prover(ip, TI, PI, n);
	        const gamma = await prover.computeGamma(A, ip, TI);
	        const Gq = prover.ip.Gq;
	        const t1Base = [ip.g[0], Gq.g];
	        for (let i = 0; i < n; i++) {
	            prover.h.push(Gq.modExp(gamma, prover.alpha[i]));
	            prover.t1.push(Gq.multiModExp(t1Base, [prover.beta1[i], prover.beta2[i]]));
	            prover.t2.push(Gq.modExp(prover.h[i], prover.beta2[i]));
	        }
	        return prover;
	    }
	    async createSecondMessage(msg1) {
	        // second message
	        if (this.n != msg1.sA.length ||
	            this.n != msg1.sB.length) {
	            throw `invalid first message`;
	        }
	        const sigmaC = [];
	        const Gq = this.ip.Gq;
	        const Zq = Gq.Zq;
	        for (let i = 0; i < this.n; i++) {
	            this.sigmaZPrime.push(Gq.modExp(msg1.sZ, this.alpha[i]));
	            this.sigmaAPrime.push(Gq.mul(this.t1[i], msg1.sA[i]));
	            this.sigmaBPrime.push(Gq.multiModExp([this.sigmaZPrime[i], this.t2[i], msg1.sB[i]], [this.beta1[i], Zq.ONE, this.alpha[i]]));
	            const H = Gq.getHash();
	            H.update(this.h[i]);
	            H.update(this.PI);
	            H.update(this.sigmaZPrime[i]);
	            H.update(this.sigmaAPrime[i]);
	            H.update(this.sigmaBPrime[i]);
	            this.sigmaCPrime.push(Zq.getElement(await H.digest()));
	            sigmaC.push(Zq.add(this.sigmaCPrime[i], this.beta1[i]));
	        }
	        return { sC: sigmaC };
	    }
	    createTokens(msg3, skipValidation = false) {
	        // U-Prove token generation
	        if (this.n != msg3.sR.length) {
	            throw `invalid third message`;
	        }
	        const Gq = this.ip.Gq;
	        const Zq = Gq.Zq;
	        const uptk = [];
	        for (let i = 0; i < this.n; i++) {
	            const sigmaRPrime = Zq.add(msg3.sR[i], this.beta2[i]);
	            if (!skipValidation) {
	                const lhs = Gq.mul(this.sigmaAPrime[i], this.sigmaBPrime[i]);
	                const rhs = Gq.multiModExp([Gq.mul(Gq.g, this.h[i]), Gq.mul(this.ip.g[0], this.sigmaZPrime[i])], [sigmaRPrime, Zq.negate(this.sigmaCPrime[i])]);
	                if (!lhs.equals(rhs)) {
	                    throw `invalid token ${i}`;
	                }
	            }
	            uptk.push({
	                upt: {
	                    UIDP: this.ip.UIDP,
	                    h: this.h[i],
	                    TI: this.TI,
	                    PI: this.PI,
	                    sZp: this.sigmaZPrime[i],
	                    sCp: this.sigmaCPrime[i],
	                    sRp: sigmaRPrime
	                },
	                alphaInverse: Zq.invert(this.alpha[i])
	            });
	        }
	        return uptk;
	    }
	}
	class Issuer extends IssuanceParticipant {
	    constructor(ikp, n) {
	        super(n);
	        this.ikp = ikp;
	        this.w = [];
	        this.gamma = {};
	        this.sigmaZ = {};
	        this.sigmaA = [];
	        this.sigmaB = [];
	        this.Gq = ikp.ip.Gq;
	        this.y0 = ikp.y0;
	    }
	    static async create(ikp, A, TI, n) {
	        const issuer = new Issuer(ikp, n);
	        const Gq = issuer.Gq;
	        const Zq = Gq.Zq;
	        issuer.gamma = await issuer.computeGamma(A, ikp.ip, TI);
	        issuer.sigmaZ = Gq.modExp(issuer.gamma, issuer.y0);
	        // precomputation (NOTE: could move this out to its own function)
	        issuer.w = Zq.getRandomElements(n);
	        issuer.sigmaA = issuer.w.map(w_i => Gq.modExp(Gq.g, w_i));
	        issuer.sigmaB = issuer.w.map(w_i => Gq.modExp(issuer.gamma, w_i));
	        return issuer;
	    }
	    createFirstMessage() {
	        return {
	            sZ: this.sigmaZ,
	            sA: this.sigmaA,
	            sB: this.sigmaB
	        };
	    }
	    createThirdMessage(msg2) {
	        if (this.n != msg2.sC.length) {
	            throw `invalid second message`;
	        }
	        const Zq = this.Gq.Zq;
	        const sigmaR = this.w.map((w_i, i, array) => Zq.add(Zq.mul(msg2.sC[i], this.y0), w_i));
	        return {
	            sR: sigmaR
	        };
	    }
	}
	function sanitizeD(D) {
	    checkUnsignedInt(D);
	    const SetD = new Set(D);
	    D = Array.from(SetD).sort((a, b) => a - b);
	    return D;
	}
	async function generatePresentationProof(ip, D, upkt, m, A, md = new Uint8Array()) {
	    const n = A.length;
	    D = sanitizeD(D);
	    const USet = new Set(Array.from({ length: n }, (e, i) => i + 1));
	    D.forEach(v => USet.delete(v));
	    const U = Array.from(USet).sort((a, b) => a - b);
	    const Gq = ip.Gq;
	    const Zq = Gq.Zq;
	    const x = await Promise.all(A.map((a, i, array) => computeXi(i + 1, ip, a)));
	    const w0 = Zq.getRandomElement();
	    const w = Zq.getRandomElements(n - D.length);
	    const H = Gq.getHash();
	    const a = await H.digest(Gq.multiModExp([upkt.upt.h, ...ip.g.slice(1, n + 1).filter((g, i, array) => U.includes(i + 1))], [w0, ...w]));
	    const challengeData = await computePresentationChallenge(Gq, upkt.upt, a, D, x.filter((x, i, array) => D.includes(i + 1)), m, md);
	    const negC = Zq.negate(challengeData.c);
	    const r = [Zq.add(Zq.mul(challengeData.c, upkt.alphaInverse), w0)];
	    for (let i = 0; i < U.length; i++) {
	        r.push(Zq.add(Zq.mul(negC, x[U[i] - 1]), w[i]));
	    }
	    const disclosedA = {};
	    for (const d of D) {
	        disclosedA[d] = A[d - 1];
	    }
	    return {
	        UIDT: challengeData.UIDT,
	        pp: {
	            A: disclosedA,
	            a: a,
	            r: r
	        }
	    };
	}
	async function verifyPresentationProof(ip, upt, m, pp, md = new Uint8Array()) {
	    const Gq = ip.Gq;
	    const Zq = Gq.Zq;
	    // U-Prove token verification
	    verifyTokenSignature(ip, upt);
	    // presentation proof verification
	    const xt = await computeXt(ip, upt.TI);
	    let D = [];
	    let x = [];
	    const px = [];
	    if (pp.A) {
	        Object.entries(pp.A).forEach(([iStr, Ai]) => {
	            const i = Number(iStr);
	            D.push(i);
	            px.push(computeXi(i, ip, Ai));
	        });
	        x = await Promise.all(px);
	        // sort the values in case they were out of order in pp.A
	        D = D.sort((a, b) => a - b);
	        x = D.map(i => x[D.indexOf(i)]);
	    }
	    const challengeData = await computePresentationChallenge(Gq, upt, pp.a, D, x, m, md);
	    const t = ip.g.length - 1;
	    const base0 = Gq.multiModExp([ip.g[0], ...ip.g.filter((g, i, array) => D.includes(i)), ip.g[t]], [Zq.ONE, ...x, xt]);
	    const hashInput = Gq.multiModExp([base0, upt.h, ...ip.g.slice(1, t).filter((g, i, array) => !D.includes(i + 1))], [Zq.negate(challengeData.c), pp.r[0], ...pp.r.slice(1)]);
	    if (!arrayEqual(pp.a, await Gq.getHash().digest(hashInput))) {
	        throw `invalid presentation proof`;
	    }
	    return {
	        UIDT: challengeData.UIDT
	    };
	}

	var uprove = /*#__PURE__*/Object.freeze({
		__proto__: null,
		get ECGroup () { return ECGroup; },
		IssuanceParticipant: IssuanceParticipant,
		Issuer: Issuer,
		IssuerParams: IssuerParams,
		Prover: Prover,
		computeXi: computeXi,
		computeXt: computeXt,
		createIssuerKeyAndParams: createIssuerKeyAndParams,
		generatePresentationProof: generatePresentationProof,
		verifyPresentationProof: verifyPresentationProof,
		verifyTokenSignature: verifyTokenSignature
	});

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	// This file defines a JSON serialization format for the U-Prove artifacts
	function encodeIssuerParams(ip) {
	    return {
	        UIDP: bytesToBase64url(ip.UIDP),
	        dGq: ip.descGq,
	        UIDH: ip.UIDH,
	        g0: bytesToBase64url(ip.g[0].getBytes()),
	        e: ip.e.map(e => e.b[0]),
	        S: bytesToBase64url(ip.S)
	    };
	}
	async function decodeIssuerParams(ipJSON) {
	    const n = ipJSON.e.length;
	    let descGq = ECGroup.P256;
	    switch (ipJSON.dGq) {
	        case ECGroup.P256:
	            descGq = ECGroup.P256;
	            break;
	        case ECGroup.P384:
	            descGq = ECGroup.P384;
	            break;
	        case ECGroup.P521:
	            descGq = ECGroup.P521;
	            break;
	    }
	    const groupParams = getEcGroup(descGq);
	    const Gq = groupParams.Gq;
	    // g = [g0, g1, ... gn, gt]
	    const g = groupParams.g.slice(0, n); // keep only n generators
	    g.unshift(Gq.getElement(base64urlToBytes(ipJSON.g0)));
	    g.push(groupParams.gt);
	    return await IssuerParams.create(base64urlToBytes(ipJSON.UIDP), descGq, ipJSON.UIDH, g, ipJSON.e.map(e => new Byte(e)), base64urlToBytes(ipJSON.S));
	}
	function encodeUProveToken(upt) {
	    return {
	        UIDP: bytesToBase64url(upt.UIDP),
	        h: bytesToBase64url(upt.h.getBytes()),
	        TI: bytesToBase64url(upt.TI),
	        PI: bytesToBase64url(upt.PI),
	        sZp: bytesToBase64url(upt.sZp.getBytes()),
	        sCp: bytesToBase64url(upt.sCp.getBytes()),
	        sRp: bytesToBase64url(upt.sRp.getBytes())
	    };
	}
	function decodeUProveToken(ip, uptJSON) {
	    const Gq = ip.Gq;
	    const Zq = Gq.Zq;
	    return {
	        UIDP: base64urlToBytes(uptJSON.UIDP),
	        h: Gq.getElement(base64urlToBytes(uptJSON.h)),
	        TI: base64urlToBytes(uptJSON.TI),
	        PI: base64urlToBytes(uptJSON.PI),
	        sZp: Gq.getElement(base64urlToBytes(uptJSON.sZp)),
	        sCp: Zq.getElement(base64urlToBytes(uptJSON.sCp)),
	        sRp: Zq.getElement(base64urlToBytes(uptJSON.sRp))
	    };
	}
	function encodeFirstIssuanceMessage(m1) {
	    return {
	        sZ: bytesToBase64url(m1.sZ.getBytes()),
	        sA: m1.sA.map(sigmaA => bytesToBase64url(sigmaA.getBytes())),
	        sB: m1.sB.map(sigmaB => bytesToBase64url(sigmaB.getBytes())),
	    };
	}
	function decodeFirstIssuanceMessage(ip, m1JSON) {
	    const Gq = ip.Gq;
	    return {
	        sZ: Gq.getElement(base64urlToBytes(m1JSON.sZ)),
	        sA: m1JSON.sA.map(sigmaA => Gq.getElement(base64urlToBytes(sigmaA))),
	        sB: m1JSON.sB.map(sigmaB => Gq.getElement(base64urlToBytes(sigmaB)))
	    };
	}
	function encodeSecondIssuanceMessage(m2) {
	    return {
	        sC: m2.sC.map(sigmaC => bytesToBase64url(sigmaC.getBytes()))
	    };
	}
	function decodeSecondIssuanceMessage(ip, m2JSON) {
	    const Zq = ip.Gq.Zq;
	    return {
	        sC: m2JSON.sC.map(sigmaC => Zq.getElement(base64urlToBytes(sigmaC)))
	    };
	}
	function encodeThirdIssuanceMessage(m3) {
	    return {
	        sR: m3.sR.map(sigmaR => bytesToBase64url(sigmaR.getBytes()))
	    };
	}
	function decodeThirdIssuanceMessage(ip, m3JSON) {
	    const Zq = ip.Gq.Zq;
	    return {
	        sR: m3JSON.sR.map(sigmaR => Zq.getElement(base64urlToBytes(sigmaR)))
	    };
	}
	function encodePresentationProof(pp) {
	    const ppJSON = {
	        a: bytesToBase64url(pp.a),
	        r: pp.r.map(r => bytesToBase64url(r.getBytes()))
	    };
	    if (pp.A && Object.keys(pp.A).length > 0) {
	        ppJSON.A = Object.entries(pp.A).reduce((acc, [i, Ai]) => {
	            acc[Number(i)] = bytesToBase64url(Ai);
	            return acc;
	        }, {});
	    }
	    return ppJSON;
	}
	function decodePresentationProof(ip, ppJSON) {
	    const Zq = ip.Gq.Zq;
	    const pp = {
	        a: base64urlToBytes(ppJSON.a),
	        r: ppJSON.r.map(r => Zq.getElement(base64urlToBytes(r)))
	    };
	    if (ppJSON.A) {
	        pp.A = Object.entries(ppJSON.A).reduce((acc, [i, Ai]) => {
	            acc[Number(i)] = base64urlToBytes(Ai);
	            return acc;
	        }, {});
	    }
	    return pp;
	}
	function encodeUIDT(UIDT) {
	    return bytesToBase64url(UIDT);
	}
	function decodeUIDT(UIDT) {
	    return base64urlToBytes(UIDT);
	}

	var serialization = /*#__PURE__*/Object.freeze({
		__proto__: null,
		decodeFirstIssuanceMessage: decodeFirstIssuanceMessage,
		decodeIssuerParams: decodeIssuerParams,
		decodePresentationProof: decodePresentationProof,
		decodeSecondIssuanceMessage: decodeSecondIssuanceMessage,
		decodeThirdIssuanceMessage: decodeThirdIssuanceMessage,
		decodeUIDT: decodeUIDT,
		decodeUProveToken: decodeUProveToken,
		encodeFirstIssuanceMessage: encodeFirstIssuanceMessage,
		encodeIssuerParams: encodeIssuerParams,
		encodePresentationProof: encodePresentationProof,
		encodeSecondIssuanceMessage: encodeSecondIssuanceMessage,
		encodeThirdIssuanceMessage: encodeThirdIssuanceMessage,
		encodeUIDT: encodeUIDT,
		encodeUProveToken: encodeUProveToken,
		fromBase64Url: base64urlToBytes,
		toBase64Url: bytesToBase64url
	});

	// Copyright (c) Microsoft Corporation.
	// Licensed under the MIT license.
	// Implements the U-Prove JSON Framework (UPJF)
	// expiration functions
	var ExpirationType;
	(function (ExpirationType) {
	    ExpirationType["sec"] = "sec";
	    ExpirationType["hour"] = "hour";
	    ExpirationType["day"] = "day";
	    ExpirationType["week"] = "week";
	    ExpirationType["year"] = "year";
	})(ExpirationType || (ExpirationType = {}));
	const MS_PER_SECOND = 1000;
	const MS_PER_HOUR = MS_PER_SECOND * 60 * 60;
	const MS_PER_DAY = MS_PER_HOUR * 24;
	const MS_PER_WEEK = MS_PER_DAY * 7;
	const MS_PER_YEAR = MS_PER_WEEK * 52;
	function msToTypedTime(type, t) {
	    let typedT;
	    switch (type) {
	        case ExpirationType.sec:
	            typedT = t / MS_PER_SECOND;
	            break;
	        case ExpirationType.hour:
	            typedT = t / MS_PER_HOUR;
	            break;
	        case ExpirationType.day:
	            typedT = t / MS_PER_DAY;
	            break;
	        case ExpirationType.week:
	            typedT = t / MS_PER_WEEK;
	            break;
	        case ExpirationType.year:
	            typedT = t / MS_PER_YEAR;
	            break;
	    }
	    return typedT;
	}
	/**
	 * Gets the expiration date given an expiration type, value, and start time.
	 * @param {ExpirationType} type - expiration type
	 * @param {number} t - non-negative integer, number of typed units to add to epoch
	 * @param {number} start - typed start time; defaults to the current time
	 * @returns the expiration date, adding `t` units from the `start` time of a given `type`
	 */
	function getExp(type, t, start = undefined) {
	    checkUnsignedInt(t);
	    if (start) {
	        checkUnsignedInt(start);
	    }
	    else {
	        // round up current time to next value depending on expiration type
	        start = Math.ceil(msToTypedTime(type, Date.now()));
	    }
	    return start + t;
	}
	/**
	 * Checks if the typed target date is after the expiration
	 * @param {ExpirationType} type - expiration type
	 * @param {number} exp - typed expiration date
	 * @param {number} target - typed target date for comparison; defaults to the current time
	 * @returns `true` if the target date is expired, `false` otherwise
	 */
	function isExpired(type, exp, target = undefined) {
	    if (!target) {
	        target = msToTypedTime(type, Date.now());
	    }
	    return target > exp;
	}
	function parseSpecification(S) {
	    const spec = JSON.parse(bytesToString(S));
	    return spec;
	}
	async function createIssuerKeyAndParamsUPJF(descGq, specification, issKeyPair) {
	    const n = specification.n;
	    checkUnsignedInt(n);
	    if (n < 0 || n > 50)
	        throw `${n} is not a valid value for n, must between 0 and 50 inclusively`;
	    return await createIssuerKeyAndParams(descGq, n, undefined, stringToBytes(JSON.stringify(specification)), issKeyPair, undefined);
	}
	var UPAlg;
	(function (UPAlg) {
	    UPAlg["UP256"] = "UP256";
	    UPAlg["UP384"] = "UP384";
	    UPAlg["UP521"] = "UP521";
	})(UPAlg || (UPAlg = {}));
	// encodes Issuer parameters and U-Prove token private keys as base64url
	function encodePrivateKeyAsBase64Url(key) {
	    return bytesToBase64url(key.getBytes());
	}
	// decodes Issuer parameters and U-Prove token private keys from base64url
	function decodeBase64UrlAsPrivateKey(ip, b64) {
	    return ip.Gq.Zq.getElement(base64urlToBytes(b64));
	}
	function descGqToUPAlg(descGq) {
	    switch (descGq) {
	        case ECGroup.P256: return UPAlg.UP256;
	        case ECGroup.P384: return UPAlg.UP384;
	        case ECGroup.P521: return UPAlg.UP521;
	    }
	}
	function encodeIPAsJWK(ip) {
	    return {
	        kty: "UP",
	        alg: descGqToUPAlg(ip.descGq),
	        kid: bytesToBase64url(ip.UIDP),
	        g0: bytesToBase64url(ip.g[0].getBytes()),
	        spec: bytesToBase64url(ip.S)
	    };
	}
	async function decodeJWKAsIP(jwk) {
	    if (jwk.kty !== "UP") {
	        throw `${jwk.kty} is not a valid key type, "UP" expected`;
	    }
	    let descGq;
	    switch (jwk.alg) {
	        case UPAlg.UP256:
	            descGq = ECGroup.P256;
	            break;
	        case UPAlg.UP384:
	            descGq = ECGroup.P384;
	            break;
	        case UPAlg.UP521:
	            descGq = ECGroup.P521;
	            break;
	        default: throw `${jwk.alg} is not a valid algorithm`;
	    }
	    const SBytes = base64urlToBytes(jwk.spec);
	    const spec = JSON.parse(bytesToString(SBytes));
	    const n = spec.n;
	    const groupParams = getEcGroup(descGq);
	    const Gq = groupParams.Gq;
	    // g = [g0, g1, ... gn, gt]
	    const g = groupParams.g.slice(0, n); // keep only n generators
	    g.unshift(Gq.getElement(base64urlToBytes(jwk.g0)));
	    g.push(groupParams.gt);
	    const e = jwk.e ? jwk.e : new Array(n).fill(1);
	    return await IssuerParams.create(base64urlToBytes(jwk.kid), descGq, groupToHash(descGq), g, e.map(e => new Byte(e)), SBytes);
	}
	function parseTokenInformation(TI) {
	    const tokenInformation = JSON.parse(bytesToString(TI));
	    return tokenInformation;
	}
	function encodeTokenInformation(TI) {
	    return stringToBytes(JSON.stringify(TI));
	}
	function createJWS(alg, m, tp) {
	    const header = bytesToBase64url(stringToBytes(JSON.stringify({ alg: alg })));
	    const payload = bytesToBase64url(m);
	    const sig = bytesToBase64url(stringToBytes(JSON.stringify(tp)));
	    return header + "." + payload + "." + sig;
	}
	function parseJWS(jws) {
	    const parts = jws.split(".");
	    if (!parts || parts.length != 3) {
	        throw "can't parse jws into 3 parts";
	    }
	    try {
	        const upJws = {
	            header: JSON.parse(bytesToString(base64urlToBytes(parts[0]))),
	            payload: base64urlToBytes(parts[1]),
	            sig: JSON.parse(bytesToString(base64urlToBytes(parts[2])))
	        };
	        return upJws;
	    }
	    catch (err) {
	        throw "can't parse jws" + err;
	    }
	}

	var upjf = /*#__PURE__*/Object.freeze({
		__proto__: null,
		get ExpirationType () { return ExpirationType; },
		get UPAlg () { return UPAlg; },
		createIssuerKeyAndParamsUPJF: createIssuerKeyAndParamsUPJF,
		createJWS: createJWS,
		decodeBase64UrlAsPrivateKey: decodeBase64UrlAsPrivateKey,
		decodeJWKAsIP: decodeJWKAsIP,
		descGqToUPAlg: descGqToUPAlg,
		encodeIPAsJWK: encodeIPAsJWK,
		encodePrivateKeyAsBase64Url: encodePrivateKeyAsBase64Url,
		encodeTokenInformation: encodeTokenInformation,
		getExp: getExp,
		isExpired: isExpired,
		msToTypedTime: msToTypedTime,
		parseJWS: parseJWS,
		parseSpecification: parseSpecification,
		parseTokenInformation: parseTokenInformation
	});

	exports.serialization = serialization;
	exports.upjf = upjf;
	exports.uprove = uprove;
	exports.utils = utils;

}));
