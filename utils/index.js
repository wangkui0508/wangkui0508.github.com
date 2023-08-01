"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.unPack = exports.pack = exports.signUnsignedTransaction = exports.extractOutputs = exports.deriveCashaddr = exports.wifToPrivateKey = exports.textToUtf8Hex = exports.hexSecretToHexPrivkey = exports.uint8ArrayToHex = exports.cashAddrToLegacy = exports.hexToWif = void 0;
const libauth_1 = require("@bitauth/libauth");
const bchaddr = require('bchaddrjs');
const wif = require('wif');
const Buffer_1 = require("Buffer");
const algo_msgpack_with_bigint_1 = require("algo-msgpack-with-bigint");
const base64url_1 = require("base64url");
function hexToWif(hexStr, network) {
    var privateKey = new Buffer_1.Buffer(hexStr, 'hex');
    if (network == libauth_1.CashAddressNetworkPrefix.mainnet) {
        return wif.encode(128, privateKey, true);
    }
    else {
        return wif.encode(239, privateKey, true);
    }
}
exports.hexToWif = hexToWif;
function cashAddrToLegacy(cashAddr) {
    return bchaddr.toLegacyAddress(cashAddr);
}
exports.cashAddrToLegacy = cashAddrToLegacy;
function uint8ArrayToHex(arr) {
    return (0, libauth_1.binToHex)(arr);
}
exports.uint8ArrayToHex = uint8ArrayToHex;
function hexSecretToHexPrivkey(text) {
    if (!(0, libauth_1.isHex)(text)) {
        throw "Invalid Hex Secret";
    }
    const hashHex = (0, libauth_1.binToHex)(libauth_1.sha256.hash((0, libauth_1.hexToBin)(text)));
    let n = BigInt("0x" + hashHex);
    const m = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
    n = n % m;
    return n.toString(16);
}
exports.hexSecretToHexPrivkey = hexSecretToHexPrivkey;
function textToUtf8Hex(text) {
    const encoder = new TextEncoder();
    return (0, libauth_1.binToHex)(encoder.encode(text));
}
exports.textToUtf8Hex = textToUtf8Hex;
function wifToPrivateKey(secret) {
    let wifResult = (0, libauth_1.decodePrivateKeyWif)(secret);
    if (typeof wifResult === "string") {
        throw Error(wifResult);
    }
    let resultData = wifResult;
    return resultData.privateKey;
}
exports.wifToPrivateKey = wifToPrivateKey;
function deriveCashaddr(privateKey, networkPrefix, addrType) {
    let publicKey = libauth_1.secp256k1.derivePublicKeyCompressed(privateKey);
    if (typeof publicKey === "string") {
        throw new Error(publicKey);
    }
    let pkh = (0, libauth_1.hash160)(publicKey);
    return (0, libauth_1.encodeCashAddress)(networkPrefix, addrType, pkh);
}
exports.deriveCashaddr = deriveCashaddr;
function extractOutputs(tx, network) {
    let outputs = [];
    for (const out of tx.outputs) {
        let result = (0, libauth_1.lockingBytecodeToCashAddress)(out.lockingBytecode, network);
        if (typeof result !== "string") {
            result = (0, libauth_1.disassembleBytecodeBCH)(out.lockingBytecode);
        }
        const entry = {
            valueSatoshis: out.valueSatoshis,
            cashAddress: result,
            token: out.token,
        };
        outputs.push(entry);
    }
    return outputs;
}
exports.extractOutputs = extractOutputs;
function signUnsignedTransaction(decoded, sourceOutputs, signingKey) {
    const template = (0, libauth_1.importAuthenticationTemplate)(libauth_1.authenticationTemplateP2pkhNonHd);
    if (typeof template === "string") {
        throw new Error("Transaction template error");
    }
    const compiler = (0, libauth_1.authenticationTemplateToCompilerBCH)(template);
    const transactionTemplate = Object.assign({}, decoded);
    for (const [index, input] of decoded.inputs.entries()) {
        if (input.unlockingBytecode.byteLength > 0) {
            continue;
        }
        const sourceOutput = sourceOutputs[index];
        transactionTemplate.inputs[index] = Object.assign(Object.assign({}, input), { unlockingBytecode: {
                compiler,
                data: {
                    keys: { privateKeys: { key: signingKey } },
                },
                valueSatoshis: sourceOutput.valueSatoshis,
                script: "unlock",
                token: sourceOutput.token,
            } });
    }
    const result = (0, libauth_1.generateTransaction)(transactionTemplate);
    if (!result.success) {
        throw result.errors;
    }
    return (0, libauth_1.encodeTransaction)(result.transaction);
}
exports.signUnsignedTransaction = signUnsignedTransaction;
function pack(tx) {
    const hex = Buffer_1.Buffer.from((0, algo_msgpack_with_bigint_1.encode)(tx)).toString("hex");
    return base64url_1.default.encode(hex);
}
exports.pack = pack;
function unPack(tx) {
    const hex = base64url_1.default.decode(tx);
    const result = (0, algo_msgpack_with_bigint_1.decode)(Buffer_1.Buffer.from(hex, "hex"));
    return JSON.parse(JSON.stringify(result), function (key, value) {
        if (value && value.type === "Buffer") {
            return new Uint8Array(value.data);
        }
        if (["token", "nft"].includes(key) && value === null) {
            return undefined;
        }
        if (["valueSatoshis", "amount"].includes(key)) {
            return BigInt(value);
        }
        return value;
    });
}
exports.unPack = unPack;
