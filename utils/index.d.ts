import { CashAddressNetworkPrefix, WalletImportFormatType, CashAddressType, TransactionCommon } from '@bitauth/libauth';
export declare function hexToWif(hexStr: string, network: CashAddressNetworkPrefix): any;
export declare function cashAddrToLegacy(cashAddr: string): string;
export interface PrivateKeyI {
    privateKey: Uint8Array;
    type: WalletImportFormatType;
}
export declare function uint8ArrayToHex(arr: Uint8Array): string;
export declare function hexSecretToHexPrivkey(text: string): string;
export declare function textToUtf8Hex(text: string): string;
export declare function wifToPrivateKey(secret: string): Uint8Array;
export declare function deriveCashaddr(privateKey: Uint8Array, networkPrefix: CashAddressNetworkPrefix, addrType: CashAddressType): string;
export interface SourceOutput {
    valueSatoshis: bigint;
    cashAddress?: string;
    token?: {
        amount: bigint;
        category: Uint8Array;
        nft?: {
            capability: "none" | "mutable" | "minting";
            commitment: Uint8Array;
        };
    };
}
export declare function extractOutputs(tx: TransactionCommon, network: "bitcoincash" | "bchtest" | "bchreg"): SourceOutput[];
export declare function signUnsignedTransaction(decoded: TransactionCommon, sourceOutputs: SourceOutput[], signingKey: Uint8Array): Uint8Array;
export declare function pack(tx: any): string;
export declare function unPack(tx: string): any;
