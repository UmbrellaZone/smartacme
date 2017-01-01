import 'typings-global';
export interface IRsaKeypair {
    publicKey: string;
    privateKey: string;
}
export declare class SmartacmeHelper {
    createKeypair(bit?: number): IRsaKeypair;
}
