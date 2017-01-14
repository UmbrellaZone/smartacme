/// <reference types="q" />
import 'typings-global';
import * as q from 'q';
import { SmartAcme } from './smartacme.classes.smartacme';
export interface IRsaKeypair {
    publicKey: string;
    privateKey: string;
}
export declare class SmartacmeHelper {
    parentSmartAcme: SmartAcme;
    constructor(smartAcmeArg: SmartAcme);
    /**
     * creates a keypair to use with requests and to generate JWK from
     */
    createKeypair(bit?: number): IRsaKeypair;
    /**
     * gets an existing registration
     * @executes ASYNC
     */
    getReg(): q.Promise<{}>;
}
