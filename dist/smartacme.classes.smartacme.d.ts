/// <reference types="q" />
import * as q from 'q';
import { AcmeAccount } from './smartacme.classes.acmeaccount';
/**
 * a rsa keypair needed for account creation and subsequent requests
 */
export interface IRsaKeypair {
    publicKey: string;
    privateKey: string;
}
export { AcmeAccount } from './smartacme.classes.acmeaccount';
export { AcmeCert, ISmartAcmeChallenge, ISmartAcmeChallengeChosen } from './smartacme.classes.acmecert';
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export declare class SmartAcme {
    acmeUrl: string;
    productionBool: boolean;
    keyPair: IRsaKeypair;
    rawacmeClient: any;
    /**
     * the constructor for class SmartAcme
     */
    constructor(productionArg?: boolean);
    /**
     * init the smartacme instance
     */
    init(): q.Promise<{}>;
    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAcmeAccount(): q.Promise<AcmeAccount>;
}
