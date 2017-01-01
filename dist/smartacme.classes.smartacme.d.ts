/// <reference types="q" />
import 'typings-global';
import * as q from 'q';
import { SmartacmeHelper, IRsaKeypair } from './smartacme.classes.helper';
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export declare class SmartAcme {
    helper: SmartacmeHelper;
    acmeUrl: string;
    productionBool: boolean;
    keyPair: IRsaKeypair;
    location: string;
    link: string;
    rawacmeClient: any;
    JWK: any;
    /**
     * the constructor for class SmartAcme
     */
    constructor(productionArg?: boolean);
    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAccount(): q.Promise<{}>;
    agreeTos(): q.Promise<{}>;
    /**
     * requests a certificate
     */
    requestCertificate(domainNameArg: any): q.Promise<{}>;
}
