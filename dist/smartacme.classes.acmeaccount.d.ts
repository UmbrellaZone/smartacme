/// <reference types="q" />
import * as q from 'q';
import { SmartAcme } from './smartacme.classes.smartacme';
/**
 * class AcmeAccount represents an AcmeAccount
 */
export declare class AcmeAccount {
    parentSmartAcme: SmartAcme;
    location: string;
    link: string;
    JWK: any;
    constructor(smartAcmeParentArg: SmartAcme);
    /**
     * register the account with letsencrypt
     */
    register(): q.Promise<{}>;
    /**
     * agree to letsencrypr terms of service
     */
    agreeTos(): q.Promise<{}>;
    createAcmeCert(domainNameArg: string): void;
}
