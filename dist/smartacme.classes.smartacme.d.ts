import * as acmeclient from './smartacme.classes.acmeclient';
export declare class SmartAcme {
    acmeAccount: AcmeAccount;
    acmeClient: acmeclient.AcmeClient;
    constructor(directoryUrlArg?: string);
    /**
     * creates an account
     */
    createAccount(): void;
    /**
     * returns the openssl key pair for
     */
    getKeyPair(): any;
}
export declare class AcmeAccount {
}
