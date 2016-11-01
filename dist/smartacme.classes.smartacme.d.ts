import * as acmeclient from './smartacme.classes.acmeclient';
export declare class SmartAcme {
    acmeAccount: AcmeAccount;
    acmeClient: acmeclient.AcmeClient;
    constructor(directoryUrlArg?: string);
    createAccount(): void;
}
export declare class AcmeAccount {
}
