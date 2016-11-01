import * as acmeclient from './smartacme.classes.acmeclient';
export declare class SmartAcme {
    acmeClient: acmeclient.AcmeClient;
    constructor(directoryUrlArg?: string);
}
