import { SmartAcme } from './smartacme.classes.smartacme';
import { AcmeCert } from './smartacme.classes.acmecert';
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
    register(): Promise<{}>;
    /**
     * agree to letsencrypr terms of service
     */
    agreeTos(): Promise<{}>;
    createAcmeCert(domainNameArg: string, countryArg?: string, countryShortArg?: string, city?: string, companyArg?: string, companyShortArg?: string): Promise<AcmeCert>;
}
