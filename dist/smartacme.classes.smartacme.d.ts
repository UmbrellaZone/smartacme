/// <reference types="q" />
import 'typings-global';
import * as q from 'q';
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export declare class SmartAcme {
    preparedBool: boolean;
    acmeUrls: any;
    productionBool: boolean;
    keyPair: any;
    constructor(productionArg?: boolean);
    /**
     * prepares the SmartAcme class
     */
    prepareAcme(): q.Promise<{}>;
    /**
     * creates an account if not currently present in module
     */
    createAccount(): q.Promise<{}>;
    /**
     * creates a keyPair
     */
    createKeyPair(): q.Promise<{}>;
    /**
     * gets the Acme Urls
     */
    getAcmeUrls(): q.Promise<{}>;
}
