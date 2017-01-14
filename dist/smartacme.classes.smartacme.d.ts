/// <reference types="q" />
import 'typings-global';
import * as q from 'q';
import { SmartacmeHelper, IRsaKeypair } from './smartacme.classes.helper';
export declare type TChallengeType = 'dns-01' | 'http-01';
export declare type TChallengeStatus = 'pending';
export interface ISmartAcmeChallenge {
    uri: string;
    status: TChallengeStatus;
    type: TChallengeType;
    token: string;
    keyAuthorization: string;
}
export interface ISmartAcmeChallengeAccepted extends ISmartAcmeChallenge {
    keyHash: string;
}
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
     * requests a challenge for a domain
     * @param domainNameArg - the domain name to request a challenge for
     * @param challengeType - the challenge type to request
     */
    requestChallenge(domainNameArg: string, challengeTypeArg?: TChallengeType): q.Promise<ISmartAcmeChallengeAccepted>;
    /**
     * getCertificate - takes care of cooldown, validation polling and certificate retrieval
     */
    getCertificate(): void;
    /**
     * validates a challenge
     */
    validate(challenge: ISmartAcmeChallengeAccepted): q.Promise<{}>;
    /**
     * accept a challenge - for private use only
     */
    private acceptChallenge(challenge);
}
