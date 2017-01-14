/// <reference types="q" />
import * as q from 'q';
import { IRsaKeypair } from './smartacme.classes.smartacme';
import { AcmeAccount } from './smartacme.classes.acmeaccount';
/**
 * types of challenges supported by letsencrypt and this module
 */
export declare type TChallengeType = 'dns-01' | 'http-01';
/**
 * values that a challenge's status can have
 */
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
export interface IAcmeCsrConstructorOptions {
    bit: number;
    key: string;
    domain: string;
    country: string;
    country_short: string;
    locality: string;
    organization: string;
    organization_short: string;
    password: string;
    unstructured: string;
    subject_alt_names: string[];
}
/**
 * class AcmeCert represents a cert for domain
 */
export declare class AcmeCert {
    attributes: any;
    fullchain: string;
    parentAcmeAccount: AcmeAccount;
    csr: any;
    validFrom: Date;
    validTo: Date;
    keypair: IRsaKeypair;
    keyPairFinal: IRsaKeypair;
    constructor(optionsArg: IAcmeCsrConstructorOptions, parentSmartAcmeArg: any);
    /**
     * requests a challenge for a domain
     * @param domainNameArg - the domain name to request a challenge for
     * @param challengeType - the challenge type to request
     */
    requestChallenge(domainNameArg: string, challengeTypeArg?: TChallengeType): q.Promise<ISmartAcmeChallengeAccepted>;
    /**
     * validates a challenge, only call after you have set the challenge at the expected location
     */
    validate(challenge: ISmartAcmeChallengeAccepted): q.Promise<{}>;
    /**
     * requests a certificate
     */
    requestCert(): q.Promise<{}>;
    /**
     * getCertificate - takes care of cooldown, validation polling and certificate retrieval
     */
    getCertificate(): void;
    /**
     * accept a challenge - for private use only
     */
    private acceptChallenge(challenge);
}
