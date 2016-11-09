/// <reference types="q" />
import * as q from 'q';
import { JWebClient } from './smartacme.classes.jwebclient';
import { IReqResArg } from './smartacme.classes.jwebclient';
/**
 * @class AcmeClient
 * @constructor
 * @description ACME protocol implementation from client perspective
 * @param {string} directory_url - Address of directory
 * @param {module:JWebClient~JWebClient} jWebClient - Reference to JSON-Web-Client
 */
export declare class AcmeClient {
    clientProfilePubKey: any;
    daysValid: number;
    directory: any;
    directoryUrl: string;
    emailDefaultPrefix: string;
    emailOverride: string;
    jWebClient: JWebClient;
    regLink: string;
    tosLink: string;
    webroot: string;
    wellKnownPath: string;
    withInteraction: boolean;
    constructor(directoryUrlArg: any);
    /**
     * getDirectory
     * @description retrieve directory entries (directory url must be set prior to execution)
     * @param {function} callback - first argument will be the answer object
     */
    getDirectory(): q.Promise<IReqResArg>;
    /**
     * newRegistration
     * @description try to register (directory lookup must have occured prior to execution)
     * @param {Object} payload
     * @param {function} callback - first argument will be the answer object
     */
    newRegistration(payload: any): q.Promise<{}>;
    /**
     * getRegistration
     * @description get information about registration
     * @param {string} uri - will be exposed when trying to register
     * @param {Object} payload - update information
     * @param {function} callback - first argument will be the answer object
     */
    getRegistration(uri: any, payload: any): q.Promise<IReqResArg>;
    /**
     * authorizeDomain
     * @description authorize domain using challenge-response-method
     * @param {string} domain
     * @param {function} callback - first argument will be the answer object
     */
    authorizeDomain(domain: any): q.Promise<{}>;
    /**
     * acceptChallenge
     * @description tell server which challenge will be accepted
     * @param {Object} challenge
     * @param {function} callback - first argument will be the answer object
     */
    acceptChallenge(challenge?: {}): q.Promise<{}>;
    /**
     * pollUntilValid
     * @description periodically (with exponential back-off) check status of challenge
     * @param {string} uri
     * @param {function} callback - first argument will be the answer object
     * @param {number} retry - factor of delay
     */
    pollUntilValid(uri: any, retry?: number): q.Promise<{}>;
    /**
     * pollUntilIssued
     * @description periodically (with exponential back-off) check status of CSR
     * @param {string} uri
     * @param {function} callback - first argument will be the answer object
     * @param {number} retry - factor of delay
     */
    pollUntilIssued(uri: any, retry?: number): q.Promise<{}>;
    /**
     * requestSigning
     * @description send CSR
     * @param {string} domain - expected to be already sanitized
     * @param {function} callback - first argument will be the answer object
     */
    requestSigning(commonName: any): q.Promise<{}>;
    /**
     * retrieves profile of user (will make directory lookup and registration check)
     * @param {function} callback - first argument will be the answer object
     */
    getProfile(): q.Promise<{}>;
    /**
     * createAccount
     * @description create new account (assumes directory lookup has already occured)
     * @param {string} email
     * @param {function} callback - first argument will be the registration URI
     */
    createAccount(email: string): q.Promise<{}>;
    /**
     * agreeTos
     * @description agree with terms of service (update agreement status in profile)
     * @param {string} tosLink
     * @param {function} callback - first argument will be the answer object
     */
    agreeTos(tosLink: any): q.Promise<{}>;
    /**
     * Entry-Point: Request certificate
     */
    requestCertificate(domainArg: string, organizationArg: string, countryCodeArg: string): q.Promise<{}>;
    /**
     * External: Create key pair
     * @param {number} bit - key strength, expected to be already sanitized
     * @param {string} c - country code, expected to be already sanitized
     * @param {string} o - organization, expected to be already sanitized
     * @param {string} cn - common name (domain name), expected to be already sanitized
     * @param {string} e - email address, expected to be already sanitized
     * @param {function} callback
     */
    createKeyPair(optionsArg: {
        keyBitSize: number;
        countryCode: string;
        organization: string;
        commonName: string;
        emailAddress: string;
    }): q.Promise<{}>;
    /**
     * Helper: Empty callback
     */
    emptyCallback(): void;
    /**
     * Helper: Make safe file name or path from string
     * @param {string} name
     * @param {boolean} withPath - optional, default false
     * @return {string}
     */
    makeSafeFileName(name: any, withPath?: boolean): any;
    /**
     * Helper: Prepare challenge
     * @param {string} domain
     * @param {Object} challenge
     * @param {function} callback
     */
    prepareChallenge(domain: any, challenge: any, callback: any): void;
    /**
     * Helper: Extract TOS Link, e.g. from "&lt;http://...&gt;;rel="terms-of-service"
     * @param {string} linkStr
     * @return {string}
     */
    getTosLink(linkStr: any): string;
    /**
     * Helper: Select challenge by type
     * @param {Object} ans
     * @param {string} challenge_type
     * @return {Object}
     */
    selectChallenge(ans: any, challengeType: string): any;
    /**
     * Helper: Extract first found email from profile (without mailto prefix)
     * @param {Object} profile
     * @return {string}
     */
    extractEmail(profile: any): string;
    /**
     * Make ACME-Request: Domain-Authorization Request - Object: resource, identifier
     * @param {string} domain
     * @return {{resource: string, identifier: Object}}
     */
    makeDomainAuthorizationRequest(domain: any): {
        'resource': string;
        'identifier': {
            'type': string;
            'value': any;
        };
    };
    /**
     * Make ACME-Object: Key-Authorization (encoded) - String: Challenge-Token . Encoded-Account-Key-Hash
     * @param {Object} challenge
     * @return {string}
     */
    makeKeyAuthorization(challenge: any): string;
    /**
     * Make ACME-Request: Challenge-Response - Object: resource, keyAuthorization
     * @param {Object} challenge
     * @return {{resource: string, keyAuthorization: string}}
     */
    makeChallengeResponse(challenge: any): {
        'resource': string;
        'keyAuthorization': string;
    };
    /**
     * Make ACME-Request: CSR - Object: resource, csr, notBefore, notAfter
     * @param {string} csr
     * @param {number} days_valid
     * @return {{resource: string, csr: string, notBefore: string, notAfter: string}}
     */
    makeCertRequest(csr: string, DAYS_VALID: number): {
        'resource': string;
        'csr': any;
        'notBefore': string;
        'notAfter': string;
    };
}
