"use strict";
const plugins = require("./smartacme.plugins");
const child_process = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const readline = require("readline");
const smartacme_classes_jwebclient_1 = require("./smartacme.classes.jwebclient");
/**
 * json_to_utf8buffer
 * @private
 * @description convert JSON to Buffer using UTF-8 encoding
 * @param {Object} obj
 * @return {Buffer}
 * @throws Exception if object cannot be stringified or contains cycle
 */
let json_to_utf8buffer = (obj) => {
    return new Buffer(JSON.stringify(obj), 'utf8');
};
/**
 * @class AcmeClient
 * @constructor
 * @description ACME protocol implementation from client perspective
 * @param {string} directory_url - Address of directory
 * @param {module:JWebClient~JWebClient} jWebClient - Reference to JSON-Web-Client
 */
class AcmeClient {
    constructor(directoryUrlArg) {
        /**
         * @member {Object} module:AcmeClient~AcmeClient#clientProfilePubKey
         * @desc Cached public key obtained from profile
         */
        this.clientProfilePubKey = {};
        /**
         * @member {number} module:AcmeClient~AcmeClient#days_valid
         * @desc Validity period in days
         * @default 1
         */
        this.days_valid = 1;
        /**
         * @member {number} module:AcmeClient~AcmeClient#defaultRsaKeySize
         * @desc Key strength in bits
         * @default 4096
         */
        this.defaultRsaKeySize = 4096;
        /**
         * @member {Object} module:AcmeClient~AcmeClient#directory
         * @desc Hash map of REST URIs
         */
        this.directory = {};
        /**
         * @member {string} module:AcmeClient~AcmeClient#directory_url
         * @desc Address of directory
         */
        this.directoryUrl = directoryUrlArg;
        /**
         * @member {string} module:AcmeClient~AcmeClient#emailDefaultPrefix
         * @desc Prefix of email address if constructed from domain name
         * @default "hostmaster"
         */
        this.emailDefaultPrefix = 'hostmaster'; // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#emailOverride
         * @desc Email address to use
         */
        this.emailOverride = null; // {string}
        /**
         * @member {module:JWebClient~JWebClient} module:AcmeClient~AcmeClient#jWebClient
         * @desc Reference to JSON-Web-Client
         */
        this.jWebClient = new smartacme_classes_jwebclient_1.JWebClient(); // {JWebClient}
        /**
         * @member {string} module:AcmeClient~AcmeClient#regLink
         * @desc Cached registration URI
         */
        this.regLink = null; // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#tosLink
         * @desc Cached terms of service URI
         */
        this.tosLink = null; // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#webroot
         * @desc Path to server web root (or path to store challenge data)
         * @default "."
         */
        this.webroot = '.'; // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#well_known_path
         * @desc Directory structure for challenge data
         * @default "/.well-known/acme-challenge/"
         */
        this.well_known_path = '/.well-known/acme-challenge/'; // {string}
        /**
         * @member {boolean} module:AcmeClient~AcmeClient#withInteraction
         * @desc Determines if interaction of user is required
         * @default true
         */
        this.withInteraction = true; // {boolean}
    }
    // *****************************************************************************
    // REQUEST-Section
    // *****************************************************************************
    /**
     * getDirectory
     * @description retrieve directory entries (directory url must be set prior to execution)
     * @param {function} callback - first argument will be the answer object
     */
    getDirectory(callback) {
        this.jWebClient.get(this.directoryUrl, callback, callback);
        // dereference
        callback = null;
    }
    /**
     * newRegistration
     * @description try to register (directory lookup must have occured prior to execution)
     * @param {Object} payload
     * @param {function} callback - first argument will be the answer object
     */
    newRegistration(payload, callback) {
        if (!(payload instanceof Object)) {
            payload = {}; // ensure payload is object
        }
        payload.resource = 'new-reg';
        this.jWebClient.post(this.directory['new-reg'], payload, callback, callback);
        // dereference
        callback = null;
        payload = null;
    }
    /**
     * getRegistration
     * @description get information about registration
     * @param {string} uri - will be exposed when trying to register
     * @param {Object} payload - update information
     * @param {function} callback - first argument will be the answer object
     */
    getRegistration(uri, payload, callback) {
        /*jshint -W069 */
        if (!(payload instanceof Object)) {
            payload = {}; // ensure payload is object
        }
        payload['resource'] = 'reg';
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.jWebClient.post(uri, payload, (ans, res) => {
            if (ans instanceof Object) {
                this.clientProfilePubKey = ans.key; // cache or reset returned public key
                if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                    let linkStr = res.headers['link'];
                    if (typeof linkStr === 'string') {
                        let tosLink = this.getTosLink(linkStr);
                        if (typeof tosLink === 'string') {
                            this.tosLink = tosLink; // cache TOS link
                        }
                        else {
                            this.tosLink = null; // reset TOS link
                        }
                    }
                    else {
                        this.tosLink = null; // reset TOS link
                    }
                }
                else {
                    this.tosLink = null; // reset TOS link
                }
                callback(ans, res);
            }
            else {
                callback(false);
            }
        });
        // dereference
        payload = null;
    }
    /**
     * authorizeDomain
     * @description authorize domain using challenge-response-method
     * @param {string} domain
     * @param {function} callback - first argument will be the answer object
     */
    authorizeDomain(domain, callback) {
        /*jshint -W069 */
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.getProfile((profile) => {
            if (!(profile instanceof Object)) {
                callback(false); // no profile returned
            }
            else {
                this.jWebClient.post(this.directory['new-authz'], this.makeDomainAuthorizationRequest(domain), (ans, res) => {
                    if ((res instanceof Object) && (res['statusCode'] === 403)) {
                        this.agreeTos(this.tosLink, (ans_, res_) => {
                            if ((res_ instanceof Object)
                                && (res_['statusCode'] >= 200)
                                && (res_['statusCode'] <= 400)) {
                                this.authorizeDomain(domain, callback); // try authorization again
                            }
                            else {
                                callback(false); // agreement failed
                            }
                        });
                    }
                    else {
                        if ((res instanceof Object)
                            && (res['headers'] instanceof Object)
                            && (typeof res.headers['location'] === 'string')
                            && (ans instanceof Object)) {
                            let poll_uri = res.headers['location']; // status URI for polling
                            let challenge = this.selectChallenge(ans, 'http-01'); // select simple http challenge
                            if (challenge instanceof Object) {
                                this.prepareChallenge(domain, challenge, () => {
                                    // reset
                                    ans = null;
                                    res = null;
                                    // accept challenge
                                    this.acceptChallenge(challenge, (ans, res) => {
                                        if ((res instanceof Object)
                                            && (res['statusCode'] < 400) // server confirms challenge acceptance
                                        ) {
                                            this.pollUntilValid(poll_uri, callback); // poll status until server states success
                                        }
                                        else {
                                            callback(false); // server did not confirm challenge acceptance
                                        }
                                    });
                                });
                            }
                            else {
                                callback(false); // desired challenge is not in list
                            }
                        }
                        else {
                            callback(false); // server did not respond with status URI
                        }
                    }
                });
            }
        });
    }
    /**
     * acceptChallenge
     * @description tell server which challenge will be accepted
     * @param {Object} challenge
     * @param {function} callback - first argument will be the answer object
     */
    acceptChallenge(challenge, callback) {
        /*jshint -W069 */
        if (!(challenge instanceof Object)) {
            challenge = {}; // ensure challenge is object
        }
        this.jWebClient.post(challenge['uri'], this.makeChallengeResponse(challenge), callback);
        // dereference
        callback = null;
        challenge = null;
    }
    /**
     * pollUntilValid
     * @description periodically (with exponential back-off) check status of challenge
     * @param {string} uri
     * @param {function} callback - first argument will be the answer object
     * @param {number} retry - factor of delay
     */
    pollUntilValid(uri, callback, retry = 1) {
        /*jshint -W069 */
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (retry > 128) {
            callback(false); // stop if retry value exceeds maximum
        }
        else {
            this.jWebClient.get(uri, (ans, res) => {
                if (!(ans instanceof Object)) {
                    callback(false); // invalid answer
                }
                else {
                    if (ans['status'] === 'pending') {
                        setTimeout(() => {
                            this.pollUntilValid(uri, callback, retry * 2); // retry
                        }, retry * 500);
                    }
                    else {
                        callback(ans, res); // challenge complete
                    }
                }
            });
        }
    }
    /**
     * pollUntilIssued
     * @description periodically (with exponential back-off) check status of CSR
     * @param {string} uri
     * @param {function} callback - first argument will be the answer object
     * @param {number} retry - factor of delay
     */
    pollUntilIssued(uri, callback, retry = 1) {
        /*jshint -W069 */
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (retry > 128) {
            callback(false); // stop if retry value exceeds maximum
        }
        else {
            this.jWebClient.get(uri, (ans, res) => {
                if ((ans instanceof Buffer) && (ans.length > 0)) {
                    callback(ans); // certificate was returned with answer
                }
                else {
                    if ((res instanceof Object) && (res['statusCode'] < 400)) {
                        setTimeout(() => {
                            this.pollUntilIssued(uri, callback, retry * 2); // retry
                        }, retry * 500);
                    }
                    else {
                        callback(false); // CSR complete
                    }
                }
            });
        }
    }
    /**
     * requestSigning
     * @description send CSR
     * @param {string} domain - expected to be already sanitized
     * @param {function} callback - first argument will be the answer object
     */
    requestSigning(domain, callback) {
        /*jshint -W069 */
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        fs.readFile(domain + '.csr', (err, csrBuffer) => {
            if (err instanceof Object) {
                if (this.jWebClient.verbose) {
                    console.error('Error  : File system error', err['code'], 'while reading key from file');
                }
                callback(false);
            }
            else {
                let csr = csrBuffer.toString();
                this.jWebClient.post(this.directory['new-cert'], this.makeCertRequest(csr, this.days_valid), (ans, res) => {
                    if ((ans instanceof Buffer) && (ans.length > 0)) {
                        callback(ans); // certificate was returned with answer
                    }
                    else {
                        if (res instanceof Object) {
                            if ((res['statusCode'] < 400) && !ans) {
                                let headers = res['headers'];
                                if (!(headers instanceof Object)) {
                                    headers = {}; // ensure headers is object
                                }
                                this.pollUntilIssued(headers['location'], callback); // poll provided status URI
                                // dereference
                                headers = null;
                            }
                            else {
                                callback((res['statusCode'] < 400) ? ans : false); // answer may be provided as string or object
                            }
                        }
                        else {
                            callback(false); // invalid response
                        }
                    }
                });
            }
        });
    }
    /**
     * getProfile
     * @description retrieve profile of user (will make directory lookup and registration check)
     * @param {function} callback - first argument will be the answer object
     */
    getProfile(callback) {
        /*jshint -W069 */
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.getDirectory((dir) => {
            if (!(dir instanceof Object)) {
                callback(false); // server did not respond with directory
            }
            else {
                this.directory = dir; // cache directory
                this.newRegistration(null, (ans, res) => {
                    if ((res instanceof Object)
                        && (res['headers'] instanceof Object)
                        && (typeof res.headers['location'] === 'string')) {
                        this.regLink = res.headers['location'];
                        this.getRegistration(this.regLink, null, callback); // get registration info from link
                    }
                    else {
                        callback(false); // registration failed
                    }
                });
            }
        });
    }
    /**
     * createAccount
     * @description create new account (assumes directory lookup has already occured)
     * @param {string} email
     * @param {function} callback - first argument will be the registration URI
     */
    createAccount(email, callback) {
        /*jshint -W069 */
        if (typeof email === 'string') {
            if (typeof callback !== 'function') {
                callback = this.emptyCallback; // ensure callback is function
            }
            this.newRegistration({
                contact: [
                    'mailto:' + email
                ]
            }, (ans, res) => {
                if ((res instanceof Object)
                    && (res['statusCode'] === 201)
                    && (res['headers'] instanceof Object)
                    && (typeof res.headers['location'] === 'string')) {
                    this.regLink = res.headers['location'];
                    callback(this.regLink); // registration URI
                }
                else {
                    callback(false); // registration failed
                }
            });
        }
        else {
            callback(false); // no email address provided
        }
    }
    /**
     * agreeTos
     * @description agree with terms of service (update agreement status in profile)
     * @param {string} tosLink
     * @param {function} callback - first argument will be the answer object
     */
    agreeTos(tosLink, callback) {
        this.getRegistration(this.regLink, {
            'Agreement': tosLink // terms of service URI
        }, callback);
        // dereference
        callback = null;
    }
    /**
     * Entry-Point: Request certificate
     * @param {string} domain
     * @param {string} organization
     * @param {string} country
     * @param {function} callback
     */
    requestCertificate(domain, organization, country, callback) {
        /*jshint -W069 */
        if (typeof domain !== 'string') {
            domain = ''; // ensure domain is string
        }
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.getProfile((profile) => {
            let email = this.extractEmail(profile); // try to determine email address from profile
            if (typeof this.emailOverride === 'string') {
                email = this.emailOverride; // override email address if set
            }
            else if (typeof email !== 'string') {
                email = this.emailDefaultPrefix + '@' + domain; // or set default
            }
            let bit = this.defaultRsaKeySize;
            // sanitize
            bit = Number(bit);
            country = this.makeSafeFileName(country);
            domain = this.makeSafeFileName(domain);
            email = this.makeSafeFileName(email);
            organization = this.makeSafeFileName(organization);
            // create key pair
            this.createKeyPair(bit, country, organization, domain, email, (e) => {
                if (!e) {
                    this.requestSigning(domain, (cert) => {
                        if ((cert instanceof Buffer) || (typeof cert === 'string')) {
                            fs.writeFile(domain + '.der', cert, (err) => {
                                if (err instanceof Object) {
                                    if (this.jWebClient.verbose) {
                                        console.error('Error  : File system error', err['code'], 'while writing certificate to file');
                                    }
                                    callback(false);
                                }
                                else {
                                    callback(true); // CSR complete and certificate written to file system
                                }
                            });
                        }
                        else {
                            callback(false); // invalid certificate data
                        }
                    });
                }
                else {
                    callback(false); // could not create key pair
                }
            });
        });
    }
    /**
     * External: Create key pair
     * @param {number} bit - key strength, expected to be already sanitized
     * @param {string} c - country code, expected to be already sanitized
     * @param {string} o - organization, expected to be already sanitized
     * @param {string} cn - common name (domain name), expected to be already sanitized
     * @param {string} e - email address, expected to be already sanitized
     * @param {function} callback
     */
    createKeyPair(bit, c, o, cn, e, callback) {
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        let openssl = `openssl req -new -nodes -newkey rsa:${bit} -sha256 -subj "/C=${c}/O=${o}/CN=${cn}/emailAddress=${e}" -keyout \"${cn}.key\" -outform der -out \"${cn}.csr\"`;
        console.error('Action : Creating key pair');
        if (this.jWebClient.verbose) {
            console.error('Running:', openssl);
        }
        child_process.exec(openssl, (e) => {
            if (!e) {
                console.error('Result : done');
            }
            else {
                console.error('Result : failed');
            }
            callback(e);
            // dereference
            callback = null;
            e = null;
        });
    }
    /**
     * Helper: Empty callback
     */
    emptyCallback() {
        // nop
    }
    /**
     * Helper: Make safe file name or path from string
     * @param {string} name
     * @param {boolean} withPath - optional, default false
     * @return {string}
     */
    makeSafeFileName(name, withPath = false) {
        if (typeof name !== 'string') {
            name = '';
        }
        // respects file name restrictions for ntfs and ext2
        let regex_file = '[<>:\"/\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]';
        let regex_path = '[<>:\"\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]';
        return name.replace(new RegExp(withPath ? regex_path : regex_file, 'g'), (charToReplace) => {
            if (typeof charToReplace === 'string') {
                return '%' + charToReplace.charCodeAt(0).toString(16).toLocaleUpperCase();
            }
            return '%00';
        });
    }
    /**
     * Helper: Prepare challenge
     * @param {string} domain
     * @param {Object} challenge
     * @param {function} callback
     */
    prepareChallenge(domain, challenge, callback) {
        /*jshint -W069, unused:false*/
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (challenge instanceof Object) {
            if (challenge['type'] === 'http-01') {
                let path = this.webroot + this.well_known_path + challenge['token']; // webroot and well_known_path are expected to be already sanitized
                fs.writeFile(path, this.makeKeyAuthorization(challenge), (err) => {
                    if (err instanceof Object) {
                        if (this.jWebClient.verbose) {
                            console.error('Error  : File system error', err['code'], 'while writing challenge data to file');
                        }
                        callback();
                    }
                    else {
                        // let uri = "http://" + domain + this.well_known_path + challenge["token"]
                        let rl = readline.createInterface(process.stdin, process.stdout);
                        if (this.withInteraction) {
                            rl.question('Press enter to proceed', (answer) => {
                                rl.close();
                                callback();
                            });
                        }
                        else {
                            rl.close();
                            callback(); // skip interaction prompt if desired
                        }
                    }
                });
            }
            else {
                console.error('Error  : Challenge not supported');
                callback();
            }
        }
        else {
            console.error('Error  : Invalid challenge response');
            callback();
        }
    }
    /**
     * Helper: Extract TOS Link, e.g. from "&lt;http://...&gt;;rel="terms-of-service"
     * @param {string} linkStr
     * @return {string}
     */
    getTosLink(linkStr) {
        let match = /(<)([^>]+)(>;rel="terms-of-service")/g.exec(linkStr);
        if ((match instanceof Array) && (match.length > 2)) {
            let result = match[2];
            // dereference
            match = null;
            return result;
        }
    }
    /**
     * Helper: Select challenge by type
     * @param {Object} ans
     * @param {string} challenge_type
     * @return {Object}
     */
    selectChallenge(ans, challengeType) {
        /*jshint -W069 */
        if ((ans instanceof Object) && (ans['challenges'] instanceof Array)) {
            return ans.challenges.filter((entry) => {
                let type = entry['type'];
                // dereference
                entry = null;
                if (type === challengeType) {
                    return true;
                }
                return false;
            }).pop();
        } // return first match or undefined
        // dereference
        ans = null;
        return void 0; // challenges not available or in expected format
    }
    /**
     * Helper: Extract first found email from profile (without mailto prefix)
     * @param {Object} profile
     * @return {string}
     */
    extractEmail(profile) {
        /*jshint -W069 */
        if (!(profile instanceof Object) || !(profile['contact'] instanceof Array)) {
            // dereference
            profile = null;
            return void 0; // invalid profile
        }
        let prefix = 'mailto:';
        let email = profile.contact.filter((entry) => {
            if (typeof entry !== 'string') {
                return false;
            }
            else {
                return !entry.indexOf(prefix); // check for mail prefix
            }
        }).pop();
        // dereference
        profile = null;
        if (typeof email !== 'string') {
            return void 0;
        } // return default
        return email.substr(prefix.length); // only return email address without protocol prefix
    }
    /**
     * Make ACME-Request: Domain-Authorization Request - Object: resource, identifier
     * @param {string} domain
     * @return {{resource: string, identifier: Object}}
     */
    makeDomainAuthorizationRequest(domain) {
        return {
            'resource': 'new-authz',
            'identifier': {
                'type': 'dns',
                'value': domain
            }
        };
    }
    /**
     * Make ACME-Object: Key-Authorization (encoded) - String: Challenge-Token . Encoded-Account-Key-Hash
     * @param {Object} challenge
     * @return {string}
     */
    makeKeyAuthorization(challenge) {
        /*jshint -W069 */
        if (challenge instanceof Object) {
            if (this.clientProfilePubKey instanceof Object) {
                let jwk = json_to_utf8buffer({
                    e: this.clientProfilePubKey['e'],
                    kty: this.clientProfilePubKey['kty'],
                    n: this.clientProfilePubKey['n']
                });
                let hash = crypto.createHash('sha256').update(jwk.toString('utf8'), 'utf8').digest();
                // create base64 encoded hash of account key
                let ACCOUNT_KEY = plugins.smartstring.base64.encodeUri(hash.toString());
                let token = challenge['token'];
                return token + '.' + ACCOUNT_KEY;
            }
        }
        else {
            return ''; // return default (for writing to file)
        }
    }
    /**
     * Make ACME-Request: Challenge-Response - Object: resource, keyAuthorization
     * @param {Object} challenge
     * @return {{resource: string, keyAuthorization: string}}
     */
    makeChallengeResponse(challenge) {
        return {
            'resource': 'challenge',
            'keyAuthorization': this.makeKeyAuthorization(challenge)
        };
    }
    /**
     * Make ACME-Request: CSR - Object: resource, csr, notBefore, notAfter
     * @param {string} csr
     * @param {number} days_valid
     * @return {{resource: string, csr: string, notBefore: string, notAfter: string}}
     */
    makeCertRequest(csr, DAYS_VALID) {
        if (typeof csr !== 'string' && !(csr instanceof Buffer)) {
            csr = ''; // default string for CSR
        }
        if ((typeof DAYS_VALID !== 'number') || (isNaN(DAYS_VALID)) || (DAYS_VALID === 0)) {
            DAYS_VALID = 1; // default validity duration (1 day)
        }
        let DOMAIN_CSR_DER = plugins.smartstring.base64.encodeUri(csr); // create base64 encoded CSR
        let CURRENT_DATE = (new Date()).toISOString(); // set start date to current date
        // set end date to current date + days_valid
        let NOTAFTER_DATE = (new Date((+new Date()) + 1000 * 60 * 60 * 24 * Math.abs(DAYS_VALID))).toISOString();
        return {
            'resource': 'new-cert',
            'csr': DOMAIN_CSR_DER,
            'notBefore': CURRENT_DATE,
            'notAfter': NOTAFTER_DATE
        };
    }
}
exports.AcmeClient = AcmeClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmFjbWVjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLCtDQUE4QztBQUM5QywrQ0FBOEM7QUFDOUMsaUNBQWdDO0FBQ2hDLHlCQUF3QjtBQUN4QixxQ0FBb0M7QUFDcEMsaUZBQTJEO0FBRTNEOzs7Ozs7O0dBT0c7QUFDSCxJQUFJLGtCQUFrQixHQUFHLENBQUMsR0FBRztJQUN6QixNQUFNLENBQUMsSUFBSSxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUNsRCxDQUFDLENBQUE7QUFFRDs7Ozs7O0dBTUc7QUFDSDtJQWNJLFlBQVksZUFBZTtRQUN2Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsbUJBQW1CLEdBQUcsRUFBRSxDQUFBO1FBQzdCOzs7O1dBSUc7UUFDSCxJQUFJLENBQUMsVUFBVSxHQUFHLENBQUMsQ0FBQTtRQUNuQjs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLGlCQUFpQixHQUFHLElBQUksQ0FBQTtRQUM3Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsU0FBUyxHQUFHLEVBQUUsQ0FBQTtRQUNuQjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsWUFBWSxHQUFHLGVBQWUsQ0FBQTtRQUNuQzs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQSxDQUFDLFdBQVc7UUFDbEQ7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLGFBQWEsR0FBRyxJQUFJLENBQUEsQ0FBQyxXQUFXO1FBQ3JDOzs7V0FHRztRQUNILElBQUksQ0FBQyxVQUFVLEdBQUcsSUFBSSx5Q0FBVSxFQUFFLENBQUEsQ0FBQyxlQUFlO1FBQ2xEOzs7V0FHRztRQUNILElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxDQUFBLENBQUMsV0FBVztRQUMv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