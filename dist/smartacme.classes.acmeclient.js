"use strict";
const plugins = require("./smartacme.plugins");
const q = require("q");
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
        this.daysValid = 1;
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
        this.wellKnownPath = '/.well-known/acme-challenge/'; // {string}
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
    getDirectory() {
        let done = q.defer();
        this.jWebClient.get(this.directoryUrl)
            .then((reqResArg) => {
            done.resolve(reqResArg);
        });
        return done.promise;
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
    getRegistration(uri, payload) {
        let done = q.defer();
        payload['resource'] = 'reg';
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
                done.resolve({ ans: ans, res: res });
            }
            else {
                done.reject(new Error('some error'));
            }
        });
        return done.promise;
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
        this.getProfile()
            .then(profile => {
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
                this.jWebClient.post(this.directory['new-cert'], this.makeCertRequest(csr, this.daysValid), (ans, res) => {
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
     * retrieves profile of user (will make directory lookup and registration check)
     * @param {function} callback - first argument will be the answer object
     */
    getProfile() {
        let done = q.defer();
        this.getDirectory()
            .then((dir) => {
            if (!(dir instanceof Object)) {
                done.reject(new Error('server did not respond with directory'));
            }
            else {
                this.directory = dir; // cache directory
                this.newRegistration(null, (ans, res) => {
                    if ((res instanceof Object)
                        && (res['headers'] instanceof Object)
                        && (typeof res.headers['location'] === 'string')) {
                        this.regLink = res.headers['location'];
                        this.getRegistration(this.regLink, null)
                            .then((reqResArg) => {
                            done.resolve();
                        }); // get registration info from link
                    }
                    else {
                        done.reject(new Error('registration failed'));
                    }
                });
            }
        });
        return done.promise;
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
        let done = q.defer();
        this.getRegistration(this.regLink, {
            'Agreement': tosLink // terms of service URI
        }).then(() => { done.resolve(); });
    }
    /**
     * Entry-Point: Request certificate
     * @param {string} domain
     * @param {string} organization
     * @param {string} country
     * @param {function} callback
     * @returns Promise
     */
    requestCertificate(domain, organization, country) {
        let done = q.defer();
        this.getProfile()
            .then((profile) => {
            let email = this.extractEmail(profile); // try to determine email address from profile
            let bit = this.defaultRsaKeySize;
            // sanitize
            bit = Number(bit);
            country = this.makeSafeFileName(country);
            domain = this.makeSafeFileName(domain);
            email = this.makeSafeFileName(email);
            organization = this.makeSafeFileName(organization);
            // create key pair
            this.createKeyPair(bit, country, organization, domain, email)
                .then(() => {
                this.requestSigning(domain, (cert) => {
                    if ((cert instanceof Buffer) || (typeof cert === 'string')) {
                        fs.writeFile(domain + '.der', cert, (err) => {
                            if (err instanceof Object) {
                                if (this.jWebClient.verbose) {
                                    console.error('Error  : File system error', err['code'], 'while writing certificate to file');
                                }
                                done.reject(err);
                            }
                            else {
                                done.resolve(); // CSR complete and certificate written to file system
                            }
                        });
                    }
                    else {
                        done.reject('invalid certificate data');
                    }
                });
            });
        });
        return done.promise;
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
    createKeyPair(bit, c, o, cn, e) {
        let done = q.defer();
        let openssl = `openssl req -new -nodes -newkey rsa:${bit} -sha256 -subj "/C=${c}/O=${o}/CN=${cn}/emailAddress=${e}" -keyout \"${cn}.key\" -outform der -out \"${cn}.csr\"`;
        console.error('Action : Creating key pair');
        if (this.jWebClient.verbose) {
            console.error('Running:', openssl);
        }
        plugins.shelljs.exec(openssl, (codeArg, stdOutArg, stdErrorArg) => {
            if (!stdErrorArg) {
                done.resolve();
            }
            else {
                done.reject(stdErrorArg);
            }
        });
        return done.promise;
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
        let regexFile = '[<>:\"/\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]';
        let regexPath = '[<>:\"\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]';
        return name.replace(new RegExp(withPath ? regexPath : regexFile, 'g'), (charToReplace) => {
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
                let path = this.webroot + this.wellKnownPath + challenge['token']; // webroot and well_known_path are expected to be already sanitized
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmFjbWVjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLCtDQUE4QztBQUM5Qyx1QkFBc0I7QUFFdEIsaUNBQWdDO0FBQ2hDLHlCQUF3QjtBQUN4QixxQ0FBb0M7QUFDcEMsaUZBQTJEO0FBRzNEOzs7Ozs7O0dBT0c7QUFDSCxJQUFJLGtCQUFrQixHQUFHLENBQUMsR0FBRztJQUN6QixNQUFNLENBQUMsSUFBSSxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUNsRCxDQUFDLENBQUE7QUFFRDs7Ozs7O0dBTUc7QUFDSDtJQWNJLFlBQVksZUFBZTtRQUN2Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsbUJBQW1CLEdBQUcsRUFBRSxDQUFBO1FBQzdCOzs7O1dBSUc7UUFDSCxJQUFJLENBQUMsU0FBUyxHQUFHLENBQUMsQ0FBQTtRQUNsQjs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLGlCQUFpQixHQUFHLElBQUksQ0FBQTtRQUM3Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsU0FBUyxHQUFHLEVBQUUsQ0FBQTtRQUNuQjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsWUFBWSxHQUFHLGVBQWUsQ0FBQTtRQUNuQzs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQSxDQUFDLFdBQVc7UUFDbEQ7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLGFBQWEsR0FBRyxJQUFJLENBQUEsQ0FBQyxXQUFXO1FBQ3JDOzs7V0FHRztRQUNILElBQUksQ0FBQyxVQUFVLEdBQUcsSUFBSSx5Q0FBVSxFQUFFLENBQUEsQ0FBQyxlQUFlO1FBQ2xEOzs7V0FHRztRQUNILElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxDQUFBLENBQUMsV0FBVztRQUMv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