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
        this.jWebClient = new smartacme_classes_jwebclient_1.JWebClient();
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
    newRegistration(payload) {
        let done = q.defer();
        if (!(payload instanceof Object)) {
            payload = {}; // ensure payload is object
        }
        payload.resource = 'new-reg';
        this.jWebClient.post(this.directory['new-reg'], payload);
        return done.promise;
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
        this.jWebClient.post(uri, payload)
            .then((reqResArg) => {
            if (reqResArg.ans instanceof Object) {
                this.clientProfilePubKey = reqResArg.ans.key; // cache or reset returned public key
                if ((reqResArg.res instanceof Object) && (reqResArg.res['headers'] instanceof Object)) {
                    let linkStr = reqResArg.res.headers['link'];
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
                done.resolve({ ans: reqResArg.ans, res: reqResArg.res });
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
    authorizeDomain(domain) {
        let done = q.defer();
        this.getProfile()
            .then(profile => {
            if (!(profile instanceof Object)) {
                done.reject(new Error('no profile returned'));
            }
            else {
                this.jWebClient.post(this.directory['new-authz'], this.makeDomainAuthorizationRequest(domain))
                    .then((reqResArg) => {
                    if ((reqResArg.res instanceof Object) && (reqResArg.res['statusCode'] === 403)) {
                        this.agreeTos(this.tosLink)
                            .then((reqResArg2) => {
                            if ((reqResArg.res instanceof Object)
                                && (reqResArg2.res['statusCode'] >= 200)
                                && (reqResArg2.res['statusCode'] <= 400)) {
                                this.authorizeDomain(domain).then(() => {
                                    done.resolve();
                                }); // try authorization again
                            }
                            else {
                                done.reject(false); // agreement failed
                            }
                        });
                    }
                    else {
                        if ((reqResArg.res instanceof Object)
                            && (reqResArg.res['headers'] instanceof Object)
                            && (typeof reqResArg.res.headers['location'] === 'string')
                            && (reqResArg.ans instanceof Object)) {
                            let poll_uri = reqResArg.res.headers['location']; // status URI for polling
                            let challenge = this.selectChallenge(reqResArg.ans, 'http-01'); // select simple http challenge
                            if (challenge instanceof Object) {
                                this.prepareChallenge(domain, challenge, () => {
                                    // reset
                                    reqResArg.ans = null;
                                    reqResArg.res = null;
                                    // accept challenge
                                    this.acceptChallenge(challenge)
                                        .then((reqResArg2) => {
                                        if ((reqResArg2.res instanceof Object)
                                            && (reqResArg2.res['statusCode'] < 400) // server confirms challenge acceptance
                                        ) {
                                            this.pollUntilValid(poll_uri)
                                                .then(() => {
                                                done.resolve();
                                            }); // poll status until server states success
                                        }
                                        else {
                                            done.reject(false); // server did not confirm challenge acceptance
                                        }
                                    });
                                });
                            }
                            else {
                                done.reject(false); // desired challenge is not in list
                            }
                        }
                        else {
                            done.reject(false); // server did not respond with status URI
                        }
                    }
                });
            }
        });
        return done.promise;
    }
    /**
     * acceptChallenge
     * @description tell server which challenge will be accepted
     * @param {Object} challenge
     * @param {function} callback - first argument will be the answer object
     */
    acceptChallenge(challenge = {}) {
        let done = q.defer();
        this.jWebClient.post(challenge['uri'], this.makeChallengeResponse(challenge))
            .then(() => {
            done.resolve();
        });
        return done.promise;
    }
    /**
     * pollUntilValid
     * @description periodically (with exponential back-off) check status of challenge
     * @param {string} uri
     * @param {function} callback - first argument will be the answer object
     * @param {number} retry - factor of delay
     */
    pollUntilValid(uri, retry = 1) {
        let done = q.defer();
        if (retry > 128) {
            done.reject(false); // stop if retry value exceeds maximum
        }
        else {
            this.jWebClient.get(uri)
                .then((reqResArg) => {
                if (!(reqResArg.ans instanceof Object)) {
                    done.reject(false); // invalid answer
                }
                else {
                    if (reqResArg.ans['status'] === 'pending') {
                        setTimeout(() => {
                            this.pollUntilValid(uri, retry * 2); // retry
                        }, retry * 500);
                    }
                    else {
                        done.resolve(); // challenge complete
                    }
                }
            });
        }
        return done.promise;
    }
    /**
     * pollUntilIssued
     * @description periodically (with exponential back-off) check status of CSR
     * @param {string} uri
     * @param {function} callback - first argument will be the answer object
     * @param {number} retry - factor of delay
     */
    pollUntilIssued(uri, retry = 1) {
        let done = q.defer();
        if (retry > 128) {
            done.reject(false); // stop if retry value exceeds maximum
        }
        else {
            this.jWebClient.get(uri)
                .then((reqResArg) => {
                if ((reqResArg.ans instanceof Buffer) && (reqResArg.ans.length > 0)) {
                    done.resolve(reqResArg.ans); // certificate was returned with answer
                }
                else {
                    if ((reqResArg.res instanceof Object) && (reqResArg.res['statusCode'] < 400)) {
                        setTimeout(() => {
                            this.pollUntilIssued(uri, retry * 2); // retry
                        }, retry * 500);
                    }
                    else {
                        done.reject(false); // CSR complete
                    }
                }
            });
        }
        return done.promise;
    }
    /**
     * requestSigning
     * @description send CSR
     * @param {string} domain - expected to be already sanitized
     * @param {function} callback - first argument will be the answer object
     */
    requestSigning(commonName) {
        let done = q.defer();
        fs.readFile(commonName + '.csr', (err, csrBuffer) => {
            if (err instanceof Object) {
                if (this.jWebClient.verbose) {
                    console.error('Error  : File system error', err['code'], 'while reading key from file');
                }
                done.reject(false);
            }
            else {
                let csr = csrBuffer.toString();
                this.jWebClient.post(this.directory['new-cert'], this.makeCertRequest(csr, this.daysValid))
                    .then((reqResArg) => {
                    if ((reqResArg.ans instanceof Buffer) && (reqResArg.ans.length > 0)) {
                        done.resolve(reqResArg.ans); // certificate was returned with answer
                    }
                    else {
                        if (reqResArg.res instanceof Object) {
                            if ((reqResArg.res['statusCode'] < 400) && !reqResArg.ans) {
                                let headers = reqResArg['headers'];
                                if (!(headers instanceof Object)) {
                                    headers = {}; // ensure headers is object
                                }
                                this.pollUntilIssued(headers['location'])
                                    .then(x => { done.resolve(x); });
                            }
                            else {
                                done.resolve((reqResArg.res['statusCode'] < 400) ? reqResArg.ans : false); // answer may be provided as string or object
                            }
                        }
                        else {
                            done.reject(false); // invalid response
                        }
                    }
                });
            }
        });
        return done.promise;
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
                this.newRegistration(null)
                    .then((reqResArg) => {
                    if ((reqResArg.res instanceof Object)
                        && (reqResArg.res['headers'] instanceof Object)
                        && (typeof reqResArg.res.headers['location'] === 'string')) {
                        this.regLink = reqResArg.res.headers['location'];
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
    createAccount(email) {
        let done = q.defer();
        if (typeof email === 'string') {
            this.newRegistration({
                contact: [
                    'mailto:' + email
                ]
            })
                .then((reqResArg) => {
                if ((reqResArg.res instanceof Object)
                    && (reqResArg.res['statusCode'] === 201)
                    && (reqResArg.res['headers'] instanceof Object)
                    && (typeof reqResArg.res.headers['location'] === 'string')) {
                    this.regLink = reqResArg.res.headers['location'];
                    done.resolve(this.regLink); // registration URI
                }
                else {
                    done.reject(new Error('could not register new account')); // registration failed
                }
            });
        }
        else {
            done.reject(new Error('no email address provided'));
        }
        return done.promise;
    }
    /**
     * agreeTos
     * @description agree with terms of service (update agreement status in profile)
     * @param {string} tosLink
     * @param {function} callback - first argument will be the answer object
     */
    agreeTos(tosLink) {
        let done = q.defer();
        this.getRegistration(this.regLink, {
            'Agreement': tosLink // terms of service URI
        }).then(() => {
            done.resolve();
        });
        return done.promise;
    }
    /**
     * Entry-Point: Request certificate
     */
    requestCertificate(domainArg, organizationArg, countryCodeArg) {
        let done = q.defer();
        this.getProfile()
            .then((profile) => {
            let email = this.extractEmail(profile); // try to determine email address from profile
            countryCodeArg = this.makeSafeFileName(countryCodeArg);
            domainArg = this.makeSafeFileName(domainArg);
            email = this.makeSafeFileName(email);
            organizationArg = this.makeSafeFileName(organizationArg);
            // create key pair
            this.createKeyPair({
                keyBitSize: 4096,
                countryCode: countryCodeArg,
                organization: organizationArg,
                commonName: domainArg,
                emailAddress: email
            })
                .then(() => {
                this.requestSigning(domainArg)
                    .then((cert) => {
                    if ((cert instanceof Buffer) || (typeof cert === 'string')) {
                        fs.writeFile(domainArg + '.der', cert, (err) => {
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
    createKeyPair(optionsArg) {
        let done = q.defer();
        let openssl = `openssl req -new -nodes -newkey rsa:${optionsArg.keyBitSize} `
            + `-sha256 `
            + `-subj "/C=${optionsArg.countryCode}/O=${optionsArg.organization}/CN=${optionsArg.commonName}/emailAddress=${optionsArg.emailAddress}" `
            + `-keyout \"${optionsArg.commonName}.key\" -outform der -out \"${optionsArg.commonName}.csr\"`;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmFjbWVjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLCtDQUE4QztBQUM5Qyx1QkFBc0I7QUFDdEIsaUNBQWdDO0FBQ2hDLHlCQUF3QjtBQUN4QixxQ0FBb0M7QUFDcEMsaUZBQTJEO0FBRzNEOzs7Ozs7O0dBT0c7QUFDSCxJQUFJLGtCQUFrQixHQUFHLENBQUMsR0FBRztJQUN6QixNQUFNLENBQUMsSUFBSSxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUNsRCxDQUFDLENBQUE7QUFFRDs7Ozs7O0dBTUc7QUFDSDtJQWFJLFlBQVksZUFBZTtRQU4zQixlQUFVLEdBQUcsSUFBSSx5Q0FBVSxFQUFFLENBQUE7UUFPekI7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLG1CQUFtQixHQUFHLEVBQUUsQ0FBQTtRQUM3Qjs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLFNBQVMsR0FBRyxDQUFDLENBQUE7UUFFbEI7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLFNBQVMsR0FBRyxFQUFFLENBQUE7UUFDbkI7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLFlBQVksR0FBRyxlQUFlLENBQUE7UUFDbkM7Ozs7V0FJRztRQUNILElBQUksQ0FBQyxrQkFBa0IsR0FBRyxZQUFZLENBQUEsQ0FBQyxXQUFXO1FBQ2xEOzs7V0FHRztRQUNILElBQUksQ0FBQyxhQUFhLEdBQUcsSUFBSSxDQUFBLENBQUMsV0FBVztRQUNyQzs7O1dBR0c7UUFDSCxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQSxDQUFDLFdBQVc7UUFDL0I7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLENBQUEsQ0FBQyxXQUFXO1FBQy9COzs7O1dBSUc7UUFDSCxJQUFJLENBQUMsT0FBTyxHQUFHLEdBQUcsQ0FBQSxDQUFDLFdBQVc7UUFDOUI7Ozs7V0FJRztRQUNILElBQUksQ0FBQyxhQUFhLEdBQUcsOEJBQThCLENBQUEsQ0FBQyxXQUFXO1FBQy9EOzs7O1dBSUc7UUFDSCxJQUFJLENBQUMsZUFBZSxHQUFHLElBQUksQ0FBQSxDQUFDLFlBQVk7SUFDNUMsQ0FBQztJQUVELGdGQUFnRjtJQUNoRixrQkFBa0I7SUFDbEIsZ0ZBQWdGO0lBRWhGOzs7O09BSUc7SUFDSCxZQUFZO1FBQ1IsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBYyxDQUFBO1FBQ2hDLElBQUksQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxZQUFZLENBQUM7YUFDakMsSUFBSSxDQUFDLENBQUMsU0FBcUI7WUFDeEIsSUFBSSxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQTtRQUMzQixDQUFDLENBQUMsQ0FBQTtRQUNOLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNILGVBQWUsQ0FBQyxPQUFPO1FBQ25CLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUMvQixPQUFPLEdBQUcsRUFBRSxDQUFBLENBQUMsMkJBQTJCO1FBQzVDLENBQUM7UUFDRCxPQUFPLENBQUMsUUFBUSxHQUFHLFNBQVMsQ0FBQTtRQUM1QixJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQyxFQUFFLE9BQU8sQ0FBQyxDQUFBO1FBQ3hELE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7Ozs7O09BTUc7SUFDSCxlQUFlLENBQUMsR0FBRyxFQUFFLE9BQU87UUFDeEIsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBYyxDQUFBO1FBQ2hDLE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxLQUFLLENBQUE7UUFDM0IsSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFLE9BQU8sQ0FBQzthQUM3QixJQUFJLENBQUMsQ0FBQyxTQUFxQjtZQUN4QixFQUFFLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUM7Z0JBQ2xDLElBQUksQ0FBQyxtQkFBbUIsR0FBRyxTQUFTLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQSxDQUFDLHFDQUFxQztnQkFDbEYsRUFBRSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsWUFBWSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7b0JBQ3BGLElBQUksT0FBTyxHQUFHLFNBQVMsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFBO29CQUMzQyxFQUFFLENBQUMsQ0FBQyxPQUFPLE9BQU8sS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDO3dCQUM5QixJQUFJLE9BQU8sR0FBRyxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFBO3dCQUN0QyxFQUFFLENBQUMsQ0FBQyxPQUFPLE9BQU8sS0FBSyxRQUFRLENBQUMsQ0FBQyxDQUFDOzRCQUM5QixJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQSxDQUFDLGlCQUFpQjt3QkFDNUMsQ0FBQzt3QkFBQyxJQUFJLENBQUMsQ0FBQzs0QkFDSixJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQSxDQUFDLGlCQUFpQjt3QkFDekMsQ0FBQztvQkFDTCxDQUFDO29CQUFDLElBQUksQ0FBQyxDQUFDO3dCQUNKLElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxDQUFBLENBQUMsaUJBQWlCO29CQUN6QyxDQUFDO2dCQUNMLENBQUM7Z0JBQUMsSUFBSSxDQUFDLENBQUM7b0JBQ0osSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLENBQUEsQ0FBQyxpQkFBaUI7Z0JBQ3pDLENBQUM7Z0JBQ0QsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLEdBQUcsRUFBRSxTQUFTLENBQUMsR0FBRyxFQUFFLEdBQUcsRUFBRSxTQUFTLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQTtZQUM1RCxDQUFDO1lBQUMsSUFBSSxDQUFDLENBQUM7Z0JBQ0osSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxZQUFZLENBQUMsQ0FBQyxDQUFBO1lBQ3hDLENBQUM7UUFDTCxDQUFDLENBQUMsQ0FBQTtRQUNOLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNILGVBQWUsQ0FBQyxNQUFNO1FBQ2xCLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLENBQUMsVUFBVSxFQUFFO2FBQ1osSUFBSSxDQUFDLE9BQU87WUFDVCxFQUFFLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztnQkFDL0IsSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxxQkFBcUIsQ0FBQyxDQUFDLENBQUE7WUFDakQsQ0FBQztZQUFDLElBQUksQ0FBQyxDQUFDO2dCQUNKLElBQUksQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsV0FBVyxDQUFDLEVBQUUsSUFBSSxDQUFDLDhCQUE4QixDQUFDLE1BQU0sQ0FBQyxDQUFDO3FCQUN6RixJQUFJLENBQUMsQ0FBQyxTQUFxQjtvQkFDeEIsRUFBRSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsS0FBSyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7d0JBQzdFLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQzs2QkFDdEIsSUFBSSxDQUFDLENBQUMsVUFBc0I7NEJBQ3pCLEVBQUUsQ0FBQyxDQUNDLENBQUMsU0FBUyxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUM7bUNBQzlCLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsSUFBSSxHQUFHLENBQUM7bUNBQ3JDLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsSUFBSSxHQUFHLENBQzNDLENBQUMsQ0FBQyxDQUFDO2dDQUNDLElBQUksQ0FBQyxlQUFlLENBQUMsTUFBTSxDQUFDLENBQUMsSUFBSSxDQUFDO29DQUM5QixJQUFJLENBQUMsT0FBTyxFQUFFLENBQUE7Z0NBQ2xCLENBQUMsQ0FBQyxDQUFBLENBQUMsMEJBQTBCOzRCQUNqQyxDQUFDOzRCQUFDLElBQUksQ0FBQyxDQUFDO2dDQUNKLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUEsQ0FBQyxtQkFBbUI7NEJBQzFDLENBQUM7d0JBQ0wsQ0FBQyxDQUFDLENBQUE7b0JBQ1YsQ0FBQztvQkFBQyxJQUFJLENBQUMsQ0FBQzt3QkFDSixFQUFFLENBQUMsQ0FDQyxDQUFDLFNBQVMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDOytCQUM5QixDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLFlBQVksTUFBTSxDQUFDOytCQUM1QyxDQUFDLE9BQU8sU0FBUyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLEtBQUssUUFBUSxDQUFDOytCQUN2RCxDQUFDLFNBQVMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUN2QyxDQUFDLENBQUMsQ0FBQzs0QkFDQyxJQUFJLFFBQVEsR0FBRyxTQUFTLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQSxDQUFDLHlCQUF5Qjs0QkFDMUUsSUFBSSxTQUFTLEdBQUcsSUFBSSxDQUFDLGVBQWUsQ0FBQyxTQUFTLENBQUMsR0FBRyxFQUFFLFNBQVMsQ0FBQyxDQUFBLENBQUMsK0JBQStCOzRCQUM5RixFQUFFLENBQUMsQ0FBQyxTQUFTLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztnQ0FDOUIsSUFBSSxDQUFDLGdCQUFnQixDQUFDLE1BQU0sRUFBRSxTQUFTLEVBQUU7b0NBQ3JDLFFBQVE7b0NBQ1IsU0FBUyxDQUFDLEdBQUcsR0FBRyxJQUFJLENBQUE7b0NBQ3BCLFNBQVMsQ0FBQyxHQUFHLEdBQUcsSUFBSSxDQUFBO29DQUNwQixtQkFBbUI7b0NBQ25CLElBQUksQ0FBQyxlQUFlLENBQUMsU0FBUyxDQUFDO3lDQUMxQixJQUFJLENBQUMsQ0FBQyxVQUFzQjt3Q0FDekIsRUFBRSxDQUFDLENBQ0MsQ0FBQyxVQUFVLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQzsrQ0FDL0IsQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQyxHQUFHLEdBQUcsQ0FBQyxDQUFDLHVDQUF1Qzt3Q0FDbkYsQ0FBQyxDQUFDLENBQUM7NENBQ0MsSUFBSSxDQUFDLGNBQWMsQ0FBQyxRQUFRLENBQUM7aURBQ3hCLElBQUksQ0FBQztnREFDRixJQUFJLENBQUMsT0FBTyxFQUFFLENBQUE7NENBQ2xCLENBQUMsQ0FBQyxDQUFBLENBQUMsMENBQTBDO3dDQUNyRCxDQUFDO3dDQUFDLElBQUksQ0FBQyxDQUFDOzRDQUNKLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUEsQ0FBQyw4Q0FBOEM7d0NBQ3JFLENBQUM7b0NBQ0wsQ0FBQyxDQUFDLENBQUE7Z0NBQ1YsQ0FBQyxDQUFDLENBQUE7NEJBQ04sQ0FBQzs0QkFBQyxJQUFJLENBQUMsQ0FBQztnQ0FDSixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFBLENBQUMsbUNBQW1DOzRCQUMxRCxDQUFDO3dCQUNMLENBQUM7d0JBQUMsSUFBSSxDQUFDLENBQUM7NEJBQ0osSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQSxDQUFDLHlDQUF5Qzt3QkFDaEUsQ0FBQztvQkFDTCxDQUFDO2dCQUNMLENBQUMsQ0FBQyxDQUFBO1lBQ1YsQ0FBQztRQUNMLENBQUMsQ0FBQyxDQUFBO1FBQ04sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0gsZUFBZSxDQUFDLFNBQVMsR0FBRyxFQUFFO1FBQzFCLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLENBQUMsVUFBVSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsS0FBSyxDQUFDLEVBQUUsSUFBSSxDQUFDLHFCQUFxQixDQUFDLFNBQVMsQ0FBQyxDQUFDO2FBQ3hFLElBQUksQ0FBQztZQUNGLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtRQUNsQixDQUFDLENBQUMsQ0FBQTtRQUNOLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7Ozs7O09BTUc7SUFDSCxjQUFjLENBQUMsR0FBRyxFQUFFLEtBQUssR0FBRyxDQUFDO1FBQ3pCLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixFQUFFLENBQUMsQ0FBQyxLQUFLLEdBQUcsR0FBRyxDQUFDLENBQUMsQ0FBQztZQUNkLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUEsQ0FBQyxzQ0FBc0M7UUFDN0QsQ0FBQztRQUFDLElBQUksQ0FBQyxDQUFDO1lBQ0osSUFBSSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDO2lCQUNuQixJQUFJLENBQUMsQ0FBQyxTQUFTO2dCQUNaLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztvQkFDckMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQSxDQUFDLGlCQUFpQjtnQkFDeEMsQ0FBQztnQkFBQyxJQUFJLENBQUMsQ0FBQztvQkFDSixFQUFFLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLFFBQVEsQ0FBQyxLQUFLLFNBQVMsQ0FBQyxDQUFDLENBQUM7d0JBQ3hDLFVBQVUsQ0FBQzs0QkFDUCxJQUFJLENBQUMsY0FBYyxDQUFDLEdBQUcsRUFBRSxLQUFLLEdBQUcsQ0FBQyxDQUFDLENBQUEsQ0FBQyxRQUFRO3dCQUNoRCxDQUFDLEVBQUUsS0FBSyxHQUFHLEdBQUcsQ0FBQyxDQUFBO29CQUNuQixDQUFDO29CQUFDLElBQUksQ0FBQyxDQUFDO3dCQUNKLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQSxDQUFDLHFCQUFxQjtvQkFDeEMsQ0FBQztnQkFDTCxDQUFDO1lBQ0wsQ0FBQyxDQUFDLENBQUE7UUFDVixDQUFDO1FBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOzs7Ozs7T0FNRztJQUNILGVBQWUsQ0FBQyxHQUFHLEVBQUUsS0FBSyxHQUFHLENBQUM7UUFDMUIsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO1FBQ3BCLEVBQUUsQ0FBQyxDQUFDLEtBQUssR0FBRyxHQUFHLENBQUMsQ0FBQyxDQUFDO1lBQ2QsSUFBSSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQSxDQUFDLHNDQUFzQztRQUM3RCxDQUFDO1FBQUMsSUFBSSxDQUFDLENBQUM7WUFDSixJQUFJLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUM7aUJBQ25CLElBQUksQ0FBQyxDQUFDLFNBQXFCO2dCQUN4QixFQUFFLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7b0JBQ2xFLElBQUksQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFBLENBQUMsdUNBQXVDO2dCQUN2RSxDQUFDO2dCQUFDLElBQUksQ0FBQyxDQUFDO29CQUNKLEVBQUUsQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDLEdBQUcsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO3dCQUMzRSxVQUFVLENBQUM7NEJBQ1AsSUFBSSxDQUFDLGVBQWUsQ0FBQyxHQUFHLEVBQUUsS0FBSyxHQUFHLENBQUMsQ0FBQyxDQUFBLENBQUMsUUFBUTt3QkFDakQsQ0FBQyxFQUFFLEtBQUssR0FBRyxHQUFHLENBQUMsQ0FBQTtvQkFDbkIsQ0FBQztvQkFBQyxJQUFJLENBQUMsQ0FBQzt3QkFDSixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFBLENBQUMsZUFBZTtvQkFDdEMsQ0FBQztnQkFDTCxDQUFDO1lBQ0wsQ0FBQyxDQUFDLENBQUE7UUFDVixDQUFDO1FBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0gsY0FBYyxDQUFDLFVBQVU7UUFDckIsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO1FBQ3BCLEVBQUUsQ0FBQyxRQUFRLENBQUMsVUFBVSxHQUFHLE1BQU0sRUFBRSxDQUFDLEdBQUcsRUFBRSxTQUFpQjtZQUNwRCxFQUFFLENBQUMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztnQkFDeEIsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDO29CQUMxQixPQUFPLENBQUMsS0FBSyxDQUFDLDRCQUE0QixFQUFFLEdBQUcsQ0FBQyxNQUFNLENBQUMsRUFBRSw2QkFBNkIsQ0FBQyxDQUFBO2dCQUMzRixDQUFDO2dCQUNELElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUE7WUFDdEIsQ0FBQztZQUFDLElBQUksQ0FBQyxDQUFDO2dCQUNKLElBQUksR0FBRyxHQUFHLFNBQVMsQ0FBQyxRQUFRLEVBQUUsQ0FBQTtnQkFDOUIsSUFBSSxDQUFDLFVBQVUsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxVQUFVLENBQUMsRUFBRSxJQUFJLENBQUMsZUFBZSxDQUFDLEdBQUcsRUFBRSxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUM7cUJBQ3RGLElBQUksQ0FBQyxDQUFDLFNBQXFCO29CQUN4QixFQUFFLENBQUMsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLE1BQU0sR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7d0JBQ2xFLElBQUksQ0FBQyxPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFBLENBQUMsdUNBQXVDO29CQUN2RSxDQUFDO29CQUFDLElBQUksQ0FBQyxDQUFDO3dCQUNKLEVBQUUsQ0FBQyxDQUFDLFNBQVMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQzs0QkFDbEMsRUFBRSxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQyxHQUFHLEdBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0NBQ3hELElBQUksT0FBTyxHQUFHLFNBQVMsQ0FBQyxTQUFTLENBQUMsQ0FBQTtnQ0FDbEMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sWUFBWSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7b0NBQy9CLE9BQU8sR0FBRyxFQUFFLENBQUEsQ0FBRSwyQkFBMkI7Z0NBQzdDLENBQUM7Z0NBQ0QsSUFBSSxDQUFDLGVBQWUsQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUM7cUNBQ3BDLElBQUksQ0FBQyxDQUFDLE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsQ0FBQSxDQUFDLENBQUMsQ0FBQyxDQUFBOzRCQUN2QyxDQUFDOzRCQUFDLElBQUksQ0FBQyxDQUFDO2dDQUNKLElBQUksQ0FBQyxPQUFPLENBQUMsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQyxHQUFHLEdBQUcsQ0FBQyxHQUFHLFNBQVMsQ0FBQyxHQUFHLEdBQUcsS0FBSyxDQUFDLENBQUEsQ0FBQyw2Q0FBNkM7NEJBQzNILENBQUM7d0JBQ0wsQ0FBQzt3QkFBQyxJQUFJLENBQUMsQ0FBQzs0QkFDSixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFBLENBQUMsbUJBQW1CO3dCQUMxQyxDQUFDO29CQUNMLENBQUM7Z0JBQ0wsQ0FBQyxDQUFDLENBQUE7WUFDVixDQUFDO1FBQ0wsQ0FBQyxDQUFDLENBQUE7UUFDRixNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUN2QixDQUFDO0lBRUQ7OztPQUdHO0lBQ0gsVUFBVTtRQUNOLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLENBQUMsWUFBWSxFQUFFO2FBQ2QsSUFBSSxDQUFDLENBQUMsR0FBRztZQUNOLEVBQUUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUMzQixJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksS0FBSyxDQUFDLHVDQUF1QyxDQUFDLENBQUMsQ0FBQTtZQUNuRSxDQUFDO1lBQUMsSUFBSSxDQUFDLENBQUM7Z0JBQ0osSUFBSSxDQUFDLFNBQVMsR0FBRyxHQUFHLENBQUEsQ0FBQyxrQkFBa0I7Z0JBQ3ZDLElBQUksQ0FBQyxlQUFlLENBQUMsSUFBSSxDQUFDO3FCQUNyQixJQUFJLENBQUMsQ0FBQyxTQUFxQjtvQkFDeEIsRUFBRSxDQUFDLENBQ0MsQ0FBQyxTQUFTLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQzsyQkFDOUIsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxZQUFZLE1BQU0sQ0FBQzsyQkFDNUMsQ0FBQyxPQUFPLFNBQVMsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxLQUFLLFFBQVEsQ0FDN0QsQ0FBQyxDQUFDLENBQUM7d0JBQ0MsSUFBSSxDQUFDLE9BQU8sR0FBRyxTQUFTLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTt3QkFDaEQsSUFBSSxDQUFDLGVBQWUsQ0FBQyxJQUFJLENBQUMsT0FBTyxFQUFFLElBQUksQ0FBQzs2QkFDbkMsSUFBSSxDQUFDLENBQUMsU0FBcUI7NEJBQ3hCLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTt3QkFDbEIsQ0FBQyxDQUFDLENBQUEsQ0FBQyxrQ0FBa0M7b0JBQzdDLENBQUM7b0JBQUMsSUFBSSxDQUFDLENBQUM7d0JBQ0osSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxxQkFBcUIsQ0FBQyxDQUFDLENBQUE7b0JBQ2pELENBQUM7Z0JBQ0wsQ0FBQyxDQUFDLENBQUE7WUFDVixDQUFDO1FBQ0wsQ0FBQyxDQUFDLENBQUE7UUFDTixNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUN2QixDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxhQUFhLENBQUMsS0FBYTtRQUN2QixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsRUFBRSxDQUFDLENBQUMsT0FBTyxLQUFLLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQztZQUM1QixJQUFJLENBQUMsZUFBZSxDQUFDO2dCQUNqQixPQUFPLEVBQUU7b0JBQ0wsU0FBUyxHQUFHLEtBQUs7aUJBQ3BCO2FBQ0osQ0FBQztpQkFDRyxJQUFJLENBQUMsQ0FBQyxTQUFxQjtnQkFDeEIsRUFBRSxDQUFDLENBQ0MsQ0FBQyxTQUFTLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQzt1QkFDOUIsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLFlBQVksQ0FBQyxLQUFLLEdBQUcsQ0FBQzt1QkFDckMsQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxZQUFZLE1BQU0sQ0FBQzt1QkFDNUMsQ0FBQyxPQUFPLFNBQVMsQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxLQUFLLFFBQVEsQ0FDN0QsQ0FBQyxDQUFDLENBQUM7b0JBQ0MsSUFBSSxDQUFDLE9BQU8sR0FBRyxTQUFTLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtvQkFDaEQsSUFBSSxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUEsQ0FBQyxtQkFBbUI7Z0JBQ2xELENBQUM7Z0JBQUMsSUFBSSxDQUFDLENBQUM7b0JBQ0osSUFBSSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEtBQUssQ0FBQyxnQ0FBZ0MsQ0FBQyxDQUFDLENBQUEsQ0FBQyxzQkFBc0I7Z0JBQ25GLENBQUM7WUFDTCxDQUFDLENBQUMsQ0FBQTtRQUVWLENBQUM7UUFBQyxJQUFJLENBQUMsQ0FBQztZQUNKLElBQUksQ0FBQyxNQUFNLENBQUMsSUFBSSxLQUFLLENBQUMsMkJBQTJCLENBQUMsQ0FBQyxDQUFBO1FBQ3ZELENBQUM7UUFDRCxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUN2QixDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxRQUFRLENBQUMsT0FBTztRQUNaLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLENBQUMsZUFBZSxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUU7WUFDL0IsV0FBVyxFQUFFLE9BQU8sQ0FBQyx1QkFBdUI7U0FDL0MsQ0FBQyxDQUFDLElBQUksQ0FBQztZQUNKLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtRQUNsQixDQUFDLENBQUMsQ0FBQTtRQUNGLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7T0FFRztJQUNILGtCQUFrQixDQUFDLFNBQWlCLEVBQUUsZUFBdUIsRUFBRSxjQUFzQjtRQUNqRixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsSUFBSSxDQUFDLFVBQVUsRUFBRTthQUNaLElBQUksQ0FBQyxDQUFDLE9BQU87WUFDVixJQUFJLEtBQUssR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDLE9BQU8sQ0FBQyxDQUFBLENBQUMsOENBQThDO1lBQ3JGLGNBQWMsR0FBRyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsY0FBYyxDQUFDLENBQUE7WUFDdEQsU0FBUyxHQUFHLElBQUksQ0FBQyxnQkFBZ0IsQ0FBQyxTQUFTLENBQUMsQ0FBQTtZQUM1QyxLQUFLLEdBQUcsSUFBSSxDQUFDLGdCQUFnQixDQUFDLEtBQUssQ0FBQyxDQUFBO1lBQ3BDLGVBQWUsR0FBRyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsZUFBZSxDQUFDLENBQUE7WUFDeEQsa0JBQWtCO1lBQ2xCLElBQUksQ0FBQyxhQUFhLENBQUM7Z0JBQ2YsVUFBVSxFQUFFLElBQUk7Z0JBQ2hCLFdBQVcsRUFBRSxjQUFjO2dCQUMzQixZQUFZLEVBQUUsZUFBZTtnQkFDN0IsVUFBVSxFQUFFLFNBQVM7Z0JBQ3JCLFlBQVksRUFBRSxLQUFLO2FBQ3RCLENBQUM7aUJBQ0csSUFBSSxDQUFDO2dCQUNGLElBQUksQ0FBQyxjQUFjLENBQUMsU0FBUyxDQUFDO3FCQUN6QixJQUFJLENBQUMsQ0FBQyxJQUFJO29CQUNQLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxZQUFZLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxJQUFJLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDO3dCQUN6RCxFQUFFLENBQUMsU0FBUyxDQUFDLFNBQVMsR0FBRyxNQUFNLEVBQUUsSUFBSSxFQUFFLENBQUMsR0FBRzs0QkFDdkMsRUFBRSxDQUFDLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUM7Z0NBQ3hCLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQztvQ0FDMUIsT0FBTyxDQUFDLEtBQUssQ0FBQyw0QkFBNEIsRUFBRSxHQUFHLENBQUMsTUFBTSxDQUFDLEVBQUUsbUNBQW1DLENBQUMsQ0FBQTtnQ0FDakcsQ0FBQztnQ0FDRCxJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBOzRCQUNwQixDQUFDOzRCQUFDLElBQUksQ0FBQyxDQUFDO2dDQUNKLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQSxDQUFFLHNEQUFzRDs0QkFDMUUsQ0FBQzt3QkFDTCxDQUFDLENBQUMsQ0FBQTtvQkFDTixDQUFDO29CQUFDLElBQUksQ0FBQyxDQUFDO3dCQUNKLElBQUksQ0FBQyxNQUFNLENBQUMsMEJBQTBCLENBQUMsQ0FBQTtvQkFDM0MsQ0FBQztnQkFDTCxDQUFDLENBQUMsQ0FBQTtZQUVWLENBQUMsQ0FBQyxDQUFBO1FBQ1YsQ0FBQyxDQUFDLENBQUE7UUFDTixNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUN2QixDQUFDO0lBRUQ7Ozs7Ozs7O09BUUc7SUFDSCxhQUFhLENBQUMsVUFNYjtRQUNHLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLE9BQU8sR0FBRyx1Q0FBdUMsVUFBVSxDQUFDLFVBQVUsR0FBRztjQUN2RSxVQUFVO2NBQ1YsYUFBYSxVQUFVLENBQUMsV0FBVyxNQUFNLFVBQVUsQ0FBQyxZQUFZLE9BQU8sVUFBVSxDQUFDLFVBQVUsaUJBQWlCLFVBQVUsQ0FBQyxZQUFZLElBQUk7Y0FDeEksYUFBYSxVQUFVLENBQUMsVUFBVSw4QkFBOEIsVUFBVSxDQUFDLFVBQVUsUUFBUSxDQUFBO1FBQ25HLE9BQU8sQ0FBQyxLQUFLLENBQUMsNEJBQTRCLENBQUMsQ0FBQTtRQUMzQyxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUM7WUFDMUIsT0FBTyxDQUFDLEtBQUssQ0FBQyxVQUFVLEVBQUUsT0FBTyxDQUFDLENBQUE7UUFDdEMsQ0FBQztRQUNELE9BQU8sQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFDLE9BQU8sRUFBRSxTQUFTLEVBQUUsV0FBVztZQUMxRCxFQUFFLENBQUMsQ0FBQyxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUM7Z0JBQ2YsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO1lBQ2xCLENBQUM7WUFBQyxJQUFJLENBQUMsQ0FBQztnQkFDSixJQUFJLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFBO1lBQzVCLENBQUM7UUFDTCxDQUFDLENBQUMsQ0FBQTtRQUNGLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7T0FFRztJQUNILGFBQWE7UUFDVCxNQUFNO0lBQ1YsQ0FBQztJQUVEOzs7OztPQUtHO0lBQ0gsZ0JBQWdCLENBQUMsSUFBSSxFQUFFLFFBQVEsR0FBRyxLQUFLO1FBQ25DLEVBQUUsQ0FBQyxDQUFDLE9BQU8sSUFBSSxLQUFLLFFBQVEsQ0FBQyxDQUFDLENBQUM7WUFDM0IsSUFBSSxHQUFHLEVBQUUsQ0FBQTtRQUNiLENBQUM7UUFDRCxvREFBb0Q7UUFDcEQsSUFBSSxTQUFTLEdBQUcsNERBQTRELENBQUE7UUFDNUUsSUFBSSxTQUFTLEdBQUcsMkRBQTJELENBQUE7UUFDM0UsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsSUFBSSxNQUFNLENBQUMsUUFBUSxHQUFHLFNBQVMsR0FBRyxTQUFTLEVBQUUsR0FBRyxDQUFDLEVBQUUsQ0FBQyxhQUFhO1lBQ2pGLEVBQUUsQ0FBQyxDQUFDLE9BQU8sYUFBYSxLQUFLLFFBQVEsQ0FBQyxDQUFDLENBQUM7Z0JBQ3BDLE1BQU0sQ0FBQyxHQUFHLEdBQUcsYUFBYSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUMsaUJBQWlCLEVBQUUsQ0FBQTtZQUM3RSxDQUFDO1lBQ0QsTUFBTSxDQUFDLEtBQUssQ0FBQTtRQUNoQixDQUFDLENBQUMsQ0FBQTtJQUNOLENBQUM7SUFFRDs7Ozs7T0FLRztJQUNILGdCQUFnQixDQUFDLE1BQU0sRUFBRSxTQUFTLEVBQUUsUUFBUTtRQUN4Qyw4QkFBOEI7UUFDOUIsRUFBRSxDQUFDLENBQUMsT0FBTyxRQUFRLEtBQUssVUFBVSxDQUFDLENBQUMsQ0FBQztZQUNqQyxRQUFRLEdBQUcsSUFBSSxDQUFDLGFBQWEsQ0FBQSxDQUFDLDhCQUE4QjtRQUNoRSxDQUFDO1FBQ0QsRUFBRSxDQUFDLENBQUMsU0FBUyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUM7WUFDOUIsRUFBRSxDQUFDLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxLQUFLLFNBQVMsQ0FBQyxDQUFDLENBQUM7Z0JBQ2xDLElBQUksSUFBSSxHQUFHLElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxDQUFDLGFBQWEsR0FBRyxTQUFTLENBQUMsT0FBTyxDQUFDLENBQUEsQ0FBQyxtRUFBbUU7Z0JBQ3JJLEVBQUUsQ0FBQyxTQUFTLENBQUMsSUFBSSxFQUFFLElBQUksQ0FBQyxvQkFBb0IsQ0FBQyxTQUFTLENBQUMsRUFBRSxDQUFDLEdBQUc7b0JBQ3pELEVBQUUsQ0FBQyxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUMsQ0FBQyxDQUFDO3dCQUN4QixFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsVUFBVSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUM7NEJBQzFCLE9BQU8sQ0FBQyxLQUFLLENBQ1QsNEJBQTRCLEVBQzVCLEdBQUcsQ0FBQyxNQUFNLENBQUMsRUFBRSxzQ0FBc0MsQ0FDdEQsQ0FBQTt3QkFDTCxDQUFDO3dCQUNELFFBQVEsRUFBRSxDQUFBO29CQUNkLENBQUM7b0JBQUMsSUFBSSxDQUFDLENBQUM7d0JBQ0osMkVBQTJFO3dCQUMzRSxJQUFJLEVBQUUsR0FBRyxRQUFRLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxLQUFLLEVBQUUsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFBO3dCQUNoRSxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsZUFBZSxDQUFDLENBQUMsQ0FBQzs0QkFDdkIsRUFBRSxDQUFDLFFBQVEsQ0FBQyx3QkFBd0IsRUFBRSxDQUFDLE1BQU07Z0NBQ3pDLEVBQUUsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtnQ0FDVixRQUFRLEVBQUUsQ0FBQTs0QkFDZCxDQUFDLENBQUMsQ0FBQTt3QkFDTixDQUFDO3dCQUFDLElBQUksQ0FBQyxDQUFDOzRCQUNKLEVBQUUsQ0FBQyxLQUFLLEVBQUUsQ0FBQTs0QkFDVixRQUFRLEVBQUUsQ0FBQSxDQUFDLHFDQUFxQzt3QkFDcEQsQ0FBQztvQkFDTCxDQUFDO2dCQUNMLENBQUMsQ0FBQyxDQUFBO1lBQ04sQ0FBQztZQUFDLElBQUksQ0FBQyxDQUFDO2dCQUNKLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQTtnQkFDakQsUUFBUSxFQUFFLENBQUE7WUFDZCxDQUFDO1FBQ0wsQ0FBQztRQUFDLElBQUksQ0FBQyxDQUFDO1lBQ0osT0FBTyxDQUFDLEtBQUssQ0FBQyxxQ0FBcUMsQ0FBQyxDQUFBO1lBQ3BELFFBQVEsRUFBRSxDQUFBO1FBQ2QsQ0FBQztJQUNMLENBQUM7SUFFRDs7OztPQUlHO0lBQ0gsVUFBVSxDQUFDLE9BQU87UUFDZCxJQUFJLEtBQUssR0FBRyx1Q0FBdUMsQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUE7UUFDakUsRUFBRSxDQUFDLENBQUMsQ0FBQyxLQUFLLFlBQVksS0FBSyxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUNqRCxJQUFJLE1BQU0sR0FBRyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFDckIsY0FBYztZQUNkLEtBQUssR0FBRyxJQUFJLENBQUE7WUFDWixNQUFNLENBQUMsTUFBTSxDQUFBO1FBQ2pCLENBQUM7SUFDTCxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxlQUFlLENBQUMsR0FBRyxFQUFFLGFBQXFCO1FBQ3RDLGlCQUFpQjtRQUNqQixFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsWUFBWSxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDbEUsTUFBTSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUMsS0FBSztnQkFDL0IsSUFBSSxJQUFJLEdBQUcsS0FBSyxDQUFDLE1BQU0sQ0FBQyxDQUFBO2dCQUN4QixjQUFjO2dCQUNkLEtBQUssR0FBRyxJQUFJLENBQUE7Z0JBQ1osRUFBRSxDQUFDLENBQUMsSUFBSSxLQUFLLGFBQWEsQ0FBQyxDQUFDLENBQUM7b0JBQ3pCLE1BQU0sQ0FBQyxJQUFJLENBQUE7Z0JBQ2YsQ0FBQztnQkFDRCxNQUFNLENBQUMsS0FBSyxDQUFBO1lBQ2hCLENBQUMsQ0FBQyxDQUFDLEdBQUcsRUFBRSxDQUFBO1FBQ1osQ0FBQyxDQUFDLGtDQUFrQztRQUNwQyxjQUFjO1FBQ2QsR0FBRyxHQUFHLElBQUksQ0FBQTtRQUNWLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQSxDQUFDLGlEQUFpRDtJQUNuRSxDQUFDO0lBRUQ7Ozs7T0FJRztJQUNILFlBQVksQ0FBQyxPQUFPO1FBQ2hCLElBQUksTUFBTSxHQUFHLFNBQVMsQ0FBQTtRQUN0QixJQUFJLEtBQUssR0FBRyxPQUFPLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEtBQUs7WUFDckMsRUFBRSxDQUFDLENBQUMsT0FBTyxLQUFLLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQztnQkFDNUIsTUFBTSxDQUFDLEtBQUssQ0FBQTtZQUNoQixDQUFDO1lBQUMsSUFBSSxDQUFDLENBQUM7Z0JBQ0osTUFBTSxDQUFDLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxNQUFNLENBQUMsQ0FBQSxDQUFDLHdCQUF3QjtZQUMxRCxDQUFDO1FBQ0wsQ0FBQyxDQUNBLENBQUMsR0FBRyxFQUFFLENBQUE7UUFDUCxjQUFjO1FBQ2QsT0FBTyxHQUFHLElBQUksQ0FBQTtRQUNkLEVBQUUsQ0FBQyxDQUFDLE9BQU8sS0FBSyxLQUFLLFFBQVEsQ0FBQyxDQUFDLENBQUM7WUFDNUIsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ2pCLENBQUMsQ0FBQyxpQkFBaUI7UUFDbkIsTUFBTSxDQUFDLEtBQUssQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFBLENBQUMsb0RBQW9EO0lBQzNGLENBQUM7SUFFRDs7OztPQUlHO0lBQ0gsOEJBQThCLENBQUMsTUFBTTtRQUNqQyxNQUFNLENBQUM7WUFDSCxVQUFVLEVBQUUsV0FBVztZQUN2QixZQUFZLEVBQUU7Z0JBQ1YsTUFBTSxFQUFFLEtBQUs7Z0JBQ2IsT0FBTyxFQUFFLE1BQU07YUFDbEI7U0FDSixDQUFBO0lBQ0wsQ0FBQztJQUVEOzs7O09BSUc7SUFDSCxvQkFBb0IsQ0FBQyxTQUFTO1FBQzFCLGlCQUFpQjtRQUNqQixFQUFFLENBQUMsQ0FBQyxTQUFTLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztZQUM5QixFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsbUJBQW1CLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztnQkFDN0MsSUFBSSxHQUFHLEdBQUcsa0JBQWtCLENBQUM7b0JBQ3pCLENBQUMsRUFBRSxJQUFJLENBQUMsbUJBQW1CLENBQUMsR0FBRyxDQUFDO29CQUNoQyxHQUFHLEVBQUUsSUFBSSxDQUFDLG1CQUFtQixDQUFDLEtBQUssQ0FBQztvQkFDcEMsQ0FBQyxFQUFFLElBQUksQ0FBQyxtQkFBbUIsQ0FBQyxHQUFHLENBQUM7aUJBQ25DLENBQ0EsQ0FBQTtnQkFDRCxJQUFJLElBQUksR0FBRyxNQUFNLENBQUMsVUFBVSxDQUFDLFFBQVEsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxFQUFFLE1BQU0sQ0FBQyxDQUFDLE1BQU0sRUFBRSxDQUFBO2dCQUNwRiw0Q0FBNEM7Z0JBQzVDLElBQUksV0FBVyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsUUFBUSxFQUFFLENBQUMsQ0FBQTtnQkFDdkUsSUFBSSxLQUFLLEdBQUcsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFBO2dCQUM5QixNQUFNLENBQUMsS0FBSyxHQUFHLEdBQUcsR0FBRyxXQUFXLENBQUE7WUFDcEMsQ0FBQztRQUNMLENBQUM7UUFBQyxJQUFJLENBQUMsQ0FBQztZQUNKLE1BQU0sQ0FBQyxFQUFFLENBQUEsQ0FBQyx1Q0FBdUM7UUFDckQsQ0FBQztJQUNMLENBQUM7SUFFRDs7OztPQUlHO0lBQ0gscUJBQXFCLENBQUMsU0FBUztRQUMzQixNQUFNLENBQUM7WUFDSCxVQUFVLEVBQUUsV0FBVztZQUN2QixrQkFBa0IsRUFBRSxJQUFJLENBQUMsb0JBQW9CLENBQUMsU0FBUyxDQUFDO1NBQzNELENBQUE7SUFDTCxDQUFDO0lBRUQ7Ozs7O09BS0c7SUFDSCxlQUFlLENBQUMsR0FBVyxFQUFFLFVBQWtCO1FBQzNDLEVBQUUsQ0FBQyxDQUFDLE9BQU8sR0FBRyxLQUFLLFFBQVEsSUFBSSxDQUFDLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUN0RCxHQUFHLEdBQUcsRUFBRSxDQUFBLENBQUMseUJBQXlCO1FBQ3RDLENBQUM7UUFDRCxFQUFFLENBQUMsQ0FBQyxDQUFDLE9BQU8sVUFBVSxLQUFLLFFBQVEsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQyxDQUFDLElBQUksQ0FBQyxVQUFVLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ2hGLFVBQVUsR0FBRyxDQUFDLENBQUEsQ0FBQyxvQ0FBb0M7UUFDdkQsQ0FBQztRQUNELElBQUksY0FBYyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQSxDQUFDLDRCQUE0QjtRQUMzRixJQUFJLFlBQVksR0FBRyxDQUFDLElBQUksSUFBSSxFQUFFLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQSxDQUFDLGlDQUFpQztRQUUvRSw0Q0FBNEM7UUFDNUMsSUFBSSxhQUFhLEdBQUcsQ0FBQyxJQUFJLElBQUksQ0FBQyxDQUFDLENBQUMsSUFBSSxJQUFJLEVBQUUsQ0FBQyxHQUFHLElBQUksR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQTtRQUN4RyxNQUFNLENBQUM7WUFDSCxVQUFVLEVBQUUsVUFBVTtZQUN0QixLQUFLLEVBQUUsY0FBYztZQUNyQixXQUFXLEVBQUUsWUFBWTtZQUN6QixVQUFVLEVBQUUsYUFBYTtTQUM1QixDQUFBO0lBQ0wsQ0FBQztDQUNKO0FBM3NCRCxnQ0Eyc0JDIn0=