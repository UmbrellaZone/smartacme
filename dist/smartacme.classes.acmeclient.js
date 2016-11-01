"use strict";
const base64url = require("base64url");
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
let json_to_utf8buffer = function (obj) {
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
        let ctx = this;
        if (!(payload instanceof Object)) {
            payload = {}; // ensure payload is object
        }
        payload['resource'] = 'reg';
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.jWebClient.post(uri, payload, function (ans, res) {
            if (ans instanceof Object) {
                ctx.clientProfilePubKey = ans.key; // cache or reset returned public key
                if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                    let linkStr = res.headers['link'];
                    if (typeof linkStr === 'string') {
                        let tosLink = ctx.getTosLink(linkStr);
                        if (typeof tosLink === 'string') {
                            ctx.tosLink = tosLink; // cache TOS link
                        }
                        else {
                            ctx.tosLink = null; // reset TOS link
                        }
                    }
                    else {
                        ctx.tosLink = null; // reset TOS link
                    }
                }
                else {
                    ctx.tosLink = null; // reset TOS link
                }
                callback(ans, res);
            }
            else {
                callback(false);
            }
            // dereference
            ans = null;
            callback = null;
            ctx = null;
            res = null;
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.getProfile(function (profile) {
            if (!(profile instanceof Object)) {
                callback(false); // no profile returned
                // dereference
                callback = null;
                ctx = null;
            }
            else {
                ctx.jWebClient.post(ctx.directory['new-authz'], ctx.makeDomainAuthorizationRequest(domain), function (ans, res) {
                    if ((res instanceof Object) && (res['statusCode'] === 403)) {
                        ctx.agreeTos(ctx.tosLink, function (ans_, res_) {
                            if ((res_ instanceof Object)
                                && (res_['statusCode'] >= 200)
                                && (res_['statusCode'] <= 400)) {
                                ctx.authorizeDomain(domain, callback); // try authorization again
                            }
                            else {
                                callback(false); // agreement failed
                            }
                            // dereference
                            ans = null;
                            ans_ = null;
                            callback = null;
                            ctx = null;
                            profile = null;
                            res = null;
                            res_ = null;
                        });
                    }
                    else {
                        if ((res instanceof Object)
                            && (res['headers'] instanceof Object)
                            && (typeof res.headers['location'] === 'string')
                            && (ans instanceof Object)) {
                            let poll_uri = res.headers['location']; // status URI for polling
                            let challenge = ctx.selectChallenge(ans, 'http-01'); // select simple http challenge
                            if (challenge instanceof Object) {
                                ctx.prepareChallenge(domain, challenge, function () {
                                    // reset
                                    ans = null;
                                    res = null;
                                    // accept challenge
                                    ctx.acceptChallenge(challenge, function (ans, res) {
                                        if ((res instanceof Object)
                                            && (res['statusCode'] < 400) // server confirms challenge acceptance
                                        ) {
                                            ctx.pollUntilValid(poll_uri, callback); // poll status until server states success
                                        }
                                        else {
                                            callback(false); // server did not confirm challenge acceptance
                                        }
                                        // dereference
                                        ans = null;
                                        callback = null;
                                        challenge = null;
                                        ctx = null;
                                        profile = null;
                                        res = null;
                                    });
                                });
                            }
                            else {
                                callback(false); // desired challenge is not in list
                                // dereference
                                ans = null;
                                callback = null;
                                ctx = null;
                                profile = null;
                                res = null;
                            }
                        }
                        else {
                            callback(false); // server did not respond with status URI
                            // dereference
                            ans = null;
                            callback = null;
                            ctx = null;
                            profile = null;
                            res = null;
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (retry > 128) {
            callback(false); // stop if retry value exceeds maximum
        }
        else {
            this.jWebClient.get(uri, function (ans, res) {
                if (!(ans instanceof Object)) {
                    callback(false); // invalid answer
                    // dereference
                    callback = null;
                    ctx = null;
                    res = null;
                }
                else {
                    if (ans['status'] === 'pending') {
                        setTimeout(function () {
                            ctx.pollUntilValid(uri, callback, retry * 2); // retry
                            // dereference
                            ans = null;
                            callback = null;
                            ctx = null;
                            res = null;
                        }, retry * 500);
                    }
                    else {
                        callback(ans, res); // challenge complete
                        // dereference
                        ans = null;
                        callback = null;
                        ctx = null;
                        res = null;
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (retry > 128) {
            callback(false); // stop if retry value exceeds maximum
        }
        else {
            this.jWebClient.get(uri, function (ans, res) {
                if ((ans instanceof Buffer) && (ans.length > 0)) {
                    callback(ans); // certificate was returned with answer
                    // dereference
                    ans = null;
                    callback = null;
                    ctx = null;
                    res = null;
                }
                else {
                    if ((res instanceof Object) && (res['statusCode'] < 400)) {
                        setTimeout(function () {
                            ctx.pollUntilIssued(uri, callback, retry * 2); // retry
                            // dereference
                            ans = null;
                            callback = null;
                            ctx = null;
                            res = null;
                        }, retry * 500);
                    }
                    else {
                        callback(false); // CSR complete
                        // dereference
                        ans = null;
                        callback = null;
                        ctx = null;
                        res = null;
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        fs.readFile(domain + '.csr', function (err, csr) {
            if (err instanceof Object) {
                if (ctx.jWebClient.verbose) {
                    console.error('Error  : File system error', err['code'], 'while reading key from file');
                }
                callback(false);
                // dereference
                callback = null;
                csr = null;
                ctx = null;
                err = null;
            }
            else {
                ctx.jWebClient.post(ctx.directory['new-cert'], ctx.makeCertRequest(csr, ctx.days_valid), function (ans, res) {
                    if ((ans instanceof Buffer) && (ans.length > 0)) {
                        callback(ans); // certificate was returned with answer
                        // dereference
                        ans = null;
                        callback = null;
                        csr = null;
                        ctx = null;
                        err = null;
                        res = null;
                    }
                    else {
                        if (res instanceof Object) {
                            if ((res['statusCode'] < 400) && !ans) {
                                let headers = res['headers'];
                                if (!(headers instanceof Object)) {
                                    headers = {}; // ensure headers is object
                                }
                                ctx.pollUntilIssued(headers['location'], callback); // poll provided status URI
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
                        // dereference
                        ans = null;
                        callback = null;
                        csr = null;
                        ctx = null;
                        err = null;
                        res = null;
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.getDirectory(function (dir) {
            if (!(dir instanceof Object)) {
                callback(false); // server did not respond with directory
                // dereference
                callback = null;
                ctx = null;
            }
            else {
                ctx.directory = dir; // cache directory
                ctx.newRegistration(null, function (ans, res) {
                    if ((res instanceof Object)
                        && (res['headers'] instanceof Object)
                        && (typeof res.headers['location'] === 'string')) {
                        ctx.regLink = res.headers['location'];
                        ctx.getRegistration(ctx.regLink, null, callback); // get registration info from link
                    }
                    else {
                        callback(false); // registration failed
                    }
                    // dereference
                    ans = null;
                    callback = null;
                    ctx = null;
                    dir = null;
                    res = null;
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
        let ctx = this;
        if (typeof email === 'string') {
            if (typeof callback !== 'function') {
                callback = this.emptyCallback; // ensure callback is function
            }
            ctx.newRegistration({
                contact: [
                    'mailto:' + email
                ]
            }, function (ans, res) {
                if ((res instanceof Object)
                    && (res['statusCode'] === 201)
                    && (res['headers'] instanceof Object)
                    && (typeof res.headers['location'] === 'string')) {
                    ctx.regLink = res.headers['location'];
                    callback(ctx.regLink); // registration URI
                }
                else {
                    callback(false); // registration failed
                }
                // dereference
                ans = null;
                callback = null;
                ctx = null;
                res = null;
            });
        }
        else {
            callback(false); // no email address provided
            // dereference
            callback = null;
            ctx = null;
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
        let ctx = this;
        if (typeof domain !== 'string') {
            domain = ''; // ensure domain is string
        }
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.getProfile(function (profile) {
            let email = ctx.extractEmail(profile); // try to determine email address from profile
            if (typeof ctx.emailOverride === 'string') {
                email = ctx.emailOverride; // override email address if set
            }
            else if (typeof email !== 'string') {
                email = ctx.emailDefaultPrefix + '@' + domain; // or set default
            }
            let bit = ctx.defaultRsaKeySize;
            // sanitize
            bit = Number(bit);
            country = ctx.makeSafeFileName(country);
            domain = ctx.makeSafeFileName(domain);
            email = ctx.makeSafeFileName(email);
            organization = ctx.makeSafeFileName(organization);
            // create key pair
            ctx.createKeyPair(bit, country, organization, domain, email, function (e) {
                if (!e) {
                    ctx.requestSigning(domain, function (cert) {
                        if ((cert instanceof Buffer) || (typeof cert === 'string')) {
                            fs.writeFile(domain + '.der', cert, function (err) {
                                if (err instanceof Object) {
                                    if (ctx.jWebClient.verbose) {
                                        console.error('Error  : File system error', err['code'], 'while writing certificate to file');
                                    }
                                    callback(false);
                                }
                                else {
                                    callback(true); // CSR complete and certificate written to file system
                                }
                                // dereference
                                callback = null;
                                cert = null;
                                ctx = null;
                                e = null;
                                err = null;
                                profile = null;
                            });
                        }
                        else {
                            callback(false); // invalid certificate data
                            // dereference
                            callback = null;
                            cert = null;
                            ctx = null;
                            e = null;
                            profile = null;
                        }
                    });
                }
                else {
                    callback(false); // could not create key pair
                    // dereference
                    callback = null;
                    ctx = null;
                    e = null;
                    profile = null;
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
        child_process.exec(openssl, function (e) {
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
        return name.replace(new RegExp(withPath ? regex_path : regex_file, 'g'), function (charToReplace) {
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (challenge instanceof Object) {
            if (challenge['type'] === 'http-01') {
                let path = this.webroot + this.well_known_path + challenge['token']; // webroot and well_known_path are expected to be already sanitized
                fs.writeFile(path, this.makeKeyAuthorization(challenge), function (err) {
                    if (err instanceof Object) {
                        if (ctx.jWebClient.verbose) {
                            console.error('Error  : File system error', err['code'], 'while writing challenge data to file');
                        }
                        callback();
                        // dereference
                        callback = null;
                        challenge = null;
                        ctx = null;
                        err = null;
                    }
                    else {
                        // let uri = "http://" + domain + this.well_known_path + challenge["token"]
                        let rl = readline.createInterface(process.stdin, process.stdout);
                        if (ctx.withInteraction) {
                            rl.question('Press enter to proceed', function (answer) {
                                rl.close();
                                callback();
                                // dereference
                                callback = null;
                                challenge = null;
                                ctx = null;
                                rl = null;
                            });
                        }
                        else {
                            rl.close();
                            callback(); // skip interaction prompt if desired
                            // dereference
                            callback = null;
                            challenge = null;
                            ctx = null;
                            rl = null;
                        }
                    }
                });
            }
            else {
                console.error('Error  : Challenge not supported');
                callback();
                // dereference
                callback = null;
                challenge = null;
                ctx = null;
            }
        }
        else {
            console.error('Error  : Invalid challenge response');
            callback();
            // dereference
            callback = null;
            challenge = null;
            ctx = null;
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
        // dereference
        match = null;
        return void 0;
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
            return ans.challenges.filter(function (entry) {
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
        let email = profile.contact.filter(function (entry) {
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
                let ACCOUNT_KEY = base64url.default.encode(hash); // create base64 encoded hash of account key
                let token = challenge['token'];
                // dereference
                challenge = null;
                jwk = null;
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
        let DOMAIN_CSR_DER = base64url.default.encode(csr); // create base64 encoded CSR
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmFjbWVjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUNBLHVDQUFzQztBQUN0QywrQ0FBOEM7QUFDOUMsaUNBQWdDO0FBQ2hDLHlCQUF3QjtBQUN4QixxQ0FBb0M7QUFDcEMsaUZBQTJEO0FBRTNEOzs7Ozs7O0dBT0c7QUFDSCxJQUFJLGtCQUFrQixHQUFHLFVBQVUsR0FBRztJQUNsQyxNQUFNLENBQUMsSUFBSSxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsRUFBRSxNQUFNLENBQUMsQ0FBQTtBQUNsRCxDQUFDLENBQUE7QUFFRDs7Ozs7O0dBTUc7QUFDSDtJQWNJLFlBQVksZUFBZTtRQUN2Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsbUJBQW1CLEdBQUcsRUFBRSxDQUFBO1FBQzdCOzs7O1dBSUc7UUFDSCxJQUFJLENBQUMsVUFBVSxHQUFHLENBQUMsQ0FBQTtRQUNuQjs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLGlCQUFpQixHQUFHLElBQUksQ0FBQTtRQUM3Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsU0FBUyxHQUFHLEVBQUUsQ0FBQTtRQUNuQjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsWUFBWSxHQUFHLGVBQWUsQ0FBQTtRQUNuQzs7OztXQUlHO1FBQ0gsSUFBSSxDQUFDLGtCQUFrQixHQUFHLFlBQVksQ0FBQSxDQUFDLFdBQVc7UUFDbEQ7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLGFBQWEsR0FBRyxJQUFJLENBQUEsQ0FBQyxXQUFXO1FBQ3JDOzs7V0FHRztRQUNILElBQUksQ0FBQyxVQUFVLEdBQUcsSUFBSSx5Q0FBVSxFQUFFLENBQUEsQ0FBQyxlQUFlO1FBQ2xEOzs7V0FHRztRQUNILElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxDQUFBLENBQUMsV0FBVztRQUMv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