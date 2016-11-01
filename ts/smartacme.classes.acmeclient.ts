import * as plugins from './smartacme.plugins'
import * as child_process from 'child_process'
import * as crypto from 'crypto'
import * as fs from 'fs'
import * as readline from 'readline'
import { JWebClient } from './smartacme.classes.jwebclient'

/**
 * json_to_utf8buffer
 * @private
 * @description convert JSON to Buffer using UTF-8 encoding
 * @param {Object} obj
 * @return {Buffer}
 * @throws Exception if object cannot be stringified or contains cycle
 */
let json_to_utf8buffer = (obj) => {
    return new Buffer(JSON.stringify(obj), 'utf8')
}

/**
 * @class AcmeClient
 * @constructor
 * @description ACME protocol implementation from client perspective
 * @param {string} directory_url - Address of directory
 * @param {module:JWebClient~JWebClient} jWebClient - Reference to JSON-Web-Client
 */
export class AcmeClient {
    clientProfilePubKey: any
    daysValid: number
    defaultRsaKeySize: number
    directory: any
    directoryUrl: string
    emailDefaultPrefix: string
    emailOverride: string
    jWebClient: any
    regLink: string
    tosLink: string
    webroot: string
    wellKnownPath: string
    withInteraction: boolean
    constructor(directoryUrlArg) {
        /**
         * @member {Object} module:AcmeClient~AcmeClient#clientProfilePubKey
         * @desc Cached public key obtained from profile
         */
        this.clientProfilePubKey = {}
        /**
         * @member {number} module:AcmeClient~AcmeClient#days_valid
         * @desc Validity period in days
         * @default 1
         */
        this.daysValid = 1
        /**
         * @member {number} module:AcmeClient~AcmeClient#defaultRsaKeySize
         * @desc Key strength in bits
         * @default 4096
         */
        this.defaultRsaKeySize = 4096
        /**
         * @member {Object} module:AcmeClient~AcmeClient#directory
         * @desc Hash map of REST URIs
         */
        this.directory = {}
        /**
         * @member {string} module:AcmeClient~AcmeClient#directory_url
         * @desc Address of directory
         */
        this.directoryUrl = directoryUrlArg
        /**
         * @member {string} module:AcmeClient~AcmeClient#emailDefaultPrefix
         * @desc Prefix of email address if constructed from domain name
         * @default "hostmaster"
         */
        this.emailDefaultPrefix = 'hostmaster' // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#emailOverride
         * @desc Email address to use
         */
        this.emailOverride = null // {string}
        /**
         * @member {module:JWebClient~JWebClient} module:AcmeClient~AcmeClient#jWebClient
         * @desc Reference to JSON-Web-Client
         */
        this.jWebClient = new JWebClient() // {JWebClient}
        /**
         * @member {string} module:AcmeClient~AcmeClient#regLink
         * @desc Cached registration URI
         */
        this.regLink = null // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#tosLink
         * @desc Cached terms of service URI
         */
        this.tosLink = null // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#webroot
         * @desc Path to server web root (or path to store challenge data)
         * @default "."
         */
        this.webroot = '.' // {string}
        /**
         * @member {string} module:AcmeClient~AcmeClient#well_known_path
         * @desc Directory structure for challenge data
         * @default "/.well-known/acme-challenge/"
         */
        this.wellKnownPath = '/.well-known/acme-challenge/' // {string}
        /**
         * @member {boolean} module:AcmeClient~AcmeClient#withInteraction
         * @desc Determines if interaction of user is required
         * @default true
         */
        this.withInteraction = true // {boolean}
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
        this.jWebClient.get(this.directoryUrl, callback, callback)
        // dereference
        callback = null
    }

    /**
     * newRegistration
     * @description try to register (directory lookup must have occured prior to execution)
     * @param {Object} payload
     * @param {function} callback - first argument will be the answer object
     */
    newRegistration(payload, callback) {
        if (!(payload instanceof Object)) {
            payload = {} // ensure payload is object
        }
        payload.resource = 'new-reg'
        this.jWebClient.post(this.directory['new-reg'], payload, callback, callback)
        // dereference
        callback = null
        payload = null
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
            payload = {} // ensure payload is object
        }
        payload['resource'] = 'reg'
        if (typeof callback !== 'function') {
            callback = this.emptyCallback // ensure callback is function
        }
        this.jWebClient.post(uri, payload,(ans, res) => {
            if (ans instanceof Object) {
                this.clientProfilePubKey = ans.key // cache or reset returned public key
                if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                    let linkStr = res.headers['link']
                    if (typeof linkStr === 'string') {
                        let tosLink = this.getTosLink(linkStr)
                        if (typeof tosLink === 'string') {
                            this.tosLink = tosLink // cache TOS link
                        } else {
                            this.tosLink = null // reset TOS link
                        }
                    } else {
                        this.tosLink = null // reset TOS link
                    }
                } else {
                    this.tosLink = null // reset TOS link
                }
                callback(ans, res)
            } else {
                callback(false)
            }
        })
        // dereference
        payload = null
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
            callback = this.emptyCallback // ensure callback is function
        }
        this.getProfile((profile) => {
            if (!(profile instanceof Object)) {
                callback(false) // no profile returned
            } else {
                this.jWebClient.post(this.directory['new-authz'], this.makeDomainAuthorizationRequest(domain), (ans, res) => {
                    if ((res instanceof Object) && (res['statusCode'] === 403)) { // if unauthorized
                        this.agreeTos(this.tosLink, (ans_, res_) => { // agree to TOS
                            if ( // if TOS were agreed successfully
                                (res_ instanceof Object)
                                && (res_['statusCode'] >= 200)
                                && (res_['statusCode'] <= 400)
                            ) {
                                this.authorizeDomain(domain, callback)  // try authorization again
                            } else {
                                callback(false) // agreement failed
                            }
                        })
                    } else {
                        if (
                            (res instanceof Object)
                            && (res['headers'] instanceof Object)
                            && (typeof res.headers['location'] === 'string')
                            && (ans instanceof Object)
                        ) {
                            let poll_uri = res.headers['location'] // status URI for polling
                            let challenge = this.selectChallenge(ans, 'http-01') // select simple http challenge
                            if (challenge instanceof Object) { // desired challenge is in list
                                this.prepareChallenge(domain, challenge, () => { // prepare all objects and files for challenge
                                    // reset
                                    ans = null
                                    res = null
                                    // accept challenge
                                    this.acceptChallenge(challenge, (ans, res) => {
                                        if (
                                            (res instanceof Object)
                                            && (res['statusCode'] < 400) // server confirms challenge acceptance
                                        ) {
                                            this.pollUntilValid(poll_uri, callback) // poll status until server states success
                                        } else {
                                            callback(false) // server did not confirm challenge acceptance
                                        }
                                    })
                                })
                            } else {
                                callback(false) // desired challenge is not in list
                            }
                        } else {
                            callback(false) // server did not respond with status URI
                        }
                    }
                })
            }
        })
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
            challenge = {} // ensure challenge is object
        }
        this.jWebClient.post(challenge['uri'], this.makeChallengeResponse(challenge), callback)
        // dereference
        callback = null
        challenge = null
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
            callback = this.emptyCallback // ensure callback is function
        }
        if (retry > 128) {
            callback(false) // stop if retry value exceeds maximum
        } else {
            this.jWebClient.get(uri, (ans, res) => {
                if (!(ans instanceof Object)) {
                    callback(false) // invalid answer
                } else {
                    if (ans['status'] === 'pending') { // still pending
                        setTimeout(() => {
                            this.pollUntilValid(uri, callback, retry * 2) // retry
                        }, retry * 500)
                    } else {
                        callback(ans, res) // challenge complete
                    }
                }
            })
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
            callback = this.emptyCallback // ensure callback is function
        }
        if (retry > 128) {
            callback(false) // stop if retry value exceeds maximum
        } else {
            this.jWebClient.get(uri,(ans, res) => {
                if ((ans instanceof Buffer) && (ans.length > 0)) {
                    callback(ans) // certificate was returned with answer
                } else {
                    if ((res instanceof Object) && (res['statusCode'] < 400)) { // still pending
                        setTimeout(() => {
                            this.pollUntilIssued(uri, callback, retry * 2) // retry
                        }, retry * 500)
                    } else {
                        callback(false) // CSR complete
                    }
                }
            })
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
            callback = this.emptyCallback // ensure callback is function
        }
        fs.readFile(domain + '.csr', (err, csrBuffer: Buffer) => {
            if (err instanceof Object) { // file system error
                if (this.jWebClient.verbose) {
                    console.error('Error  : File system error', err['code'], 'while reading key from file')
                }
                callback(false)
            } else {
                let csr = csrBuffer.toString()
                this.jWebClient.post(this.directory['new-cert'], this.makeCertRequest(csr, this.daysValid), (ans, res) => {
                    if ((ans instanceof Buffer) && (ans.length > 0)) { // answer is buffer
                        callback(ans) // certificate was returned with answer
                    } else {
                        if (res instanceof Object) {
                            if ((res['statusCode'] < 400) && !ans) { // success response, but no answer was provided
                                let headers = res['headers']
                                if (!(headers instanceof Object)) {
                                    headers = {}  // ensure headers is object
                                }
                                this.pollUntilIssued(headers['location'], callback) // poll provided status URI
                                // dereference
                                headers = null
                            } else {
                                callback((res['statusCode'] < 400) ? ans : false) // answer may be provided as string or object
                            }
                        } else {
                            callback(false) // invalid response
                        }
                    }
                })
            }
        })
    }

    /**
     * getProfile
     * @description retrieve profile of user (will make directory lookup and registration check)
     * @param {function} callback - first argument will be the answer object
     */
    getProfile(callback) {
        /*jshint -W069 */
        if (typeof callback !== 'function') {
            callback = this.emptyCallback // ensure callback is function
        }
        this.getDirectory((dir) => {
            if (!(dir instanceof Object)) {
                callback(false) // server did not respond with directory
            } else {
                this.directory = dir // cache directory
                this.newRegistration(null, (ans, res) => { // try new registration to get registration link
                    if (
                        (res instanceof Object)
                        && (res['headers'] instanceof Object)
                        && (typeof res.headers['location'] === 'string')
                    ) {
                        this.regLink = res.headers['location']
                        this.getRegistration(this.regLink, null, callback) // get registration info from link
                    } else {
                        callback(false) // registration failed
                    }
                })
            }
        })
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
                callback = this.emptyCallback // ensure callback is function
            }
            this.newRegistration(
                {
                    contact: [
                        'mailto:' + email
                    ]
                },
                (ans, res) => {
                    if (
                        (res instanceof Object)
                        && (res['statusCode'] === 201)
                        && (res['headers'] instanceof Object)
                        && (typeof res.headers['location'] === 'string')
                    ) {
                        this.regLink = res.headers['location']
                        callback(this.regLink) // registration URI
                    } else {
                        callback(false) // registration failed
                    }
                })
        } else {
            callback(false) // no email address provided
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
        }, callback)
        // dereference
        callback = null
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
            domain = '' // ensure domain is string
        }
        if (typeof callback !== 'function') {
            callback = this.emptyCallback // ensure callback is function
        }
        this.getProfile((profile) => {
            let email = this.extractEmail(profile) // try to determine email address from profile
            if (typeof this.emailOverride === 'string') {
                email = this.emailOverride  // override email address if set
            } else if (typeof email !== 'string') {
                email = this.emailDefaultPrefix + '@' + domain  // or set default
            }
            let bit = this.defaultRsaKeySize
            // sanitize
            bit = Number(bit)
            country = this.makeSafeFileName(country)
            domain = this.makeSafeFileName(domain)
            email = this.makeSafeFileName(email)
            organization = this.makeSafeFileName(organization)
            // create key pair
            this.createKeyPair(bit, country, organization, domain, email, (e) => { // create key pair
                if (!e) {
                    this.requestSigning(domain, (cert) => { // send CSR
                        if ((cert instanceof Buffer) || (typeof cert === 'string')) { // valid certificate data
                            fs.writeFile(domain + '.der', cert, (err) => { // sanitize domain name for file path
                                if (err instanceof Object) { // file system error
                                    if (this.jWebClient.verbose) {
                                        console.error('Error  : File system error', err['code'], 'while writing certificate to file')
                                    }
                                    callback(false)
                                } else {
                                    callback(true)  // CSR complete and certificate written to file system
                                }
                            })
                        } else {
                            callback(false) // invalid certificate data
                        }
                    })
                } else {
                    callback(false) // could not create key pair
                }
            })
        })
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
            callback = this.emptyCallback // ensure callback is function
        }
        let openssl = `openssl req -new -nodes -newkey rsa:${bit} -sha256 -subj "/C=${c}/O=${o}/CN=${cn}/emailAddress=${e}" -keyout \"${cn}.key\" -outform der -out \"${cn}.csr\"`
        console.error('Action : Creating key pair')
        if (this.jWebClient.verbose) {
            console.error('Running:', openssl)
        }
        child_process.exec(openssl, (e) => {
            if (!e) {
                console.error('Result : done')
            } else {
                console.error('Result : failed')
            }
            callback(e)
            // dereference
            callback = null
            e = null
        }
        )
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
            name = ''
        }
        // respects file name restrictions for ntfs and ext2
        let regex_file = '[<>:\"/\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]'
        let regex_path = '[<>:\"\\\\\\|\\?\\*\\u0000-\\u001f\\u007f\\u0080-\\u009f]'
        return name.replace(new RegExp(withPath ? regex_path : regex_file, 'g'), (charToReplace) => {
            if (typeof charToReplace === 'string') {
                return '%' + charToReplace.charCodeAt(0).toString(16).toLocaleUpperCase()
            }
            return '%00'
        })
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
            callback = this.emptyCallback // ensure callback is function
        }
        if (challenge instanceof Object) {
            if (challenge['type'] === 'http-01') { // simple http challenge
                let path = this.webroot + this.wellKnownPath + challenge['token'] // webroot and well_known_path are expected to be already sanitized
                fs.writeFile(path, this.makeKeyAuthorization(challenge), (err) => { // create challenge file
                    if (err instanceof Object) { // file system error
                        if (this.jWebClient.verbose) {
                            console.error(
                                'Error  : File system error',
                                err['code'], 'while writing challenge data to file'
                            )
                        }
                        callback()
                    } else {
                        // let uri = "http://" + domain + this.well_known_path + challenge["token"]
                        let rl = readline.createInterface(process.stdin, process.stdout)
                        if (this.withInteraction) {
                            rl.question('Press enter to proceed', (answer) => { // wait for user to proceed
                                rl.close()
                                callback()
                            })
                        } else {
                            rl.close()
                            callback() // skip interaction prompt if desired
                        }
                    }
                })
            } else { // no supported challenge
                console.error('Error  : Challenge not supported')
                callback()
            }
        } else { // invalid challenge response
            console.error('Error  : Invalid challenge response')
            callback()
        }
    }

    /**
     * Helper: Extract TOS Link, e.g. from "&lt;http://...&gt;;rel="terms-of-service"
     * @param {string} linkStr
     * @return {string}
     */
    getTosLink(linkStr) {
        let match = /(<)([^>]+)(>;rel="terms-of-service")/g.exec(linkStr)
        if ((match instanceof Array) && (match.length > 2)) {
            let result = match[2]
            // dereference
            match = null
            return result
        }
    }

    /**
     * Helper: Select challenge by type
     * @param {Object} ans
     * @param {string} challenge_type
     * @return {Object}
     */
    selectChallenge(ans, challengeType: string) {
        /*jshint -W069 */
        if ((ans instanceof Object) && (ans['challenges'] instanceof Array)) {
            return ans.challenges.filter((entry) => {
                let type = entry['type']
                // dereference
                entry = null
                if (type === challengeType) { // check for type match
                    return true
                }
                return false
            }).pop()
        } // return first match or undefined
        // dereference
        ans = null
        return void 0 // challenges not available or in expected format
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
            profile = null
            return void 0 // invalid profile
        }
        let prefix = 'mailto:'
        let email = profile.contact.filter((entry) => {
            if (typeof entry !== 'string') {
                return false
            } else {
                return !entry.indexOf(prefix) // check for mail prefix
            }
        }
        ).pop()
        // dereference
        profile = null
        if (typeof email !== 'string') {
            return void 0
        } // return default
        return email.substr(prefix.length) // only return email address without protocol prefix
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
        }
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
                }
                )
                let hash = crypto.createHash('sha256').update(jwk.toString('utf8'), 'utf8').digest()
                // create base64 encoded hash of account key
                let ACCOUNT_KEY = plugins.smartstring.base64.encodeUri(hash.toString())
                let token = challenge['token']
                return token + '.' + ACCOUNT_KEY
            }
        } else {
            return '' // return default (for writing to file)
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
        }
    }

    /**
     * Make ACME-Request: CSR - Object: resource, csr, notBefore, notAfter
     * @param {string} csr
     * @param {number} days_valid
     * @return {{resource: string, csr: string, notBefore: string, notAfter: string}}
     */
    makeCertRequest(csr: string, DAYS_VALID: number) {
        if (typeof csr !== 'string' && !(csr instanceof Buffer)) {
            csr = '' // default string for CSR
        }
        if ((typeof DAYS_VALID !== 'number') || (isNaN(DAYS_VALID)) || (DAYS_VALID === 0)) {
            DAYS_VALID = 1 // default validity duration (1 day)
        }
        let DOMAIN_CSR_DER = plugins.smartstring.base64.encodeUri(csr) // create base64 encoded CSR
        let CURRENT_DATE = (new Date()).toISOString() // set start date to current date

        // set end date to current date + days_valid
        let NOTAFTER_DATE = (new Date((+new Date()) + 1000 * 60 * 60 * 24 * Math.abs(DAYS_VALID))).toISOString()
        return {
            'resource': 'new-cert',
            'csr': DOMAIN_CSR_DER,
            'notBefore': CURRENT_DATE,
            'notAfter': NOTAFTER_DATE
        }
    }
}
