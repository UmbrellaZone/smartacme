import * as plugins from './smartacme.plugins'
import * as https from 'https'
let jwa = require('jwa')
import * as url from 'url'

/**
 * json_to_utf8base64url
 * @private
 * @description convert JSON to base64-url encoded string using UTF-8 encoding
 * @param {Object} obj
 * @return {string}
 * @throws Exception if object cannot be stringified or contains cycle
 */
let json_to_utf8base64url = function (obj) {
    return plugins.smartstring.base64.encodeUri(JSON.stringify(obj))
}

/**
 * @class JWebClient
 * @constructor
 * @description Implementation of HTTPS-based JSON-Web-Client
 */
export class JWebClient {
    key_pair: any
    last_nonce: string
    verbose: boolean
    constructor() {
        /**
         * @member {Object} module:JWebClient~JWebClient#key_pair
         * @desc User account key pair
         */
        this.key_pair = {}
        /**
         * @member {string} module:JWebClient~JWebClient#last_nonce
         * @desc Cached nonce returned with last request
         */
        this.last_nonce = null
        /**
         * @member {boolean} module:JWebClient~JWebClient#verbose
         * @desc Determines verbose mode
         */
        this.verbose = false
    }

    /**
     * createJWT
     * @description create JSON-Web-Token signed object
     * @param {string|undefined} nonce
     * @param {Object|string|number|boolean} payload
     * @param {string} alg
     * @param {Object|string} key
     * @param {Object} jwk
     * @return {string}
     */
    createJWT(nonce, payload, alg, key, jwk) {
        /*jshint -W069 */
        // prepare key
        if (key instanceof Object) {
            key = new Buffer(plugins.smartstring.base64.decode(key['k']))
        }
        // prepare header
        let header = {
            typ: 'JWT',
            alg: alg,
            jwk: jwk,
            nonce: null
        }

        if (nonce !== void 0) {
            header.nonce = nonce
        }
        // concatenate header and payload
        let input = [
            json_to_utf8base64url(header),
            json_to_utf8base64url(payload)
        ].join('.')
        // sign input
        let hmac = jwa(alg)
        let sig = hmac.sign(input, key)
        // concatenate input and signature
        let output = [
            input,
            sig
        ].join('.')
        // output
        return output
    }

    /**
     * request
     * @description make GET or POST request over HTTPS and use JOSE as payload type
     * @param {string} query
     * @param {string} payload
     * @param {function} callback
     * @param {function} errorCallback
     */
    request(query, payload, callback, errorCallback) {
        /*jshint -W069 */
        if (typeof query !== 'string') {
            query = '' // ensure query is string
        }
        if (typeof callback !== 'function') {
            callback = this.emptyCallback // ensure callback is function
        }
        if (typeof errorCallback !== 'function') {
            errorCallback = this.emptyCallback // ensure callback is function
        }
        // prepare options
        let uri = url.parse(query)
        let options = {
            hostname: uri.hostname,
            port: parseInt(uri.port, 10),
            path: uri.path,
            method: null,
            headers: {}
        }
        if (typeof payload === 'string') {
            options.method = 'POST'
            options.headers = {
                'Content-Type': 'application/jose',
                'Content-Length': payload.length
            }
        } else {
            options.method = 'GET'
        }
        // prepare request
        let req = https.request(options, function (res) {
            // receive data
            let data = []
            res.on('data', function (block) {
                if (block instanceof Buffer) {
                    data.push(block)
                }
            })
            res.on('end', function () {
                let buf = Buffer.concat(data)
                let isJSON = (
                    (res instanceof Object)
                    && (res['headers'] instanceof Object)
                    && (typeof res.headers['content-type'] === 'string')
                    && (res.headers['content-type'].indexOf('json') > -1)
                )
                if (isJSON && buf.length > 0) {
                    try {
                        // convert to JSON
                        let json = JSON.parse(buf.toString('utf8'))
                        callback(json, res)
                    } catch (e) {
                        // error (if empty or invalid JSON)
                        errorCallback(void 0, e)
                    }
                } else {
                    callback(buf, res)
                }
            })
        }).on('error', function (e) {
            console.error('Error occured', e)
            // error
            errorCallback(void 0, e)
        })
        // write POST body if payload was specified
        if (typeof payload === 'string') {
            req.write(payload)
        }
        // make request
        req.end()
    }

    /**
     * get
     * @description make GET request
     * @param {string} uri
     * @param {function} callback
     * @param {function} errorCallback
     */
    get(uri, callback, errorCallback) {
        /*jshint -W069 */
        let ctx = this
        if (typeof callback !== 'function') {
            callback = this.emptyCallback // ensure callback is function
        }
        this.request(uri, void 0, function (ans, res) {
            ctx.evaluateStatus(uri, null, ans, res)
            // save replay nonce for later requests
            if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                ctx.last_nonce = res.headers['replay-nonce']
            }
            callback(ans, res)
            // dereference
            ans = null
            callback = null
            ctx = null
            res = null
        }, errorCallback)
        // dereference
        errorCallback = null
    }

    /**
     * post
     * @description make POST request
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {function} callback
     * @param {function} errorCallback
     */
    post(uri, payload, callback, errorCallback) {
        /*jshint -W069 */
        let ctx = this
        if (typeof callback !== 'function') {
            callback = this.emptyCallback // ensure callback is function
        }
        let jwt = this.createJWT(
            this.last_nonce,
            payload,
            'RS256',
            this.key_pair['private_pem'],
            this.key_pair['public_jwk'])
        this.request(uri, jwt, (ans, res) => {
            ctx.evaluateStatus(uri, payload, ans, res)
            // save replay nonce for later requests
            if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                ctx.last_nonce = res.headers['replay-nonce']
            }
            callback(ans, res)
        }, errorCallback )
    }

    /**
     * evaluateStatus
     * @description check if status is expected and log errors
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {Object|string} ans
     * @param {Object} res
     */
    evaluateStatus(uri, payload, ans, res) {
        /*jshint -W069 */
        if (this.verbose) {
            if (
                (payload instanceof Object)
                || (typeof payload === 'string')
                || (typeof payload === 'number')
                || (typeof payload === 'boolean')
            ) {
                console.error('Send   :', payload) // what has been sent
            }
        }
        let uri_parsed = url.parse(uri)
        if (res['statusCode'] >= 100 && res['statusCode'] < 400) {
            console.error('HTTP   :', res['statusCode'], uri_parsed.path) // response code if successful
        }
        if (res['statusCode'] >= 400 && res['statusCode'] < 500) {
            console.error('HTTP   :', res['statusCode'], uri_parsed.path) // response code if error
            if (ans instanceof Object) {
                if (typeof ans['detail'] === 'string') {
                    console.error('Message:', ans.detail.split(' :: ').pop()) // error message if any
                }
            }
        }
        if (this.verbose) {
            console.error('Receive:', res['headers']) // received headers
            console.error('Receive:', ans) // received data
        }
    }

    /**
     * Helper: Empty callback
     */
    emptyCallback() {
        // nop
    }
}
