import * as plugins from './smartacme.plugins'
import * as https from 'https'
let jwa = require('jwa')
import * as url from 'url'
import * as q from 'q'

export interface IReqResArg {
    ans: any
    res: any
}

/**
 * json_to_utf8base64url
 * @private
 * @description convert JSON to base64-url encoded string using UTF-8 encoding
 * @param {Object} obj
 * @return {string}
 * @throws Exception if object cannot be stringified or contains cycle
 */
let json_to_utf8base64url = (obj) => {
    return plugins.smartstring.base64.encodeUri(JSON.stringify(obj))
}

/**
 * @class JWebClient
 * @constructor
 * @description Implementation of HTTPS-based JSON-Web-Client
 */
export class JWebClient {
    /**
     * User account key pair
     */
    keyPair: any = {}

    /**
     * Cached nonce returned with last request
     */
    lastNonce: string = null

    /**
     * @member {boolean} module:JWebClient~JWebClient#verbose
     * @desc Determines verbose mode
     */
    verbose: boolean
    constructor() {
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
    request(query: string, payload: string = null) {
        let done = q.defer()
        // prepare options
        let uri = url.parse(query)
        let options = {
            hostname: uri.hostname,
            port: parseInt(uri.port, 10),
            path: uri.path,
            method: null,
            headers: {}
        }
        if (!payload === null) {
            options.method = 'POST'
            options.headers = {
                'Content-Type': 'application/jose',
                'Content-Length': payload.length
            }
        } else {
            options.method = 'GET'
        }
        // prepare request
        let req = https.request(options, (res) => {
            // receive data
            let data = []
            res.on('data', (block) => {
                if (block instanceof Buffer) {
                    data.push(block)
                }
            })
            res.on('end', () => {
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
                        done.resolve({ json: json, res: res })
                    } catch (e) {
                        // error (if empty or invalid JSON)
                        done.reject(e)
                    }
                }
            })
        }).on('error', (e) => {
            console.error('Error occured', e)
            // error
            done.reject(e)
        })
        // write POST body if payload was specified
        if (!payload === null) {
            req.write(payload)
        }
        // make request
        req.end()
        return done.promise
    }

    /**
     * get
     * @description make GET request
     * @param {string} uri
     * @param {function} callback
     * @param {function} errorCallback
     */
    get(uri: string) {
        let done = q.defer<IReqResArg>()
        this.request(uri)
            .then((reqResArg: IReqResArg) => {
                this.evaluateStatus(uri, null, reqResArg.ans, reqResArg.res)
                // save replay nonce for later requests
                if ((reqResArg.res instanceof Object) && (reqResArg.res['headers'] instanceof Object)) {
                    this.lastNonce = reqResArg.res.headers['replay-nonce']
                }
                done.resolve(reqResArg)
            })
        return done.promise
    }

    /**
     * make POST request
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {function} callback
     * @param {function} errorCallback
     */
    post(uri: string, payload) {
        let done = q.defer<IReqResArg>()
        let jwt = this.createJWT(
            this.lastNonce,
            payload,
            'RS256',
            this.keyPair['private_pem'],
            this.keyPair['public_jwk'])
        this.request(uri, jwt)
            .then((reqResArg: IReqResArg) => {
                this.evaluateStatus(uri, payload, reqResArg.ans, reqResArg.res)
                // save replay nonce for later requests
                if ((reqResArg.res instanceof Object) && (reqResArg.res['headers'] instanceof Object)) {
                    this.lastNonce = reqResArg.res.headers['replay-nonce']
                }
                done.resolve(reqResArg)
            })
        return done.promise
    }

    /**
     * checks if status is expected and log errors
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {Object|string} ans
     * @param {Object} res
     */
    evaluateStatus(uri, payload, ans, res) {
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
}
