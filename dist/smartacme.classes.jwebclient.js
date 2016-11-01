"use strict";
const base64url = require("base64url");
const https = require("https");
let jwa = require('jwa');
const url = require("url");
/**
 * json_to_utf8base64url
 * @private
 * @description convert JSON to base64-url encoded string using UTF-8 encoding
 * @param {Object} obj
 * @return {string}
 * @throws Exception if object cannot be stringified or contains cycle
 */
let json_to_utf8base64url = function (obj) {
    return base64url.default.encode(new Buffer(JSON.stringify(obj), 'utf8'));
};
/**
 * @class JWebClient
 * @constructor
 * @description Implementation of HTTPS-based JSON-Web-Client
 */
class JWebClient {
    constructor() {
        /**
         * @member {Object} module:JWebClient~JWebClient#key_pair
         * @desc User account key pair
         */
        this.key_pair = null; // {Object}
        /**
         * @member {string} module:JWebClient~JWebClient#last_nonce
         * @desc Cached nonce returned with last request
         */
        this.last_nonce = null; // {string}
        /**
         * @member {boolean} module:JWebClient~JWebClient#verbose
         * @desc Determines verbose mode
         */
        this.verbose = false; // {boolean}
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
            key = base64url.default.toBuffer(key['k']);
        }
        // prepare header
        let header = {
            typ: 'JWT',
            alg: alg,
            jwk: jwk,
            nonce: null
        };
        if (nonce !== void 0) {
            header.nonce = nonce;
        }
        // concatenate header and payload
        let input = [
            json_to_utf8base64url(header),
            json_to_utf8base64url(payload)
        ].join('.');
        // sign input
        let hmac = jwa(alg);
        let sig = hmac.sign(input, key);
        // concatenate input and signature
        let output = [
            input,
            sig
        ].join('.');
        // dereference
        header = null;
        hmac = null;
        input = null;
        jwk = null;
        key = null;
        payload = null;
        // output
        return output;
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
            query = ''; // ensure query is string
        }
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        if (typeof errorCallback !== 'function') {
            errorCallback = this.emptyCallback; // ensure callback is function
        }
        // prepare options
        let uri = url.parse(query);
        let options = {
            hostname: uri.hostname,
            port: parseInt(uri.port, 10),
            path: uri.path,
            method: null,
            headers: {}
        };
        if (typeof payload === 'string') {
            options.method = 'POST';
            options.headers = {
                'Content-Type': 'application/jose',
                'Content-Length': payload.length
            };
        }
        else {
            options.method = 'GET';
        }
        // prepare request
        let req = https.request(options, function (res) {
            // receive data
            let data = [];
            res.on('data', function (block) {
                if (block instanceof Buffer) {
                    data.push(block);
                }
            });
            res.on('end', function () {
                let buf = Buffer.concat(data);
                let isJSON = ((res instanceof Object)
                    && (res['headers'] instanceof Object)
                    && (typeof res.headers['content-type'] === 'string')
                    && (res.headers['content-type'].indexOf('json') > -1));
                if (isJSON && buf.length > 0) {
                    try {
                        // convert to JSON
                        let json = JSON.parse(buf.toString('utf8'));
                        callback(json, res);
                    }
                    catch (e) {
                        // error (if empty or invalid JSON)
                        errorCallback(void 0, e);
                    }
                }
                else {
                    callback(buf, res);
                }
            });
        }).on('error', function (e) {
            console.error('Error occured', e);
            // error
            errorCallback(void 0, e);
        });
        // write POST body if payload was specified
        if (typeof payload === 'string') {
            req.write(payload);
        }
        // make request
        req.end();
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        this.request(uri, void 0, function (ans, res) {
            ctx.evaluateStatus(uri, null, ans, res);
            // save replay nonce for later requests
            if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                ctx.last_nonce = res.headers['replay-nonce'];
            }
            callback(ans, res);
            // dereference
            ans = null;
            callback = null;
            ctx = null;
            res = null;
        }, errorCallback);
        // dereference
        errorCallback = null;
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
        let ctx = this;
        if (typeof callback !== 'function') {
            callback = this.emptyCallback; // ensure callback is function
        }
        let key_pair = this.key_pair;
        if (!(key_pair instanceof Object)) {
            key_pair = {}; // ensure key pair is object
        }
        let jwt = this.createJWT(this.last_nonce, payload, 'RS256', key_pair['private_pem'], key_pair['public_jwk']);
        this.request(uri, jwt, (ans, res) => {
            ctx.evaluateStatus(uri, payload, ans, res);
            // save replay nonce for later requests
            if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                ctx.last_nonce = res.headers['replay-nonce'];
            }
            callback(ans, res);
            // dereference
            ans = null;
            callback = null;
            ctx = null;
            key_pair = null;
            payload = null;
            res = null;
        }, errorCallback);
        // dereference
        errorCallback = null;
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
            if ((payload instanceof Object)
                || (typeof payload === 'string')
                || (typeof payload === 'number')
                || (typeof payload === 'boolean')) {
                console.error('Send   :', payload); // what has been sent
            }
        }
        let uri_parsed = url.parse(uri);
        if (res['statusCode'] >= 100 && res['statusCode'] < 400) {
            console.error('HTTP   :', res['statusCode'], uri_parsed.path); // response code if successful
        }
        if (res['statusCode'] >= 400 && res['statusCode'] < 500) {
            console.error('HTTP   :', res['statusCode'], uri_parsed.path); // response code if error
            if (ans instanceof Object) {
                if (typeof ans['detail'] === 'string') {
                    console.error('Message:', ans.detail.split(' :: ').pop()); // error message if any
                }
            }
        }
        if (this.verbose) {
            console.error('Receive:', res['headers']); // received headers
            console.error('Receive:', ans); // received data
        }
        // dereference
        ans = null;
        payload = null;
        res = null;
        uri_parsed = null;
    }
    /**
     * Helper: Empty callback
     */
    emptyCallback() {
        // nop
    }
}
exports.JWebClient = JWebClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuandlYmNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmp3ZWJjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUNBLHVDQUFzQztBQUN0QywrQkFBOEI7QUFDOUIsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO0FBQ3hCLDJCQUEwQjtBQUUxQjs7Ozs7OztHQU9HO0FBQ0gsSUFBSSxxQkFBcUIsR0FBRyxVQUFVLEdBQUc7SUFDckMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxPQUFPLENBQUMsTUFBTSxDQUFDLElBQUksTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLEVBQUUsTUFBTSxDQUFDLENBQUMsQ0FBQTtBQUM1RSxDQUFDLENBQUE7QUFFRDs7OztHQUlHO0FBQ0g7SUFJSTtRQUNJOzs7V0FHRztRQUNILElBQUksQ0FBQyxRQUFRLEdBQUcsSUFBSSxDQUFBLENBQUMsV0FBVztRQUNoQzs7O1dBR0c7UUFDSCxJQUFJLENBQUMsVUFBVSxHQUFHLElBQUksQ0FBQSxDQUFDLFdBQVc7UUFDbEM7OztXQUdHO1FBQ0gsSUFBSSxDQUFDLE9BQU8sR0FBRyxLQUFLLENBQUEsQ0FBQyxZQUFZO0lBQ3JDLENBQUM7SUFFRDs7Ozs7Ozs7O09BU0c7SUFDSCxTQUFTLENBQUMsS0FBSyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLEdBQUc7UUFDbkMsaUJBQWlCO1FBQ2pCLGNBQWM7UUFDZCxFQUFFLENBQUMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztZQUN4QixHQUFHLEdBQUcsU0FBUyxDQUFDLE9BQU8sQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUE7UUFDOUMsQ0FBQztRQUNELGlCQUFpQjtRQUNqQixJQUFJLE1BQU0sR0FBRztZQUNULEdBQUcs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