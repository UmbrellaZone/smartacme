"use strict";
const plugins = require("./smartacme.plugins");
const https = require("https");
let jwa = require('jwa');
const url = require("url");
const q = require("q");
/**
 * json_to_utf8base64url
 * @private
 * @description convert JSON to base64-url encoded string using UTF-8 encoding
 * @param {Object} obj
 * @return {string}
 * @throws Exception if object cannot be stringified or contains cycle
 */
let json_to_utf8base64url = (obj) => {
    return plugins.smartstring.base64.encodeUri(JSON.stringify(obj));
};
/**
 * @class JWebClient
 * @constructor
 * @description Implementation of HTTPS-based JSON-Web-Client
 */
class JWebClient {
    constructor() {
        /**
         * User account key pair
         */
        this.keyPair = {};
        /**
         * Cached nonce returned with last request
         */
        this.lastNonce = null;
        this.verbose = false;
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
            key = new Buffer(plugins.smartstring.base64.decode(key['k']));
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
    request(query, payload = null) {
        let done = q.defer();
        // prepare options
        let uri = url.parse(query);
        let options = {
            hostname: uri.hostname,
            port: parseInt(uri.port, 10),
            path: uri.path,
            method: null,
            headers: {}
        };
        if (!payload === null) {
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
        let req = https.request(options, (res) => {
            // receive data
            let data = [];
            res.on('data', (block) => {
                if (block instanceof Buffer) {
                    data.push(block);
                }
            });
            res.on('end', () => {
                let buf = Buffer.concat(data);
                let isJSON = ((res instanceof Object)
                    && (res['headers'] instanceof Object)
                    && (typeof res.headers['content-type'] === 'string')
                    && (res.headers['content-type'].indexOf('json') > -1));
                if (isJSON && buf.length > 0) {
                    try {
                        // convert to JSON
                        let json = JSON.parse(buf.toString('utf8'));
                        done.resolve({ json: json, res: res });
                    }
                    catch (e) {
                        // error (if empty or invalid JSON)
                        done.reject(e);
                    }
                }
            });
        }).on('error', (e) => {
            console.error('Error occured', e);
            // error
            done.reject(e);
        });
        // write POST body if payload was specified
        if (!payload === null) {
            req.write(payload);
        }
        // make request
        req.end();
        return done.promise;
    }
    /**
     * get
     * @description make GET request
     * @param {string} uri
     * @param {function} callback
     * @param {function} errorCallback
     */
    get(uri) {
        let done = q.defer();
        this.request(uri)
            .then((reqResArg) => {
            this.evaluateStatus(uri, null, reqResArg.ans, reqResArg.res);
            // save replay nonce for later requests
            if ((reqResArg.res instanceof Object) && (reqResArg.res['headers'] instanceof Object)) {
                this.lastNonce = reqResArg.res.headers['replay-nonce'];
            }
            done.resolve(reqResArg);
        });
        return done.promise;
    }
    /**
     * make POST request
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {function} callback
     * @param {function} errorCallback
     */
    post(uri, payload) {
        let done = q.defer();
        let jwt = this.createJWT(this.lastNonce, payload, 'RS256', this.keyPair['private_pem'], this.keyPair['public_jwk']);
        this.request(uri, jwt)
            .then((reqResArg) => {
            this.evaluateStatus(uri, payload, reqResArg.ans, reqResArg.res);
            // save replay nonce for later requests
            if ((reqResArg.res instanceof Object) && (reqResArg.res['headers'] instanceof Object)) {
                this.lastNonce = reqResArg.res.headers['replay-nonce'];
            }
            done.resolve(reqResArg);
        });
        return done.promise;
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
    }
}
exports.JWebClient = JWebClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuandlYmNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmp3ZWJjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLCtDQUE4QztBQUM5QywrQkFBOEI7QUFDOUIsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO0FBQ3hCLDJCQUEwQjtBQUMxQix1QkFBc0I7QUFPdEI7Ozs7Ozs7R0FPRztBQUNILElBQUkscUJBQXFCLEdBQUcsQ0FBQyxHQUFHO0lBQzVCLE1BQU0sQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFBO0FBQ3BFLENBQUMsQ0FBQTtBQUVEOzs7O0dBSUc7QUFDSDtJQWdCSTtRQWZBOztXQUVHO1FBQ0gsWUFBTyxHQUFRLEVBQUUsQ0FBQTtRQUVqQjs7V0FFRztRQUNILGNBQVMsR0FBVyxJQUFJLENBQUE7UUFRcEIsSUFBSSxDQUFDLE9BQU8sR0FBRyxLQUFLLENBQUE7SUFDeEIsQ0FBQztJQUVEOzs7Ozs7Ozs7T0FTRztJQUNILFNBQVMsQ0FBQyxLQUFLLEVBQUUsT0FBTyxFQUFFLEdBQUcsRUFBRSxHQUFHLEVBQUUsR0FBRztRQUNuQyxpQkFBaUI7UUFDakIsY0FBYztRQUNkLEVBQUUsQ0FBQyxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUMsQ0FBQyxDQUFDO1lBQ3hCLEdBQUcsR0FBRyxJQUFJLE1BQU0sQ0FBQyxPQUFPLENBQUMsV0FBVyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUNqRSxDQUFDO1FBQ0QsaUJBQWlCO1FBQ2pCLElBQUksTUFBTSxHQUFHO1lBQ1QsR0FBRyxFQUFFLEtBQUs7WUFDVixHQUFHLEVBQUUsR0FBRztZQUNSLEdBQUcs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