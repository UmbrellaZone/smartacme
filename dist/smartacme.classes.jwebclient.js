"use strict";
const plugins = require("./smartacme.plugins");
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
         * @member {Object} module:JWebClient~JWebClient#key_pair
         * @desc User account key pair
         */
        this.key_pair = {};
        /**
         * @member {string} module:JWebClient~JWebClient#last_nonce
         * @desc Cached nonce returned with last request
         */
        this.last_nonce = null;
        /**
         * @member {boolean} module:JWebClient~JWebClient#verbose
         * @desc Determines verbose mode
         */
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
        let jwt = this.createJWT(this.last_nonce, payload, 'RS256', this.key_pair['private_pem'], this.key_pair['public_jwk']);
        this.request(uri, jwt, (ans, res) => {
            ctx.evaluateStatus(uri, payload, ans, res);
            // save replay nonce for later requests
            if ((res instanceof Object) && (res['headers'] instanceof Object)) {
                ctx.last_nonce = res.headers['replay-nonce'];
            }
            callback(ans, res);
        }, errorCallback);
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
    }
    /**
     * Helper: Empty callback
     */
    emptyCallback() {
        // nop
    }
}
exports.JWebClient = JWebClient;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuandlYmNsaWVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL3NtYXJ0YWNtZS5jbGFzc2VzLmp3ZWJjbGllbnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLCtDQUE4QztBQUM5QywrQkFBOEI7QUFDOUIsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO0FBQ3hCLDJCQUEwQjtBQUUxQjs7Ozs7OztHQU9HO0FBQ0gsSUFBSSxxQkFBcUIsR0FBRyxVQUFVLEdBQUc7SUFDckMsTUFBTSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUE7QUFDcEUsQ0FBQyxDQUFBO0FBRUQ7Ozs7R0FJRztBQUNIO0lBSUk7UUFDSTs7O1dBR0c7UUFDSCxJQUFJLENBQUMsUUFBUSxHQUFHLEVBQUUsQ0FBQTtRQUNsQjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsVUFBVSxHQUFHLElBQUksQ0FBQTtRQUN0Qjs7O1dBR0c7UUFDSCxJQUFJLENBQUMsT0FBTyxHQUFHLEtBQUssQ0FBQTtJQUN4QixDQUFDO0lBRUQ7Ozs7Ozs7OztPQVNHO0lBQ0gsU0FBUyxDQUFDLEtBQUssRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLEdBQUcsRUFBRSxHQUFHO1FBQ25DLGlCQUFpQjtRQUNqQixjQUFjO1FBQ2QsRUFBRSxDQUFDLENBQUMsR0FBRyxZQUFZLE1BQU0sQ0FBQyxDQUFDLENBQUM7WUFDeEIsR0FBRyxHQUFHLElBQUksTUFBTSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFBO1FBQ2pFLENBQUM7UUFDRCxpQkFBaUI7UUFDakIsSUFBSSxNQUFNLEdBQUc7WUFDVCxHQUFHLEVBQUUsS0FBSztZQUNWLEdBQUcsRUFBRSxHQUFHO1lBQ1IsR0FBRyxFQUFFLEdBQUc7WUFDUixLQUFLLEVBQUUsSUFBSTtTQUNkLENBQUE7UUFFRCxFQUFFLENBQUMsQ0FBQyxLQUFLLEtBQUssS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ25CLE1BQU0sQ0FBQyxLQUFLLEdBQUcsS0FBSyxDQUFBO1FBQ3hCLENBQUM7UUFDRCxpQ0FBaUM7UUFDakMsSUFBSSxLQUFLLEdBQUc7WUFDUixxQkFBcUIsQ0FBQyxNQUFNLENBQUM7WUFDN0IscUJBQXFCLENBQUMsT0FBTyxDQUFDO1NBQ2pDLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQ1gsYUFBYTtRQUNiLElBQUksSUFBSSxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUNuQixJQUFJLEdBQUcsR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLEtBQUssRUFBRSxHQUFHLENBQUMsQ0FBQTtRQUMvQixrQ0FBa0M7UUFDbEMsSUFBSSxNQUFNLEdBQUc7WUFDVCxLQUFLO1lBQ0wsR0FBRztTQUNOLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQ1gsU0FBUztRQUNULE1BQU0sQ0FBQyxNQUFNLENBQUE7SUFDakIsQ0FBQztJQUVEOzs7Ozs7O09BT0c7SUFDSCxPQUFPLENBQUMsS0FBSyxFQUFFLE9BQU8sRUFBRSxRQUFRLEVBQUUsYUFBYTtRQUMzQyxpQkFBaUI7UUFDakIsRUFBRSxDQUFDLENBQUMsT0FBTyxLQUFLLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQztZQUM1QixLQUFLLEdBQUcsRUFBRSxDQUFBLENBQUMseUJBQXlCO1FBQ3hDLENBQUM7UUFDRCxFQUFFLENBQUMsQ0FBQyxPQUFPLFFBQVEsS0FBSyxVQUFVLENBQUMsQ0FBQyxDQUFDO1lBQ2pDLFFBQVEsR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFBLENBQUMsOEJBQThCO1FBQ2hFLENBQUM7UUFDRCxFQUFFLENBQUMsQ0FBQyxPQUFPLGFBQWEsS0FBSyxVQUFVLENBQUMsQ0FBQyxDQUFDO1lBQ3RDLGFBQWEsR0FBRyxJQUFJLENBQUMsYUFBYSxDQUFBLENBQUMsOEJBQThCO1FBQ3JFLENBQUM7UUFDRCxrQkFBa0I7UUFDbEIsSUFBSSxHQUFHLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUMxQixJQUFJLE9BQU8sR0FBRztZQUNWLFFBQVEsRUFBRSxHQUFHLENBQUMsUUFBUTtZQUN0QixJQUFJLEVBQUUsUUFBUSxDQUFDLEdBQUcsQ0FBQyxJQUFJLEVBQUUsRUFBRSxDQUFDO1lBQzVCLElBQUksRUFBRSxHQUFHLENBQUMsSUFBSTtZQUNkLE1BQU0sRUFBRSxJQUFJO1lBQ1osT0FBTyxFQUFFLEVBQUU7U0FDZCxDQUFBO1FBQ0QsRUFBRSxDQUFDLENBQUMsT0FBTyxPQUFPLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQztZQUM5QixPQUFPLENBQUMsTUFBTSxHQUFHLE1BQU0sQ0FBQTtZQUN2QixPQUFPLENBQUMsT0FBTyxHQUFHO2dCQUNkLGNBQWMsRUFBRSxrQkFBa0I7Z0JBQ2xDLGdCQUFnQixFQUFFLE9BQU8sQ0FBQyxNQUFNO2FBQ25DLENBQUE7UUFDTCxDQUFDO1FBQUMsSUFBSSxDQUFDLENBQUM7WUFDSixPQUFPLENBQUMsTUFBTSxHQUFHLEtBQUssQ0FBQTtRQUMxQixDQUFDO1FBQ0Qsa0JBQWtCO1FBQ2xCLElBQUksR0FBRyxHQUFHLEtBQUssQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFLFVBQVUsR0FBRztZQUMxQyxlQUFlO1lBQ2YsSUFBSSxJQUFJLEdBQUcsRUFBRSxDQUFBO1lBQ2IsR0FBRyxDQUFDLEVBQUUsQ0FBQyxNQUFNLEVBQUUsVUFBVSxLQUFLO2dCQUMxQixFQUFFLENBQUMsQ0FBQyxLQUFLLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztvQkFDMUIsSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsQ0FBQTtnQkFDcEIsQ0FBQztZQUNMLENBQUMsQ0FBQyxDQUFBO1lBQ0YsR0FBRyxDQUFDLEVBQUUsQ0FBQyxLQUFLLEVBQUU7Z0JBQ1YsSUFBSSxHQUFHLEdBQUcsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQTtnQkFDN0IsSUFBSSxNQUFNLEdBQUcsQ0FDVCxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUM7dUJBQ3BCLENBQUMsR0FBRyxDQUFDLFNBQVMsQ0FBQyxZQUFZLE1BQU0sQ0FBQzt1QkFDbEMsQ0FBQyxPQUFPLEdBQUcsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLEtBQUssUUFBUSxDQUFDO3VCQUNqRCxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQ3hELENBQUE7Z0JBQ0QsRUFBRSxDQUFDLENBQUMsTUFBTSxJQUFJLEdBQUcsQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQztvQkFDM0IsSUFBSSxDQUFDO3dCQUNELGtCQUFrQjt3QkFDbEIsSUFBSSxJQUFJLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsUUFBUSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUE7d0JBQzNDLFFBQVEsQ0FBQyxJQUFJLEVBQUUsR0FBRyxDQUFDLENBQUE7b0JBQ3ZCLENBQUU7b0JBQUEsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQzt3QkFDVCxtQ0FBbUM7d0JBQ25DLGFBQWEsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQTtvQkFDNUIsQ0FBQztnQkFDTCxDQUFDO2dCQUFDLElBQUksQ0FBQyxDQUFDO29CQUNKLFFBQVEsQ0FBQyxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUE7Z0JBQ3RCLENBQUM7WUFDTCxDQUFDLENBQUMsQ0FBQTtRQUNOLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxPQUFPLEVBQUUsVUFBVSxDQUFDO1lBQ3RCLE9BQU8sQ0FBQyxLQUFLLENBQUMsZUFBZSxFQUFFLENBQUMsQ0FBQyxDQUFBO1lBQ2pDLFFBQVE7WUFDUixhQUFhLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUE7UUFDNUIsQ0FBQyxDQUFDLENBQUE7UUFDRiwyQ0FBMkM7UUFDM0MsRUFBRSxDQUFDLENBQUMsT0FBTyxPQUFPLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQztZQUM5QixHQUFHLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFBO1FBQ3RCLENBQUM7UUFDRCxlQUFlO1FBQ2YsR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFBO0lBQ2IsQ0FBQztJQUVEOzs7Ozs7T0FNRztJQUNILEdBQUcsQ0FBQyxHQUFHLEVBQUUsUUFBUSxFQUFFLGFBQWE7UUFDNUIsaUJBQWlCO1FBQ2pCLElBQUksR0FBRyxHQUFHLElBQUksQ0FBQTtRQUNkLEVBQUUsQ0FBQyxDQUFDLE9BQU8sUUFBUSxLQUFLLFVBQVUsQ0FBQyxDQUFDLENBQUM7WUFDakMsUUFBUSxHQUFHLElBQUksQ0FBQyxhQUFhLENBQUEsQ0FBQyw4QkFBOEI7UUFDaEUsQ0FBQztRQUNELElBQUksQ0FBQyxPQUFPLENBQUMsR0FBRyxFQUFFLEtBQUssQ0FBQyxFQUFFLFVBQVUsR0FBRyxFQUFFLEdBQUc7WUFDeEMsR0FBRyxDQUFDLGNBQWMsQ0FBQyxHQUFHLEVBQUUsSUFBSSxFQUFFLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQTtZQUN2Qyx1Q0FBdUM7WUFDdkMsRUFBRSxDQUFDLENBQUMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsU0FBUyxDQUFDLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQyxDQUFDO2dCQUNoRSxHQUFHLENBQUMsVUFBVSxHQUFHLEdBQUcsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLENBQUE7WUFDaEQsQ0FBQztZQUNELFFBQVEsQ0FBQyxHQUFHLEVBQUUsR0FBRyxDQUFDLENBQUE7WUFDbEIsY0FBYztZQUNkLEdBQUcsR0FBRyxJQUFJLENBQUE7WUFDVixRQUFRLEdBQUcsSUFBSSxDQUFBO1lBQ2YsR0FBRyxHQUFHLElBQUksQ0FBQTtZQUNWLEdBQUcsR0FBRyxJQUFJLENBQUE7UUFDZCxDQUFDLEVBQUUsYUFBYSxDQUFDLENBQUE7UUFDakIsY0FBYztRQUNkLGFBQWEsR0FBRyxJQUFJLENBQUE7SUFDeEIsQ0FBQztJQUVEOzs7Ozs7O09BT0c7SUFDSCxJQUFJLENBQUMsR0FBRyxFQUFFLE9BQU8sRUFBRSxRQUFRLEVBQUUsYUFBYTtRQUN0QyxpQkFBaUI7UUFDakIsSUFBSSxHQUFHLEdBQUcsSUFBSSxDQUFBO1FBQ2QsRUFBRSxDQUFDLENBQUMsT0FBTyxRQUFRLEtBQUssVUFBVSxDQUFDLENBQUMsQ0FBQztZQUNqQyxRQUFRLEdBQUcsSUFBSSxDQUFDLGFBQWEsQ0FBQSxDQUFDLDhCQUE4QjtRQUNoRSxDQUFDO1FBQ0QsSUFBSSxHQUFHLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FDcEIsSUFBSSxDQUFDLFVBQVUsRUFDZixPQUFPLEVBQ1AsT0FBTyxFQUNQLElBQUksQ0FBQyxRQUFRLENBQUMsYUFBYSxDQUFDLEVBQzVCLElBQUksQ0FBQyxRQUFRLENBQUMsWUFBWSxDQUFDLENBQUMsQ0FBQTtRQUNoQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxHQUFHLEVBQUUsQ0FBQyxHQUFHLEVBQUUsR0FBRztZQUM1QixHQUFHLENBQUMsY0FBYyxDQUFDLEdBQUcsRUFBRSxPQUFPLEVBQUUsR0FBRyxFQUFFLEdBQUcsQ0FBQyxDQUFBO1lBQzFDLHVDQUF1QztZQUN2QyxFQUFFLENBQUMsQ0FBQyxDQUFDLEdBQUcsWUFBWSxNQUFNLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQyxTQUFTLENBQUMsWUFBWSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7Z0JBQ2hFLEdBQUcsQ0FBQyxVQUFVLEdBQUcsR0FBRyxDQUFDLE9BQU8sQ0FBQyxjQUFjLENBQUMsQ0FBQTtZQUNoRCxDQUFDO1lBQ0QsUUFBUSxDQUFDLEdBQUcsRUFBRSxHQUFHLENBQUMsQ0FBQTtRQUN0QixDQUFDLEVBQUUsYUFBYSxDQUFFLENBQUE7SUFDdEIsQ0FBQztJQUVEOzs7Ozs7O09BT0c7SUFDSCxjQUFjLENBQUMsR0FBRyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsR0FBRztRQUNqQyxpQkFBaUI7UUFDakIsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUM7WUFDZixFQUFFLENBQUMsQ0FDQyxDQUFDLE9BQU8sWUFBWSxNQUFNLENBQUM7bUJBQ3hCLENBQUMsT0FBTyxPQUFPLEtBQUssUUFBUSxDQUFDO21CQUM3QixDQUFDLE9BQU8sT0FBTyxLQUFLLFFBQVEsQ0FBQzttQkFDN0IsQ0FBQyxPQUFPLE9BQU8sS0FBSyxTQUFTLENBQ3BDLENBQUMsQ0FBQyxDQUFDO2dCQUNDLE9BQU8sQ0FBQyxLQUFLLENBQUMsVUFBVSxFQUFFLE9BQU8sQ0FBQyxDQUFBLENBQUMscUJBQXFCO1lBQzVELENBQUM7UUFDTCxDQUFDO1FBQ0QsSUFBSSxVQUFVLEdBQUcsR0FBRyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUMvQixFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsWUFBWSxDQUFDLElBQUksR0FBRyxJQUFJLEdBQUcsQ0FBQyxZQUFZLENBQUMsR0FBRyxHQUFHLENBQUMsQ0FBQyxDQUFDO1lBQ3RELE9BQU8sQ0FBQyxLQUFLLENBQUMsVUFBVSxFQUFFLEdBQUcsQ0FBQyxZQUFZLENBQUMsRUFBRSxVQUFVLENBQUMsSUFBSSxDQUFDLENBQUEsQ0FBQyw4QkFBOEI7UUFDaEcsQ0FBQztRQUNELEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxZQUFZLENBQUMsSUFBSSxHQUFHLElBQUksR0FBRyxDQUFDLFlBQVksQ0FBQyxHQUFHLEdBQUcsQ0FBQyxDQUFDLENBQUM7WUFDdEQsT0FBTyxDQUFDLEtBQUssQ0FBQyxVQUFVLEVBQUUsR0FBRyxDQUFDLFlBQVksQ0FBQyxFQUFFLFVBQVUsQ0FBQyxJQUFJLENBQUMsQ0FBQSxDQUFDLHlCQUF5QjtZQUN2RixFQUFFLENBQUMsQ0FBQyxHQUFHLFlBQVksTUFBTSxDQUFDLENBQUMsQ0FBQztnQkFDeEIsRUFBRSxDQUFDLENBQUMsT0FBTyxHQUFHLENBQUMsUUFBUSxDQUFDLEtBQUssUUFBUSxDQUFDLENBQUMsQ0FBQztvQkFDcEMsT0FBTyxDQUFDLEtBQUssQ0FBQyxVQUFVLEVBQUUsR0FBRyxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQSxDQUFDLHVCQUF1QjtnQkFDckYsQ0FBQztZQUNMLENBQUM7UUFDTCxDQUFDO1FBQ0QsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUM7WUFDZixPQUFPLENBQUMsS0FBSyxDQUFDLFVBQVUsRUFBRSxHQUFHLENBQUMsU0FBUyxDQUFDLENBQUMsQ0FBQSxDQUFDLG1CQUFtQjtZQUM3RCxPQUFPLENBQUMsS0FBSyxDQUFDLFVBQVUsRUFBRSxHQUFHLENBQUMsQ0FBQSxDQUFDLGdCQUFnQjtRQUNuRCxDQUFDO0lBQ0wsQ0FBQztJQUVEOztPQUVHO0lBQ0gsYUFBYTtRQUNULE1BQU07SUFDVixDQUFDO0NBQ0o7QUExUEQsZ0NBMFBDIn0=