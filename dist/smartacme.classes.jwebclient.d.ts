/**
 * @class JWebClient
 * @constructor
 * @description Implementation of HTTPS-based JSON-Web-Client
 */
export declare class JWebClient {
    key_pair: any;
    last_nonce: string;
    verbose: boolean;
    constructor();
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
    createJWT(nonce: any, payload: any, alg: any, key: any, jwk: any): string;
    /**
     * request
     * @description make GET or POST request over HTTPS and use JOSE as payload type
     * @param {string} query
     * @param {string} payload
     * @param {function} callback
     * @param {function} errorCallback
     */
    request(query: any, payload: any, callback: any, errorCallback: any): void;
    /**
     * get
     * @description make GET request
     * @param {string} uri
     * @param {function} callback
     * @param {function} errorCallback
     */
    get(uri: any, callback: any, errorCallback: any): void;
    /**
     * post
     * @description make POST request
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {function} callback
     * @param {function} errorCallback
     */
    post(uri: any, payload: any, callback: any, errorCallback: any): void;
    /**
     * evaluateStatus
     * @description check if status is expected and log errors
     * @param {string} uri
     * @param {Object|string|number|boolean} payload
     * @param {Object|string} ans
     * @param {Object} res
     */
    evaluateStatus(uri: any, payload: any, ans: any, res: any): void;
    /**
     * Helper: Empty callback
     */
    emptyCallback(): void;
}
