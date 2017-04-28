"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
require("typings-global");
const q = require("smartq");
const plugins = require("./smartacme.plugins");
/**
 * creates a keypair to use with requests and to generate JWK from
 */
exports.createKeypair = (bit = 2048) => {
    let result = plugins.rsaKeygen.generate(bit);
    return {
        publicKey: result.public_key,
        privateKey: result.private_key
    };
};
/**
 * prefix a domain name to make sure it complies with letsencrypt
 */
exports.prefixName = (domainNameArg) => {
    return '_acme-challenge.' + domainNameArg;
};
/**
 * gets an existing registration
 * @executes ASYNC
 */
let getReg = (SmartAcmeArg, location) => {
    let done = q.defer();
    let body = { resource: 'reg' };
    SmartAcmeArg.rawacmeClient.post(location, body, SmartAcmeArg.keyPair, (err, res) => {
        if (err) {
            console.error('smartacme: something went wrong:');
            console.log(err);
            done.reject(err);
            return;
        }
        console.log(JSON.stringify(res.body));
        done.resolve();
    });
    return done.promise;
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmhlbHBlcnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuaGVscGVycy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLDBCQUF1QjtBQUN2Qiw0QkFBMkI7QUFFM0IsK0NBQThDO0FBSzlDOztHQUVHO0FBQ1EsUUFBQSxhQUFhLEdBQUcsQ0FBQyxHQUFHLEdBQUcsSUFBSTtJQUNwQyxJQUFJLE1BQU0sR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsQ0FBQTtJQUM1QyxNQUFNLENBQUM7UUFDTCxTQUFTLEVBQUUsTUFBTSxDQUFDLFVBQVU7UUFDNUIsVUFBVSxFQUFFLE1BQU0sQ0FBQyxXQUFXO0tBQy9CLENBQUE7QUFDSCxDQUFDLENBQUE7QUFFRDs7R0FFRztBQUNRLFFBQUEsVUFBVSxHQUFHLENBQUMsYUFBcUI7SUFDNUMsTUFBTSxDQUFDLGtCQUFrQixHQUFHLGFBQWEsQ0FBQTtBQUMzQyxDQUFDLENBQUE7QUFFRDs7O0dBR0c7QUFDSCxJQUFJLE1BQU0sR0FBRyxDQUFDLFlBQXVCLEVBQUUsUUFBZ0I7SUFDckQsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO0lBQ3BCLElBQUksSUFBSSxHQUFHLEVBQUUsUUFBUSxFQUFFLEtBQUssRUFBRSxDQUFBO0lBQzlCLFlBQVksQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUM3QixRQUFRLEVBQ1IsSUFBSSxFQUNKLFlBQVksQ0FBQyxPQUFPLEVBQ3BCLENBQUMsR0FBRyxFQUFFLEdBQUc7UUFDUCxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO1lBQ1IsT0FBTyxDQUFDLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFBO1lBQ2pELE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7WUFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUNoQixNQUFNLENBQUE7UUFDUixDQUFDO1FBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFBO1FBQ3JDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtJQUNoQixDQUFDLENBQ0YsQ0FBQTtJQUNELE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0FBQ3JCLENBQUMsQ0FBQSJ9