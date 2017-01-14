"use strict";
// typings
require("typings-global"); // typings for node
// third party modules
const q = require("q"); // promises
let rsaKeygen = require('rsa-keygen'); // rsa keygen
let rawacme = require('rawacme'); // acme helper functions
const smartacme_classes_helper_1 = require("./smartacme.classes.helper");
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
class SmartAcme {
    /**
     * the constructor for class SmartAcme
     */
    constructor(productionArg = false) {
        this.productionBool = productionArg;
        this.helper = new smartacme_classes_helper_1.SmartacmeHelper(this);
        this.keyPair = this.helper.createKeypair();
        if (this.productionBool) {
            this.acmeUrl = rawacme.LETSENCRYPT_URL;
        }
        else {
            this.acmeUrl = rawacme.LETSENCRYPT_STAGING_URL;
        }
    }
    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAccount() {
        let done = q.defer();
        rawacme.createClient({
            url: this.acmeUrl,
            publicKey: this.keyPair.publicKey,
            privateKey: this.keyPair.privateKey
        }, (err, client) => {
            if (err) {
                console.error('smartacme: something went wrong:');
                console.log(err);
                done.reject(err);
                return;
            }
            // make client available in class 
            this.rawacmeClient = client;
            // create the registration
            client.newReg({
                contact: ['mailto:domains@lossless.org']
            }, (err, res) => {
                if (err) {
                    console.error('smartacme: something went wrong:');
                    console.log(err);
                    done.reject(err);
                    return;
                }
                this.JWK = res.body.key;
                this.link = res.headers.link;
                console.log(this.link);
                this.location = res.headers.location;
                done.resolve();
            });
        });
        return done.promise;
    }
    agreeTos() {
        let done = q.defer();
        let tosPart = this.link.split(',')[1];
        let tosLinkPortion = tosPart.split(';')[0];
        let url = tosLinkPortion.split(';')[0].trim().replace(/[<>]/g, '');
        this.rawacmeClient.post(this.location, { Agreement: url, resource: 'reg' }, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
                return;
            }
            done.resolve();
        });
        return done.promise;
    }
    /**
     * requests a challenge for a domain
     * @param domainNameArg - the domain name to request a challenge for
     * @param challengeType - the challenge type to request
     */
    requestChallenge(domainNameArg, challengeTypeArg = 'dns-01') {
        let done = q.defer();
        this.rawacmeClient.newAuthz({
            identifier: {
                type: 'dns',
                value: domainNameArg
            }
        }, this.keyPair, (err, res) => {
            if (err) {
                console.error('smartacme: something went wrong:');
                console.log(err);
                done.reject(err);
            }
            console.log(JSON.stringify(res.body));
            let dnsChallenge = res.body.challenges.filter(x => {
                return x.type === challengeTypeArg;
            })[0];
            this.acceptChallenge(dnsChallenge)
                .then((x) => {
                done.resolve(x);
            });
        });
        return done.promise;
    }
    /**
     * getCertificate - takes care of cooldown, validation polling and certificate retrieval
     */
    getCertificate() {
    }
    /**
     * validates a challenge
     */
    validate(challenge) {
        let done = q.defer();
        this.rawacmeClient.poll(challenge.uri, function (err, res) {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            console.log(res.status);
            console.log(JSON.stringify(res.body));
            done.resolve();
        });
        return done.promise;
    }
    /**
     * accept a challenge - for private use only
     */
    acceptChallenge(challenge) {
        let done = q.defer();
        /**
         * the key is needed to accept the challenge
         */
        let authKey = rawacme.keyAuthz(challenge.token, this.keyPair.publicKey);
        /**
         * needed in case selected challenge is of type dns-01
         */
        let keyHash = rawacme.dnsKeyAuthzHash(authKey); // needed if dns challenge is chosen
        /**
         * the return challenge
         */
        let returnDNSChallenge = {
            uri: challenge.uri,
            type: challenge.type,
            token: challenge.token,
            keyAuthorization: challenge.keyAuthorization,
            keyHash: keyHash,
            status: challenge.status
        };
        this.rawacmeClient.post(challenge.uri, {
            resource: 'challenge',
            keyAuthorization: authKey
        }, this.keyPair, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            done.resolve(returnDNSChallenge);
        });
        return done.promise;
    }
}
exports.SmartAcme = SmartAcme;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxVQUFVO0FBQ1YsMEJBQXVCLENBQUMsbUJBQW1CO0FBRTNDLHNCQUFzQjtBQUN0Qix1QkFBc0IsQ0FBQyxXQUFXO0FBRWxDLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQSxDQUFDLGFBQWE7QUFDbkQsSUFBSSxPQUFPLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyxDQUFBLENBQUMsd0JBQXdCO0FBT3pELHlFQUF5RTtBQWlCekU7O0dBRUc7QUFDSDtJQVVJOztPQUVHO0lBQ0gsWUFBWSxnQkFBeUIsS0FBSztRQUN0QyxJQUFJLENBQUMsY0FBYyxHQUFHLGFBQWEsQ0FBQTtRQUNuQyxJQUFJLENBQUMsTUFBTSxHQUFHLElBQUksMENBQWUsQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUN2QyxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLENBQUE7UUFDMUMsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUM7WUFDdEIsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsZUFBZSxDQUFBO1FBQzFDLENBQUM7UUFBQyxJQUFJLENBQUMsQ0FBQztZQUNKLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFDLHVCQUF1QixDQUFBO1FBQ2xELENBQUM7SUFDTCxDQUFDO0lBRUQ7OztPQUdHO0lBQ0gsYUFBYTtRQUNULElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixPQUFPLENBQUMsWUFBWSxDQUNoQjtZQUNJLEdBQUcsRUFBRSxJQUFJLENBQUMsT0FBTztZQUNqQixTQUFTLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FB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