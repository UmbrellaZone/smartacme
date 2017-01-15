"use strict";
const q = require("q");
const plugins = require("./smartacme.plugins");
const helpers = require("./smartacme.helpers");
/**
 * class AcmeCert represents a cert for domain
 */
class AcmeCert {
    constructor(optionsArg, parentAcmeAccount) {
        this.domainName = optionsArg.domain;
        this.parentAcmeAccount = parentAcmeAccount;
        this.keypair = helpers.createKeypair(optionsArg.bit);
        let privateKeyForged = plugins.nodeForge.pki.privateKeyFromPem(this.keypair.privateKey);
        let publicKeyForged = plugins.nodeForge.pki.publicKeyToPem(plugins.nodeForge.pki.setRsaPublicKey(privateKeyForged.n, privateKeyForged.e));
        this.keyPairFinal = {
            privateKey: privateKeyForged,
            publicKey: publicKeyForged
        };
        // set dates
        this.validFrom = new Date();
        this.validTo = new Date();
        this.validTo.setDate(this.validFrom.getDate() + 90);
        // set attributes
        this.attributes = [
            { name: 'commonName', value: optionsArg.domain },
            { name: 'countryName', value: optionsArg.country },
            { shortName: 'ST', value: optionsArg.country_short },
            { name: 'localityName', value: optionsArg.locality },
            { name: 'organizationName', value: optionsArg.organization },
            { shortName: 'OU', value: optionsArg.organization_short },
            { name: 'challengePassword', value: optionsArg.password },
            { name: 'unstructuredName', value: optionsArg.unstructured }
        ];
        // set up csr
        this.csr = plugins.nodeForge.pki.createCertificationRequest();
        this.csr.setSubject(this.attributes);
        this.csr.setAttributes(this.attributes);
    }
    /**
     * requests a challenge for a domain
     * @param domainNameArg - the domain name to request a challenge for
     * @param challengeType - the challenge type to request
     */
    requestChallenge(challengeTypeArg = 'dns-01') {
        let done = q.defer();
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.newAuthz({
            identifier: {
                type: 'dns',
                value: this.domainName
            }
        }, this.parentAcmeAccount.parentSmartAcme.keyPair, (err, res) => {
            if (err) {
                console.error('smartacme: something went wrong:');
                console.log(err);
                done.reject(err);
            }
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
     * validates a challenge, only call after you have set the challenge at the expected location
     */
    requestValidation() {
        let done = q.defer();
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.poll(this.acceptedChallenge.uri, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            console.log(`Validation response:`);
            console.log(JSON.stringify(res.body));
            if (res.body.status === 'pending' || 'invalid') {
                setTimeout(() => {
                    this.requestValidation().then(x => { done.resolve(x); });
                }, 2000);
            }
            else {
                done.resolve(res.body);
            }
        });
        return done.promise;
    }
    /**
     * requests a certificate
     */
    requestCert() {
        let done = q.defer();
        let payload = {
            csr: plugins.rawacme.base64.encode(plugins.rawacme.toDer(plugins.nodeForge.pki.certificationRequestToPem(this.csr))),
            notBefore: this.validFrom.toISOString(),
            notAfter: this.validTo.toISOString()
        };
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.newCert(payload, helpers.createKeypair(), (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            console.log(res.body);
            done.resolve(res.body);
        });
        return done.promise;
    }
    /**
     * getCertificate - takes care of cooldown, validation polling and certificate retrieval
     */
    getCertificate() {
    }
    /**
     * accept a challenge - for private use only
     */
    acceptChallenge(challengeArg) {
        let done = q.defer();
        /**
         * the key is needed to accept the challenge
         */
        let authKey = plugins.rawacme.keyAuthz(challengeArg.token, this.parentAcmeAccount.parentSmartAcme.keyPair.publicKey);
        /**
         * needed in case selected challenge is of type dns-01
         */
        let keyHash = plugins.rawacme.dnsKeyAuthzHash(authKey); // needed if dns challenge is chosen
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.post(challengeArg.uri, {
            resource: 'challenge',
            keyAuthorization: authKey
        }, this.parentAcmeAccount.parentSmartAcme.keyPair, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            /**
             * the return challenge
             */
            let returnDNSChallenge = {
                uri: res.body.uri,
                type: res.body.type,
                token: res.body.token,
                keyAuthorization: res.body.keyAuthorization,
                keyHash: keyHash,
                status: res.body.status
            };
            this.acceptedChallenge = returnDNSChallenge;
            done.resolve(returnDNSChallenge);
        });
        return done.promise;
    }
}
exports.AcmeCert = AcmeCert;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNlcnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lY2VydC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsdUJBQXNCO0FBRXRCLCtDQUE4QztBQUM5QywrQ0FBOEM7QUF5QzlDOztHQUVHO0FBQ0g7SUFXSSxZQUFZLFVBQXNDLEVBQUUsaUJBQThCO1FBQzlFLElBQUksQ0FBQyxVQUFVLEdBQUcsVUFBVSxDQUFDLE1BQU0sQ0FBQTtRQUNuQyxJQUFJLENBQUMsaUJBQWlCLEdBQUcsaUJBQWlCLENBQUE7UUFDMUMsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsYUFBYSxDQUFDLFVBQVUsQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUNwRCxJQUFJLGdCQUFnQixHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLGlCQUFpQixDQUFDLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLENBQUE7UUFDdkYsSUFBSSxlQUFlLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsY0FBYyxDQUN0RCxPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxlQUFlLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxFQUFFLGdCQUFnQixDQUFDLENBQUMsQ0FBQyxDQUNoRixDQUFBO1FBQ0QsSUFBSSxDQUFDLFlBQVksR0FBRztZQUNoQixVQUFVLEVBQUUsZ0JBQWdCO1lBQzVCLFNBQVMsRUFBRSxlQUFlO1NBQzdCLENBQUE7UUFFRCxZQUFZO1FBQ1osSUFBSSxDQUFDLFNBQVMsR0FBRyxJQUFJLElBQUksRUFBRSxDQUFBO1FBQzNCLElBQUksQ0FBQyxPQUFPLEdBQUcsSUFBSSxJQUFJLEVBQUUsQ0FBQTtRQUN6QixJQUFJLENBQUMsT0FBTyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sRUFBRSxHQUFHLEVBQUUsQ0FB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