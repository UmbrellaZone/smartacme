"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const q = require("q");
const plugins = require("./smartacme.plugins");
const helpers = require("./smartacme.helpers");
// Dnsly instance (we really just need one)
let myDnsly = new plugins.dnsly.Dnsly('google');
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
     * checks if DNS records are set
     */
    checkDns() {
        return __awaiter(this, void 0, void 0, function* () {
            let myRecord;
            try {
                myRecord = yield myDnsly.getRecord(helpers.prefixName(this.domainName), 'TXT');
            }
            catch (err) {
                yield this.checkDns();
            }
            return myRecord[0][0];
        });
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
                status: res.body.status,
                dnsKeyHash: keyHash,
                domainName: this.domainName,
                domainNamePrefixed: helpers.prefixName(this.domainName)
            };
            this.acceptedChallenge = returnDNSChallenge;
            done.resolve(returnDNSChallenge);
        });
        return done.promise;
    }
}
exports.AcmeCert = AcmeCert;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNlcnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lY2VydC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQSx1QkFBc0I7QUFFdEIsK0NBQThDO0FBQzlDLCtDQUE4QztBQTJDOUMsMkNBQTJDO0FBQzNDLElBQUksT0FBTyxHQUFHLElBQUksT0FBTyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUE7QUFFL0M7O0dBRUc7QUFDSDtJQVdJLFlBQVksVUFBc0MsRUFBRSxpQkFBOEI7UUFDOUUsSUFBSSxDQUFDLFVBQVUsR0FBRyxVQUFVLENBQUMsTUFBTSxDQUFBO1FBQ25DLElBQUksQ0FBQyxpQkFBaUIsR0FBRyxpQkFBaUIsQ0FBQTtRQUMxQyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQ3BELElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtRQUN2RixJQUFJLGVBQWUsR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxjQUFjLENBQ3RELE9BQU8sQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLGVBQWUsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDLENBQ2hGLENBQUE7UUFDRCxJQUFJLENBQUMsWUFBWSxHQUFHO1lBQ2hCLFVBQVUsRUFBRSxnQkFBZ0I7WUFDNUIsU0FBUyxFQUFFLGVBQWU7U0FDN0IsQ0FBQTtRQUVELFlBQVk7UUFDWixJQUFJLENBQUMsU0FBUyxHQUFHLElBQUksSUFBSSxFQUFFLENBQUE7UUFDM0IsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLElB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