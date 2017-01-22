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
     * checks if DNS records are set, will go through a max of 30 cycles
     */
    checkDns(cycleArg = 1) {
        return __awaiter(this, void 0, void 0, function* () {
            console.log(`checkDns failed ${cycleArg} times and has ${30 - cycleArg} cycles to go before it fails permanently!`);
            let myRecord;
            try {
                myRecord = yield myDnsly.getRecord(helpers.prefixName(this.domainName), 'TXT');
                console.log('DNS is set!');
                return myRecord[0][0];
            }
            catch (err) {
                if (cycleArg < 30) {
                    cycleArg++;
                    yield plugins.smartdelay.delayFor(2000);
                    return yield this.checkDns(cycleArg);
                }
                else {
                    console.log('failed permanently...');
                    throw err;
                }
            }
        });
    }
    /**
     * validates a challenge, only call after you have set the challenge at the expected location
     */
    requestValidation() {
        return __awaiter(this, void 0, void 0, function* () {
            console.log('give it 2 minutes to settle!');
            yield plugins.smartdelay.delayFor(10000);
            let makeRequest = () => {
                let done = q.defer();
                this.parentAcmeAccount.parentSmartAcme.rawacmeClient.poll(this.acceptedChallenge.uri, (err, res) => __awaiter(this, void 0, void 0, function* () {
                    if (err) {
                        console.log(err);
                        return;
                    }
                    console.log(`Validation response:`);
                    console.log(JSON.stringify(res.body));
                    if (res.body.status === 'pending' || 'invalid') {
                        console.log('retry in 4 minutes!');
                        yield plugins.smartdelay.delayFor(240000);
                        makeRequest().then((x) => { done.resolve(x); });
                    }
                    else {
                        done.resolve(res.body);
                    }
                }));
                return done.promise;
            };
            yield makeRequest();
        });
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