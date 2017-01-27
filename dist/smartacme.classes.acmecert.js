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
            let preChosenChallenge = res.body.challenges.filter(x => {
                return x.type === challengeTypeArg;
            })[0];
            /**
             * the key is needed to accept the challenge
             */
            let authKey = plugins.rawacme.keyAuthz(preChosenChallenge.token, this.parentAcmeAccount.parentSmartAcme.keyPair.publicKey);
            /**
             * needed in case selected challenge is of type dns-01
             */
            this.dnsKeyHash = plugins.rawacme.dnsKeyAuthzHash(authKey); // needed if dns challenge is chosen
            /**
             * the return challenge
             */
            this.chosenChallenge = {
                uri: preChosenChallenge.uri,
                type: preChosenChallenge.type,
                token: preChosenChallenge.token,
                keyAuthorization: authKey,
                status: preChosenChallenge.status,
                dnsKeyHash: this.dnsKeyHash,
                domainName: this.domainName,
                domainNamePrefixed: helpers.prefixName(this.domainName)
            };
            done.resolve(this.chosenChallenge);
        });
        return done.promise;
    }
    /**
     * checks if DNS records are set, will go through a max of 30 cycles
     */
    checkDns(cycleArg = 1) {
        return __awaiter(this, void 0, void 0, function* () {
            let result = yield myDnsly.checkUntilAvailable(helpers.prefixName(this.domainName), 'TXT', this.dnsKeyHash);
            if (result) {
                console.log('DNS is set!');
                return;
            }
            else {
                throw new Error('DNS not set!');
            }
        });
    }
    /**
     * validates a challenge, only call after you have set the challenge at the expected location
     */
    requestValidation() {
        return __awaiter(this, void 0, void 0, function* () {
            let makeRequest = () => {
                let done = q.defer();
                this.parentAcmeAccount.parentSmartAcme.rawacmeClient.poll(this.chosenChallenge.uri, (err, res) => __awaiter(this, void 0, void 0, function* () {
                    if (err) {
                        console.log(err);
                        return;
                    }
                    console.log(`Validation response:`);
                    console.log(JSON.stringify(res.body));
                    if (res.body.status === 'pending' || res.body.status === 'invalid') {
                        yield plugins.smartdelay.delayFor(3000);
                        makeRequest().then((x) => { done.resolve(x); });
                    }
                    else {
                        console.log('perfect!');
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
    acceptChallenge() {
        let done = q.defer();
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.post(this.chosenChallenge.uri, {
            resource: 'challenge',
            keyAuthorization: this.chosenChallenge.keyAuthorization
        }, this.parentAcmeAccount.parentSmartAcme.keyPair, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            done.resolve(res.body);
        });
        return done.promise;
    }
}
exports.AcmeCert = AcmeCert;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNlcnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lY2VydC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQSx1QkFBc0I7QUFFdEIsK0NBQThDO0FBQzlDLCtDQUE4QztBQTJDOUMsMkNBQTJDO0FBQzNDLElBQUksT0FBTyxHQUFHLElBQUksT0FBTyxDQUFDLEtBQUssQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLENBQUE7QUFFL0M7O0dBRUc7QUFDSDtJQVlJLFlBQVksVUFBc0MsRUFBRSxpQkFBOEI7UUFDOUUsSUFBSSxDQUFDLFVBQVUsR0FBRyxVQUFVLENBQUMsTUFBTSxDQUFBO1FBQ25DLElBQUksQ0FBQyxpQkFBaUIsR0FBRyxpQkFBaUIsQ0FBQTtRQUMxQyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQ3BELElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtRQUN2RixJQUFJLGVBQWUsR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxjQUFjLENBQ3RELE9BQU8sQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLGVBQWUsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDLENBQ2hGLENBQUE7UUFDRCxJQUFJLENBQUMsWUFBWSxHQUFHO1lBQ2hCLFVBQVUsRUFBRSxnQkFBZ0I7WUFDNUIsU0FBUyxFQUFFLGVBQWU7U0FDN0IsQ0FBQTtRQUVELFlBQVk7UUFDWixJQUFJLENBQUMsU0FBUyxHQUFHLElBQUksSUFBSSxFQUFFLENBQUE7UUFDM0IsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLElB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