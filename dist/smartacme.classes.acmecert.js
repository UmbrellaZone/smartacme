"use strict";
const q = require("q");
const plugins = require("./smartacme.plugins");
const helpers = require("./smartacme.helpers");
/**
 * class AcmeCert represents a cert for domain
 */
class AcmeCert {
    constructor(optionsArg, parentSmartAcmeArg) {
        this.parentAcmeAccount = parentSmartAcmeArg;
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
    requestChallenge(domainNameArg, challengeTypeArg = 'dns-01') {
        let done = q.defer();
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.newAuthz({
            identifier: {
                type: 'dns',
                value: domainNameArg
            }
        }, this.parentAcmeAccount.parentSmartAcme.keyPair, (err, res) => {
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
     * validates a challenge, only call after you have set the challenge at the expected location
     */
    validate(challenge) {
        let done = q.defer();
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.poll(challenge.uri, function (err, res) {
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
    acceptChallenge(challenge) {
        let done = q.defer();
        /**
         * the key is needed to accept the challenge
         */
        let authKey = plugins.rawacme.keyAuthz(challenge.token, this.parentAcmeAccount.parentSmartAcme.keyPair.publicKey);
        /**
         * needed in case selected challenge is of type dns-01
         */
        let keyHash = plugins.rawacme.dnsKeyAuthzHash(authKey); // needed if dns challenge is chosen
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
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.post(challenge.uri, {
            resource: 'challenge',
            keyAuthorization: authKey
        }, this.parentAcmeAccount.parentSmartAcme.keyPair, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            done.resolve(returnDNSChallenge);
        });
        return done.promise;
    }
}
exports.AcmeCert = AcmeCert;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWNlcnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lY2VydC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsdUJBQXNCO0FBRXRCLCtDQUE4QztBQUM5QywrQ0FBOEM7QUF5QzlDOztHQUVHO0FBQ0g7SUFTSSxZQUFZLFVBQXNDLEVBQUUsa0JBQWtCO1FBQ2xFLElBQUksQ0FBQyxpQkFBaUIsR0FBRyxrQkFBa0IsQ0FBQTtRQUMzQyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxhQUFhLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1FBQ3BELElBQUksZ0JBQWdCLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsaUJBQWlCLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVLENBQUMsQ0FBQTtRQUN2RixJQUFJLGVBQWUsR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxjQUFjLENBQ3RELE9BQU8sQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLGVBQWUsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDLEVBQUUsZ0JBQWdCLENBQUMsQ0FBQyxDQUFDLENBQ2hGLENBQUE7UUFDRCxJQUFJLENBQUMsWUFBWSxHQUFHO1lBQ2hCLFVBQVUsRUFBRSxnQkFBZ0I7WUFDNUIsU0FBUyxFQUFFLGVBQWU7U0FDN0IsQ0FBQTtRQUVELFlBQVk7UUFDWixJQUFJLENBQUMsU0FBUyxHQUFHLElBQUksSUFBSSxFQUFFLENBQUE7UUFDM0IsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLElBQUksRUFBRSxDQUFBO1FBQ3pCLElBQUksQ0FBQyxPQUFPLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsT0FBTyxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUE7UUFFbkQsaUJBQWlCO1FBQ2pCLElBQUksQ0FBQyxVQUFVLEdBQUc7WUFDZCxFQUFFLElBQUksRUFBRSxZQUFZLEVBQUUsS0FBSyxFQUFFLFVBQVUsQ0FBQyxNQUFNLEVBQUU7WUFDaEQsRUFBRSxJQUFJLEVBQUUsYUFBYSxFQUFFLEtBQUssRUFBRSxVQUFVLENBQUMsT0FBTyxFQUFFO1lBQ2xELEVBQUUsU0FBUyxFQUFFLElBQUksRUFBRSxLQUFLLEVBQUUsVUFBVSxDQUFDLGFBQWEsRUFBRTtZQUNwRCxFQUFFLElBQUksRUFBRSxjQUFjLEVBQUUsS0FBSyxFQUFFLFVBQVUsQ0FBQyxRQUFRLEVBQUU7WUFDcEQsRUFBRSxJQUFJLEVBQUUsa0JBQWtCLEVBQUUsS0FBSyxFQUFFLFVBQVUsQ0FBQyxZQUFZLEVBQUU7WUFDNUQsRUFBRSxTQUFTLEVBQUUsSUFBSSxFQUFFLEtBQUssRUFBRSxVQUFVLENBQUMsa0JBQWtCLEVBQUU7WUFDekQsRUFBRSxJQUFJLEVBQUUsbUJBQW1CLEVBQUUsS0FBSyxFQUFFLFVBQVUsQ0FBQyxRQUFRLEVBQUU7WUFDekQsRUFBRSxJQUFJLEVBQUUsa0JBQWtCLEVBQUUsS0FBSyxFQUFFLFVBQVUsQ0FBQyxZQUFZLEVBQUU7U0FDL0QsQ0FBQTtRQUVELGFBQWE7UUFDYixJQUFJLENBQUMsR0FBRyxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLDBCQUEwQixFQUFFLENBQUE7UUFDN0QsSUFBSSxDQUFDLEdBQUcsQ0FBQyxVQUFVLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFBO1FBQ3BDLElBQUksQ0FBQyxHQUFHLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQTtJQUMzQyxDQUFDO0lBRUQ7Ozs7T0FJRztJQUNILGdCQUFnQixDQUFDLGFBQXFCLEVBQUUsbUJBQW1DLFFBQVE7UUFDL0UsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBK0IsQ0FBQTtRQUNqRCxJQUFJLENBQUMsaUJBQWlCLENBQUMsZUFBZSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQ3pEO1lBQ0ksVUFBVSxFQUFFO2dCQUNSLElBQUksRUFBRSxLQUFLO2dCQUNYLEtBQUssRUFBRSxhQUFhO2FBQ3ZCO1NBQ0osRUFDRCxJQUFJLENBQUMsaUJBQWlCLENBQUMsZUFBZSxDQUFDLE9BQU8sRUFDOUMsQ0FBQyxHQUFHLEVBQUUsR0FBRztZQUNMLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ04sT0FBTyxDQUFDLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFBO2dCQUNqRCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1lBQ3BCLENBQUM7WUFDRCxPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUE7WUFDckMsSUFBSSxZQUFZLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQyxVQUFVLENBQUMsTUFBTSxDQUFDLENBQUM7Z0JBQzNDLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxLQUFLLGdCQUFnQixDQUFBO1lBQ3RDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBQ0wsSUFBSSxDQUFDLGVBQWUsQ0FBQyxZQUFZLENBQUM7aUJBQzdCLElBQUksQ0FBQyxDQUFDLENBQThCO2dCQUNqQyxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBQ25CLENBQUMsQ0FBQyxDQUFBO1FBQ1YsQ0FBQyxDQUNKLENBQUE7UUFDRCxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUN2QixDQUFDO0lBRUQ7O09BRUc7SUFDSCxRQUFRLENBQUMsU0FBc0M7UUFDM0MsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO1FBQ3BCLElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxlQUFlLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxFQUFFLFVBQVUsR0FBRyxFQUFFLEdBQUc7WUFDdkYsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDTixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1lBQ3BCLENBQUM7WUFDRCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQTtZQUN2QixPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUE7WUFDckMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO1FBQ2xCLENBQUMsQ0FBQyxDQUFBO1FBQ0YsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOztPQUVHO0lBQ0gsV0FBVztRQUNQLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLE9BQU8sR0FBRztZQUNWLEdBQUcsRUFBRSxPQUFPLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQzlCLE9BQU8sQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUNqQixPQUFPLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyx5QkFBeUIsQ0FDM0MsSUFBSSxDQUFDLEdBQUcsQ0FDWCxDQUNKLENBQ0o7WUFDRCxTQUFTLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQyxXQUFXLEVBQUU7WUFDdkMsUUFBUSxFQUFFLElBQUksQ0FBQyxPQUFPLENBQUMsV0FBVyxFQUFFO1NBQ3ZDLENBQUE7UUFDRCxJQUFJLENBQUMsaUJBQWlCLENBQUMsZUFBZSxDQUFDLGFBQWEsQ0FBQyxPQUFPLENBQ3hELE9BQU8sRUFDUCxPQUFPLENBQUMsYUFBYSxFQUFFLEVBQ3ZCLENBQUMsR0FBRyxFQUFFLEdBQUc7WUFDTCxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUNOLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7WUFDcEIsQ0FBQztRQUNMLENBQUMsQ0FBQyxDQUFBO1FBQ04sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOztPQUVHO0lBQ0gsY0FBYztJQUVkLENBQUM7SUFFRDs7T0FFRztJQUNLLGVBQWUsQ0FBQyxTQUE4QjtRQUNsRCxJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFFcEI7O1dBRUc7UUFDSCxJQUFJLE9BQU8sR0FBVyxPQUFPLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FDMUMsU0FBUyxDQUFDLEtBQUssRUFDZixJQUFJLENBQUMsaUJBQWlCLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQzNELENBQUE7UUFFRDs7V0FFRztRQUNILElBQUksT0FBTyxHQUFXLE9BQU8sQ0FBQyxPQUFPLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxDQUFBLENBQUMsb0NBQW9DO1FBRW5HOztXQUVHO1FBQ0gsSUFBSSxrQkFBa0IsR0FBZ0M7WUFDbEQsR0FBRyxFQUFFLFNBQVMsQ0FBQyxHQUFHO1lBQ2xCLElBQUksRUFBRSxTQUFTLENBQUMsSUFBSTtZQUNwQixLQUFLLEVBQUUsU0FBUyxDQUFDLEtBQUs7WUFDdEIsZ0JBQWdCLEVBQUUsU0FBUyxDQUFDLGdCQUFnQjtZQUM1QyxPQUFPLEVBQUUsT0FBTztZQUNoQixNQUFNLEVBQUUsU0FBUyxDQUFDLE1BQU07U0FDM0IsQ0FBQTtRQUVELElBQUksQ0FBQyxpQkFBaUIsQ0FBQyxlQUFlLENBQUMsYUFBYSxDQUFDLElBQUksQ0FDckQsU0FBUyxDQUFDLEdBQUcsRUFDYjtZQUNJLFFBQVEsRUFBRSxXQUFXO1lBQ3JCLGdCQUFnQixFQUFFLE9BQU87U0FDNUIsRUFDRCxJQUFJLENBQUMsaUJBQWlCLENBQUMsZUFBZSxDQUFDLE9BQU8sRUFDOUMsQ0FBQyxHQUFHLEVBQUUsR0FBRztZQUNMLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ04sT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUNwQixDQUFDO1lBQ0QsSUFBSSxDQUFDLE9BQU8sQ0FBQyxrQkFBa0IsQ0FBQyxDQUFBO1FBQ3BDLENBQUMsQ0FDSixDQUFBO1FBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztDQUNKO0FBbExELDRCQWtMQyJ9