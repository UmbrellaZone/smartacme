"use strict";
require("typings-global");
const q = require("q");
let rsaKeygen = require('rsa-keygen');
let rawacme = require('rawacme');
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
     * requests a certificate
     */
    requestCertificate(domainNameArg) {
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
            done.resolve();
        });
        return done.promise;
    }
}
exports.SmartAcme = SmartAcme;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSwwQkFBdUI7QUFDdkIsdUJBQXNCO0FBRXRCLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQUdyQyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUE7QUFHaEMseUVBQXlFO0FBRXpFOztHQUVHO0FBQ0g7SUFVSTs7T0FFRztJQUNILFlBQVksZ0JBQXlCLEtBQUs7UUFDdEMsSUFBSSxDQUFDLGNBQWMsR0FBRyxhQUFhLENBQUE7UUFDbkMsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFJLDBDQUFlLENBQUMsSUFBSSxDQUFDLENBQUE7UUFDdkMsSUFBSSxDQUFDLE9BQU8sR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFBO1FBQzFDLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxjQUFjLENBQUMsQ0FBQyxDQUFDO1lBQ3RCLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFDLGVBQWUsQ0FBQTtRQUMxQyxDQUFDO1FBQUMsSUFBSSxDQUFDLENBQUM7WUFDSixJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyx1QkFBdUIsQ0FBQTtRQUNsRCxDQUFDO0lBQ0wsQ0FBQztJQUVEOzs7T0FHRztJQUNILGFBQWE7UUFDVCxJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsT0FBTyxDQUFDLFlBQVksQ0FDaEI7WUFDSSxHQUFHLEVBQUUsSUFBSSxDQUFDLE9BQU87WUFDakIsU0FBUyxFQUFFLElBQUksQ0FBQyxPQUFPLENBQUMsU0FBUztZQUNqQyxVQUFVLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVO1NBQ3RDLEVBQ0QsQ0FBQyxHQUFHLEVBQUUsTUFBTTtZQUNSLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ04sT0FBTyxDQUFDLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFBO2dCQUNqRCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixNQUFNLENBQUE7WUFDVixDQUFDO1lBRUQsa0NBQWtDO1lBQ2xDLElBQUksQ0FBQyxhQUFhLEdBQUcsTUFBTSxDQUFBO1lBRTNCLDBCQUEwQjtZQUMxQixNQUFNLENBQUMsTUFBTSxDQUNUO2dCQUNJLE9BQU8sRUFBRSxDQUFDLDZCQUE2QixDQUFDO2FBQzNDLEVBQ0QsQ0FBQyxHQUFHLEVBQUUsR0FBRztnQkFDTCxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO29CQUNOLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQTtvQkFDakQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtvQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtvQkFDaEIsTUFBTSxDQUFBO2dCQUNWLENBQUM7Z0JBQ0QsSUFBSSxDQUFDLEdBQUcsR0FBRyxHQUFHLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQTtnQkFDdkIsSUFBSSxDQUFDLElBQUksR0FBRyxHQUFHLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQTtnQkFDNUIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUE7Z0JBQ3RCLElBQUksQ0FBQyxRQUFRLEdBQUcsR0FBRyxDQUFDLE9BQU8sQ0FBQyxRQUFRLENBQUE7Z0JBQ3BDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtZQUNsQixDQUFDLENBQUMsQ0FBQTtRQUVWLENBQUMsQ0FDSixDQUFBO1FBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVELFFBQVE7UUFDSixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsSUFBSSxPQUFPLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7UUFDckMsSUFBSSxjQUFjLEdBQUcsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUMxQyxJQUFJLEdBQUcsR0FBRyxjQUFjLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksRUFBRSxDQUFDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsRUFBRSxDQUFDLENBQUE7UUFDbEUsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBQyxFQUFDLFNBQVMsRUFBRSxHQUFHLEVBQUUsUUFBUSxFQUFFLEtBQUssRUFBQyxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUc7WUFDOUUsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDTixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixNQUFNLENBQUE7WUFDVixDQUFDO1lBQ0QsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO1FBQ2xCLENBQUMsQ0FBQyxDQUFBO1FBQ0YsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOztPQUVHO0lBQ0gsa0JBQWtCLENBQUMsYUFBYTtRQUM1QixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsSUFBSSxDQUFDLGFBQWEsQ0FBQyxRQUFRLENBQ3ZCO1lBQ0ksVUFBVSxFQUFFO2dCQUNSLElBQUksRUFBRSxLQUFLO2dCQUNYLEtBQUssRUFBRSxhQUFhO2FBQ3ZCO1NBQ0osRUFDRCxJQUFJLENBQUMsT0FBTyxFQUNaLENBQUMsR0FBRyxFQUFFLEdBQUc7WUFDTCxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUNOLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQTtnQkFDakQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUNwQixDQUFDO1lBQ0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFBO1lBQ3JDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtRQUNsQixDQUFDLENBQ0osQ0FBQTtRQUNELE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7Q0FDSjtBQWhIRCw4QkFnSEMifQ==