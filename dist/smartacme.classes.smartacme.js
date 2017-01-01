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
        this.helper = new smartacme_classes_helper_1.SmartacmeHelper();
        this.keyPair = this.helper.createKeypair();
        if (this.productionBool) {
            this.acmeUrl = rawacme.LETSENCRYPT_STAGING_URL;
        }
        else {
            this.acmeUrl = rawacme.LETSENCRYPT_URL;
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
                console.log(this.JWK);
                done.resolve();
            });
        });
        return done.promise;
    }
}
exports.SmartAcme = SmartAcme;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSwwQkFBdUI7QUFDdkIsdUJBQXNCO0FBRXRCLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQUdyQyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsU0FBUyxDQUFDLENBQUE7QUFHaEMseUVBQXlFO0FBRXpFOztHQUVHO0FBQ0g7SUFPSTs7T0FFRztJQUNILFlBQVksZ0JBQXlCLEtBQUs7UUFDdEMsSUFBSSxDQUFDLGNBQWMsR0FBRyxhQUFhLENBQUE7UUFDbkMsSUFBSSxDQUFDLE1BQU0sR0FBRyxJQUFJLDBDQUFlLEVBQUUsQ0FBQTtRQUNuQyxJQUFJLENBQUMsT0FBTyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsYUFBYSxFQUFFLENBQUE7UUFDMUMsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUM7WUFDdEIsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsdUJBQXVCLENBQUE7UUFDbEQsQ0FBQztRQUFDLElBQUksQ0FBQyxDQUFDO1lBQ0osSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsZUFBZSxDQUFBO1FBQzFDLENBQUM7SUFDTCxDQUFDO0lBRUQ7OztPQUdHO0lBQ0gsYUFBYTtRQUNULElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixPQUFPLENBQUMsWUFBWSxDQUNoQjtZQUNJLEdBQUcsRUFBRSxJQUFJLENBQUMsT0FBTztZQUNqQixTQUFTLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxTQUFTO1lBQ2pDLFVBQVUsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLFVBQVU7U0FDdEMsRUFDRCxDQUFDLEdBQUcsRUFBRSxNQUFNO1lBQ1IsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDTixPQUFPLENBQUMsS0FBSyxDQUFDLGtDQUFrQyxDQUFDLENBQUE7Z0JBQ2pELE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLE1BQU0sQ0FBQTtZQUNWLENBQUM7WUFFRCxNQUFNLENBQUMsTUFBTSxDQUNUO2dCQUNJLE9BQU8sRUFBRSxDQUFDLDZCQUE2QixDQUFDO2FBQzNDLEVBQ0QsQ0FBQyxHQUFHLEVBQUUsR0FBRztnQkFDTCxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO29CQUNOLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQTtvQkFDakQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtvQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtvQkFDaEIsTUFBTSxDQUFBO2dCQUNWLENBQUM7Z0JBQ0QsSUFBSSxDQUFDLEdBQUcsR0FBRyxHQUFHLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQTtnQkFDdkIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ3JCLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtZQUNsQixDQUFDLENBQUMsQ0FBQTtRQUVWLENBQUMsQ0FDSixDQUFBO1FBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztDQUNKO0FBN0RELDhCQTZEQyJ9