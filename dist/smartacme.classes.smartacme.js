"use strict";
// third party modules
const q = require("q"); // promises
const plugins = require("./smartacme.plugins");
const helpers = require("./smartacme.helpers");
const smartacme_classes_acmeaccount_1 = require("./smartacme.classes.acmeaccount");
var smartacme_classes_acmeaccount_2 = require("./smartacme.classes.acmeaccount");
exports.AcmeAccount = smartacme_classes_acmeaccount_2.AcmeAccount;
var smartacme_classes_acmecert_1 = require("./smartacme.classes.acmecert");
exports.AcmeCert = smartacme_classes_acmecert_1.AcmeCert;
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
class SmartAcme {
    /**
     * the constructor for class SmartAcme
     */
    constructor(productionArg = false) {
        this.productionBool = productionArg;
        this.keyPair = helpers.createKeypair();
        if (this.productionBool) {
            this.acmeUrl = plugins.rawacme.LETSENCRYPT_URL;
        }
        else {
            this.acmeUrl = plugins.rawacme.LETSENCRYPT_STAGING_URL;
        }
    }
    /**
     * init the smartacme instance
     */
    init() {
        let done = q.defer();
        plugins.rawacme.createClient({
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
            done.resolve();
        });
        return done.promise;
    }
    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAccount() {
        let done = q.defer();
        let acmeAccount = new smartacme_classes_acmeaccount_1.AcmeAccount(this);
        acmeAccount.register().then(() => {
            return acmeAccount.agreeTos();
        }).then(() => {
            done.resolve(acmeAccount);
        });
        return done.promise;
    }
}
exports.SmartAcme = SmartAcme;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxzQkFBc0I7QUFDdEIsdUJBQXNCLENBQUMsV0FBVztBQUNsQywrQ0FBOEM7QUFDOUMsK0NBQThDO0FBRTlDLG1GQUE2RDtBQVU3RCxpRkFBNkQ7QUFBcEQsc0RBQUEsV0FBVyxDQUFBO0FBQ3BCLDJFQUF5RztBQUFoRyxnREFBQSxRQUFRLENBQUE7QUFFakI7O0dBRUc7QUFDSDtJQU1JOztPQUVHO0lBQ0gsWUFBWSxnQkFBeUIsS0FBSztRQUN0QyxJQUFJLENBQUMsY0FBYyxHQUFHLGFBQWEsQ0FBQTtRQUNuQyxJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxhQUFhLEVBQUUsQ0FBQTtRQUN0QyxFQUFFLENBQUMsQ0FBQyxJQUFJLENBQUMsY0FBYyxDQUFDLENBQUMsQ0FBQztZQUN0QixJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxPQUFPLENBQUMsZUFBZSxDQUFBO1FBQ2xELENBQUM7UUFBQyxJQUFJLENBQUMsQ0FBQztZQUNKLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFDLE9BQU8sQ0FBQyx1QkFBdUIsQ0FBQTtRQUMxRCxDQUFDO0lBQ0wsQ0FBQztJQUVEOztPQUVHO0lBQ0gsSUFBSTtRQUNBLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixPQUFPLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FDeEI7WUFDSSxHQUFHLEVBQUUsSUFBSSxDQUFDLE9BQU87WUFDakIsU0FBUyxFQUFFLElBQUksQ0FBQyxPQUFPLENBQUMsU0FBUztZQUNqQyxVQUFVLEVBQUUsSUFBSSxDQUFDLE9BQU8sQ0FBQyxVQUFVO1NBQ3RDLEVBQ0QsQ0FBQyxHQUFHLEVBQUUsTUFBTTtZQUNSLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ04sT0FBTyxDQUFDLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFBO2dCQUNqRCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixNQUFNLENBQUE7WUFDVixDQUFDO1lBRUQsa0NBQWtDO1lBQ2xDLElBQUksQ0FBQyxhQUFhLEdBQUcsTUFBTSxDQUFBO1lBQzNCLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtRQUNsQixDQUFDLENBQ0osQ0FBQTtRQUNELE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7O09BR0c7SUFDSCxhQUFhO1FBQ1QsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBZSxDQUFBO1FBQ2pDLElBQUksV0FBVyxHQUFHLElBQUksMkNBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUN2QyxXQUFXLENBQUMsUUFBUSxFQUFFLENBQUMsSUFBSSxDQUFDO1lBQ3hCLE1BQU0sQ0FBQyxXQUFXLENBQUMsUUFBUSxFQUFFLENBQUE7UUFDakMsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDO1lBQ0osSUFBSSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQTtRQUM3QixDQUFDLENBQUMsQ0FBQTtRQUNGLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7Q0FDSjtBQTVERCw4QkE0REMifQ==