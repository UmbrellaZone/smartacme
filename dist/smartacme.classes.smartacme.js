"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// third party modules
const q = require("smartq"); // promises
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
    createAcmeAccount() {
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsc0JBQXNCO0FBQ3RCLDRCQUEyQixDQUFDLFdBQVc7QUFDdkMsK0NBQThDO0FBQzlDLCtDQUE4QztBQUU5QyxtRkFBNkQ7QUFVN0QsaUZBQTZEO0FBQXBELHNEQUFBLFdBQVcsQ0FBQTtBQUNwQiwyRUFBdUc7QUFBOUYsZ0RBQUEsUUFBUSxDQUFBO0FBRWpCOztHQUVHO0FBQ0g7SUFNRTs7T0FFRztJQUNILFlBQVksZ0JBQXlCLEtBQUs7UUFDeEMsSUFBSSxDQUFDLGNBQWMsR0FBRyxhQUFhLENBQUE7UUFDbkMsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsYUFBYSxFQUFFLENBQUE7UUFDdEMsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUM7WUFDeEIsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUMsT0FBTyxDQUFDLGVBQWUsQ0FBQTtRQUNoRCxDQUFDO1FBQUMsSUFBSSxDQUFDLENBQUM7WUFDTixJQUFJLENBQUMsT0FBTyxHQUFHLE9BQU8sQ0FBQyxPQUFPLENBQUMsdUJBQXVCLENBQUE7UUFDeEQsQ0FBQztJQUNILENBQUM7SUFFRDs7T0FFRztJQUNILElBQUk7UUFDRixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsT0FBTyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQzFCO1lBQ0UsR0FBRyxFQUFFLElBQUksQ0FBQyxPQUFPO1lBQ2pCLFNBQVMsRUFBRSxJQUFJLENBQUMsT0FBTyxDQUFDLFNBQVM7WUFDakMsVUFBVSxFQUFFLElBQUksQ0FBQyxPQUFPLENBQUMsVUFBVTtTQUNwQyxFQUNELENBQUMsR0FBRyxFQUFFLE1BQU07WUFDVixFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUNSLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQTtnQkFDakQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsTUFBTSxDQUFBO1lBQ1IsQ0FBQztZQUVELGtDQUFrQztZQUNsQyxJQUFJLENBQUMsYUFBYSxHQUFHLE1BQU0sQ0FBQTtZQUMzQixJQUFJLENBQUMsT0FBTyxFQUFFLENBQUE7UUFDaEIsQ0FBQyxDQUNGLENBQUE7UUFDRCxNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUNyQixDQUFDO0lBRUQ7OztPQUdHO0lBQ0gsaUJBQWlCO1FBQ2YsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBZSxDQUFBO1FBQ2pDLElBQUksV0FBVyxHQUFHLElBQUksMkNBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQTtRQUN2QyxXQUFXLENBQUMsUUFBUSxFQUFFLENBQUMsSUFBSSxDQUFDO1lBQzFCLE1BQU0sQ0FBQyxXQUFXLENBQUMsUUFBUSxFQUFFLENBQUE7UUFDL0IsQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDO1lBQ04sSUFBSSxDQUFDLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQTtRQUMzQixDQUFDLENBQUMsQ0FBQTtRQUNGLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3JCLENBQUM7Q0FDRjtBQTVERCw4QkE0REMifQ==