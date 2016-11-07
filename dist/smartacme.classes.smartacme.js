"use strict";
const acmeclient = require("./smartacme.classes.acmeclient");
class SmartAcme {
    constructor(directoryUrlArg = 'https://acme-staging.api.letsencrypt.org/directory') {
        this.acmeClient = new acmeclient.AcmeClient(directoryUrlArg);
    }
    /**
     * creates an account
     */
    createAccount() {
        this.acmeClient.createAccount('test@bleu.de', (answer) => {
            console.log(answer);
        });
    }
    /**
     * returns the openssl key pair for
     */
    getKeyPair() {
        return this.acmeClient.getKeyPair();
    }
}
exports.SmartAcme = SmartAcme;
class AcmeAccount {
}
exports.AcmeAccount = AcmeAccount;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFDQSw2REFBNEQ7QUFFNUQ7SUFHSSxZQUFZLGtCQUEwQixvREFBb0Q7UUFDdEYsSUFBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsZUFBZSxDQUFDLENBQUE7SUFDaEUsQ0FBQztJQUVEOztPQUVHO0lBQ0gsYUFBYTtRQUNULElBQUksQ0FBQyxVQUFVLENBQUMsYUFBYSxDQUFDLGNBQWMsRUFBQyxDQUFDLE1BQU07WUFDaEQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxNQUFNLENBQUMsQ0FBQTtRQUN2QixDQUFDLENBQUMsQ0FBQTtJQUNOLENBQUM7SUFFRDs7T0FFRztJQUNILFVBQVU7UUFDTixNQUFNLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxVQUFVLEVBQUUsQ0FBQTtJQUN2QyxDQUFDO0NBQ0o7QUF0QkQsOEJBc0JDO0FBRUQ7Q0FFQztBQUZELGtDQUVDIn0=