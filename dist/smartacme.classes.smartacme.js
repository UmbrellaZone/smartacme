"use strict";
const acmeclient = require("./smartacme.classes.acmeclient");
class SmartAcme {
    constructor(directoryUrlArg = 'https://acme-staging.api.letsencrypt.org/directory') {
        this.acmeClient = new acmeclient.AcmeClient(directoryUrlArg);
    }
    createAccount() {
        this.acmeClient.createAccount('test@bleu.de', (answer) => {
            console.log(answer);
        });
    }
}
exports.SmartAcme = SmartAcme;
class AcmeAccount {
}
exports.AcmeAccount = AcmeAccount;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFDQSw2REFBNEQ7QUFFNUQ7SUFHSSxZQUFZLGtCQUEwQixvREFBb0Q7UUFDdEYsSUFBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsZUFBZSxDQUFDLENBQUE7SUFDaEUsQ0FBQztJQUVELGFBQWE7UUFDVCxJQUFJLENBQUMsVUFBVSxDQUFDLGFBQWEsQ0FBQyxjQUFjLEVBQUMsQ0FBQyxNQUFNO1lBQ2hELE9BQU8sQ0FBQyxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUE7UUFDdkIsQ0FBQyxDQUFDLENBQUE7SUFDTixDQUFDO0NBQ0o7QUFaRCw4QkFZQztBQUVEO0NBRUM7QUFGRCxrQ0FFQyJ9