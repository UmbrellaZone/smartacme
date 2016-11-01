"use strict";
const acmeclient = require("./smartacme.classes.acmeclient");
class SmartAcme {
    constructor(directoryUrlArg = 'https://acme-staging.api.letsencrypt.org/directory') {
        this.acmeClient = new acmeclient.AcmeClient(directoryUrlArg);
    }
}
exports.SmartAcme = SmartAcme;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFDQSw2REFBNEQ7QUFFNUQ7SUFFSSxZQUFZLGtCQUEwQixvREFBb0Q7UUFDdEYsSUFBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLFVBQVUsQ0FBQyxVQUFVLENBQUMsZUFBZSxDQUFDLENBQUE7SUFDaEUsQ0FBQztDQUNKO0FBTEQsOEJBS0MifQ==