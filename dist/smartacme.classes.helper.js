"use strict";
require("typings-global");
const q = require("q");
let rsaKeygen = require('rsa-keygen');
class SmartacmeHelper {
    constructor(smartAcmeArg) {
        this.parentSmartAcme = smartAcmeArg;
    }
    /**
     * creates a keypair to use with requests and to generate JWK from
     */
    createKeypair(bit = 2048) {
        let result = rsaKeygen.generate(bit);
        return {
            publicKey: result.public_key,
            privateKey: result.private_key
        };
    }
    /**
     * getReg
     * @executes ASYNC
     */
    getReg() {
        let done = q.defer();
        let body = { resource: 'reg' };
        this.parentSmartAcme.rawacmeClient.post(this.parentSmartAcme.location, body, this.parentSmartAcme.keyPair, (err, res) => {
            if (err) {
                console.error('smartacme: something went wrong:');
                console.log(err);
                done.reject(err);
                return;
            }
            console.log(JSON.stringify(res.body));
            done.resolve();
        });
        return done.promise;
    }
}
exports.SmartacmeHelper = SmartacmeHelper;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuaGVscGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuaGVscGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSwwQkFBdUI7QUFDdkIsdUJBQXNCO0FBQ3RCLElBQUksU0FBUyxHQUFHLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQTtBQVNyQztJQUdJLFlBQVksWUFBdUI7UUFDL0IsSUFBSSxDQUFDLGVBQWUsR0FBRyxZQUFZLENBQUE7SUFDdkMsQ0FBQztJQUVEOztPQUVHO0lBQ0gsYUFBYSxDQUFDLEdBQUcsR0FBRyxJQUFJO1FBQ3BCLElBQUksTUFBTSxHQUFHLFNBQVMsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDcEMsTUFBTSxDQUFDO1lBQ0gsU0FBUyxFQUFFLE1BQU0sQ0FBQyxVQUFVO1lBQzVCLFVBQVUsRUFBRSxNQUFNLENBQUMsV0FBVztTQUNqQyxDQUFBO0lBQ0wsQ0FBQztJQUVEOzs7T0FHRztJQUNILE1BQU07UUFDRixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsSUFBSSxJQUFJLEdBQUcsRUFBRSxRQUFRLEVBQUUsS0FBSyxFQUFFLENBQUE7UUFDOUIsSUFBSSxDQUFDLGVBQWUsQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUNuQyxJQUFJLENBQUMsZUFBZSxDQUFDLFFBQVEsRUFDN0IsSUFBSSxFQUFFLElBQUksQ0FBQyxlQUFlLENBQUMsT0FBTyxFQUNsQyxDQUFDLEdBQUcsRUFBRSxHQUFHO1lBQ0wsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDTixPQUFPLENBQUMsS0FBSyxDQUFDLGtDQUFrQyxDQUFDLENBQUE7Z0JBQ2pELE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLE1BQU0sQ0FBQTtZQUNWLENBQUM7WUFDRCxPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUE7WUFDckMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO1FBQ2xCLENBQUMsQ0FDSixDQUFBO1FBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztDQUNKO0FBekNELDBDQXlDQyJ9