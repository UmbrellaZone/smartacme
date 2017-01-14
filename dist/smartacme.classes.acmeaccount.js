"use strict";
const q = require("q");
/**
 * class AcmeAccount represents an AcmeAccount
 */
class AcmeAccount {
    constructor(smartAcmeParentArg) {
        this.parentSmartAcme = smartAcmeParentArg;
    }
    /**
     * register the account with letsencrypt
     */
    register() {
        let done = q.defer();
        this.parentSmartAcme.rawacmeClient.newReg({
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
        return done.promise;
    }
    /**
     * agree to letsencrypr terms of service
     */
    agreeTos() {
        let done = q.defer();
        let tosPart = this.link.split(',')[1];
        let tosLinkPortion = tosPart.split(';')[0];
        let url = tosLinkPortion.split(';')[0].trim().replace(/[<>]/g, '');
        this.parentSmartAcme.rawacmeClient.post(this.location, { Agreement: url, resource: 'reg' }, (err, res) => {
            if (err) {
                console.log(err);
                done.reject(err);
                return;
            }
            done.resolve();
        });
        return done.promise;
    }
    createAcmeCert(domainNameArg) {
    }
}
exports.AcmeAccount = AcmeAccount;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWFjY291bnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lYWNjb3VudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsdUJBQXNCO0FBUXRCOztHQUVHO0FBQ0g7SUFLSSxZQUFZLGtCQUE2QjtRQUNyQyxJQUFJLENBQUMsZUFBZSxHQUFHLGtCQUFrQixDQUFBO0lBQzdDLENBQUM7SUFFRDs7T0FFRztJQUNILFFBQVE7UUFDSixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsSUFBSSxDQUFDLGVBQWUsQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUNyQztZQUNJLE9BQU8sRUFBRSxDQUFDLDZCQUE2QixDQUFDO1NBQzNDLEVBQ0QsQ0FBQyxHQUFHLEVBQUUsR0FBRztZQUNMLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ04sT0FBTyxDQUFDLEtBQUssQ0FBQyxrQ0FBa0MsQ0FBQyxDQUFBO2dCQUNqRCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixNQUFNLENBQUE7WUFDVixDQUFDO1lBQ0QsSUFBSSxDQUFDLEdBQUcsR0FBRyxHQUFHLENBQUMsSUFBSSxDQUFDLEdBQUcsQ0FBQTtZQUN2QixJQUFJLENBQUMsSUFBSSxHQUFHLEdBQUcsQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFBO1lBQzVCLE9BQU8sQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFBO1lBQ3RCLElBQUksQ0FBQyxRQUFRLEdBQUcsR0FBRyxDQUFDLE9BQU8sQ0FBQyxRQUFRLENBQUE7WUFDcEMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO1FBQ2xCLENBQUMsQ0FBQyxDQUFBO1FBQ04sTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVEOztPQUVHO0lBQ0gsUUFBUTtRQUNKLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLE9BQU8sR0FBRyxJQUFJLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUNyQyxJQUFJLGNBQWMsR0FBRyxPQUFPLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO1FBQzFDLElBQUksR0FBRyxHQUFHLGNBQWMsQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsSUFBSSxFQUFFLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRSxFQUFFLENBQUMsQ0FBQTtRQUNsRSxJQUFJLENBQUMsZUFBZSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLFFBQVEsRUFBRSxFQUFFLFNBQVMsRUFBRSxHQUFHLEVBQUUsUUFBUSxFQUFFLEtBQUssRUFBRSxFQUFFLENBQUMsR0FBRyxFQUFFLEdBQUc7WUFDakcsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDTixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO2dCQUNoQixNQUFNLENBQUE7WUFDVixDQUFDO1lBQ0QsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO1FBQ2xCLENBQUMsQ0FBQyxDQUFBO1FBQ0YsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7SUFDdkIsQ0FBQztJQUVELGNBQWMsQ0FBQyxhQUFxQjtJQUVwQyxDQUFDO0NBQ0o7QUF4REQsa0NBd0RDIn0=