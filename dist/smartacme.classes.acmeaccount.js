"use strict";
const q = require("q");
const smartacme_classes_acmecert_1 = require("./smartacme.classes.acmecert");
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
    createAcmeCert(domainNameArg, countryArg = 'Germany', countryShortArg = 'DE', city = 'Bremen', companyArg = 'Some Company', companyShortArg = 'SC') {
        let done = q.defer();
        let acmeCert = new smartacme_classes_acmecert_1.AcmeCert({
            bit: 2064,
            key: null,
            domain: domainNameArg,
            country: countryArg,
            country_short: countryShortArg,
            locality: city,
            organization: companyArg,
            organization_short: companyShortArg,
            password: null,
            unstructured: null,
            subject_alt_names: null
        }, this);
        done.resolve(acmeCert);
        return done.promise;
    }
}
exports.AcmeAccount = AcmeAccount;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWFjY291bnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lYWNjb3VudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsdUJBQXNCO0FBTXRCLDZFQUF1RDtBQUV2RDs7R0FFRztBQUNIO0lBS0ksWUFBWSxrQkFBNkI7UUFDckMsSUFBSSxDQUFDLGVBQWUsR0FBRyxrQkFBa0IsQ0FBQTtJQUM3QyxDQUFDO0lBRUQ7O09BRUc7SUFDSCxRQUFRO1FBQ0osSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO1FBQ3BCLElBQUksQ0FBQyxlQUFlLENBQUMsYUFBYSxDQUFDLE1BQU0sQ0FDckM7WUFDSSxPQUFPLEVBQUUsQ0FBQyw2QkFBNkIsQ0FBQztTQUMzQyxFQUNELENBQUMsR0FBRyxFQUFFLEdBQUc7WUFDTCxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUNOLE9BQU8sQ0FBQyxLQUFLLENBQUMsa0NBQWtDLENBQUMsQ0FBQTtnQkFDakQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsTUFBTSxDQUFBO1lBQ1YsQ0FBQztZQUNELElBQUksQ0FBQyxHQUFHLEdBQUcsR0FBRyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUE7WUFDdkIsSUFBSSxDQUFDLElBQUksR0FBRyxHQUFHLENBQUMsT0FBTyxDQUFDLElBQUksQ0FBQTtZQUM1QixPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtZQUN0QixJQUFJLENBQUMsUUFBUSxHQUFHLEdBQUcsQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFBO1lBQ3BDLElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtRQUNsQixDQUFDLENBQUMsQ0FBQTtRQUNOLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRDs7T0FFRztJQUNILFFBQVE7UUFDSixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsSUFBSSxPQUFPLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUE7UUFDckMsSUFBSSxjQUFjLEdBQUcsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUMxQyxJQUFJLEdBQUcsR0FBRyxjQUFjLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLElBQUksRUFBRSxDQUFDLE9BQU8sQ0FBQyxPQUFPLEVBQUUsRUFBRSxDQUFDLENBQUE7UUFDbEUsSUFBSSxDQUFDLGVBQWUsQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLEVBQUUsRUFBRSxTQUFTLEVBQUUsR0FBRyxFQUFFLFFBQVEsRUFBRSxLQUFLLEVBQUUsRUFBRSxDQUFDLEdBQUcsRUFBRSxHQUFHO1lBQ2pHLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7Z0JBQ04sT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsSUFBSSxDQUFDLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQTtnQkFDaEIsTUFBTSxDQUFBO1lBQ1YsQ0FBQztZQUNELElBQUksQ0FBQyxPQUFPLEVBQUUsQ0FBQTtRQUNsQixDQUFDLENBQUMsQ0FBQTtRQUNGLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7SUFFRCxjQUFjLENBQ1YsYUFBcUIsRUFDckIsVUFBVSxHQUFHLFNBQVMsRUFDdEIsZUFBZSxHQUFHLElBQUksRUFDdEIsSUFBSSxHQUFHLFFBQVEsRUFDZixVQUFVLEdBQUcsY0FBYyxFQUMzQixlQUFlLEdBQUcsSUFBSTtRQUd0QixJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFZLENBQUE7UUFDOUIsSUFBSSxRQUFRLEdBQUcsSUFBSSxxQ0FBUSxDQUN2QjtZQUNJLEdBQUcsRUFBRSxJQUFJO1lBQ1QsR0FBRyxFQUFFLElBQUk7WUFDVCxNQUFNLEVBQUUsYUFBYTtZQUNyQixPQUFPLEVBQUUsVUFBVTtZQUNuQixhQUFhLEVBQUUsZUFBZTtZQUM5QixRQUFRLEVBQUUsSUFBSTtZQUNkLFlBQVksRUFBRSxVQUFVO1lBQ3hCLGtCQUFrQixFQUFFLGVBQWU7WUFDbkMsUUFBUSxFQUFFLElBQUk7WUFDZCxZQUFZLEVBQUUsSUFBSTtZQUNsQixpQkFBaUIsRUFBRSxJQUFJO1NBQzFCLEVBQ0QsSUFBSSxDQUNQLENBQUE7UUFDRCxJQUFJLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFBO1FBQ3RCLE1BQU0sQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFBO0lBQ3ZCLENBQUM7Q0FDSjtBQWxGRCxrQ0FrRkMifQ==