"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const q = require("smartq");
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuYWNtZWFjY291bnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuY2xhc3Nlcy5hY21lYWNjb3VudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOztBQUFBLDRCQUEyQjtBQU0zQiw2RUFBdUQ7QUFFdkQ7O0dBRUc7QUFDSDtJQUtFLFlBQVksa0JBQTZCO1FBQ3ZDLElBQUksQ0FBQyxlQUFlLEdBQUcsa0JBQWtCLENBQUE7SUFDM0MsQ0FBQztJQUVEOztPQUVHO0lBQ0gsUUFBUTtRQUNOLElBQUksSUFBSSxHQUFHLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQTtRQUNwQixJQUFJLENBQUMsZUFBZSxDQUFDLGFBQWEsQ0FBQyxNQUFNLENBQ3ZDO1lBQ0UsT0FBTyxFQUFFLENBQUUsNkJBQTZCLENBQUU7U0FDM0MsRUFDRCxDQUFDLEdBQUcsRUFBRSxHQUFHO1lBQ1AsRUFBRSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQztnQkFDUixPQUFPLENBQUMsS0FBSyxDQUFDLGtDQUFrQyxDQUFDLENBQUE7Z0JBQ2pELE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLE1BQU0sQ0FBQTtZQUNSLENBQUM7WUFDRCxJQUFJLENBQUMsR0FBRyxHQUFHLEdBQUcsQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFBO1lBQ3ZCLElBQUksQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDLE9BQU8sQ0FBQyxJQUFJLENBQUE7WUFDNUIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUE7WUFDdEIsSUFBSSxDQUFDLFFBQVEsR0FBRyxHQUFHLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQTtZQUNwQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUE7UUFDaEIsQ0FBQyxDQUFDLENBQUE7UUFDSixNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUNyQixDQUFDO0lBRUQ7O09BRUc7SUFDSCxRQUFRO1FBQ04sSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBRSxDQUFBO1FBQ3BCLElBQUksT0FBTyxHQUFHLElBQUksQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLEdBQUcsQ0FBQyxDQUFFLENBQUMsQ0FBRSxDQUFBO1FBQ3ZDLElBQUksY0FBYyxHQUFHLE9BQU8sQ0FBQyxLQUFLLENBQUMsR0FBRyxDQUFDLENBQUUsQ0FBQyxDQUFFLENBQUE7UUFDNUMsSUFBSSxHQUFHLEdBQUcsY0FBYyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBRSxDQUFDLENBQUUsQ0FBQyxJQUFJLEVBQUUsQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFLEVBQUUsQ0FBQyxDQUFBO1FBQ3BFLElBQUksQ0FBQyxlQUFlLENBQUMsYUFBYSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsUUFBUSxFQUFFLEVBQUUsU0FBUyxFQUFFLEdBQUcsRUFBRSxRQUFRLEVBQUUsS0FBSyxFQUFFLEVBQUUsQ0FBQyxHQUFHLEVBQUUsR0FBRztZQUNuRyxFQUFFLENBQUMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDO2dCQUNSLE9BQU8sQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUE7Z0JBQ2hCLE1BQU0sQ0FBQTtZQUNSLENBQUM7WUFDRCxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUE7UUFDaEIsQ0FBQyxDQUFDLENBQUE7UUFDRixNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUNyQixDQUFDO0lBRUQsY0FBYyxDQUNaLGFBQXFCLEVBQ3JCLFVBQVUsR0FBRyxTQUFTLEVBQ3RCLGVBQWUsR0FBRyxJQUFJLEVBQ3RCLElBQUksR0FBRyxRQUFRLEVBQ2YsVUFBVSxHQUFHLGNBQWMsRUFDM0IsZUFBZSxHQUFHLElBQUk7UUFHdEIsSUFBSSxJQUFJLEdBQUcsQ0FBQyxDQUFDLEtBQUssRUFBWSxDQUFBO1FBQzlCLElBQUksUUFBUSxHQUFHLElBQUkscUNBQVEsQ0FDekI7WUFDRSxHQUFHLEVBQUUsSUFBSTtZQUNULEdBQUcsRUFBRSxJQUFJO1lBQ1QsTUFBTSxFQUFFLGFBQWE7WUFDckIsT0FBTyxFQUFFLFVBQVU7WUFDbkIsYUFBYSxFQUFFLGVBQWU7WUFDOUIsUUFBUSxFQUFFLElBQUk7WUFDZCxZQUFZLEVBQUUsVUFBVTtZQUN4QixrQkFBa0IsRUFBRSxlQUFlO1lBQ25DLFFBQVEsRUFBRSxJQUFJO1lBQ2QsWUFBWSxFQUFFLElBQUk7WUFDbEIsaUJBQWlCLEVBQUUsSUFBSTtTQUN4QixFQUNELElBQUksQ0FDTCxDQUFBO1FBQ0QsSUFBSSxDQUFDLE9BQU8sQ0FBQyxRQUFRLENBQUMsQ0FBQTtRQUN0QixNQUFNLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQTtJQUNyQixDQUFDO0NBQ0Y7QUFsRkQsa0NBa0ZDIn0=