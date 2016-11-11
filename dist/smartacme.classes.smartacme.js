"use strict";
require("typings-global");
const q = require("q");
let ACME = require('le-acme-core').ACME.create();
let RSA = require('rsa-compat').RSA;
let bitlen = 1024;
let exp = 65537;
let options = {
    public: true,
    pem: true,
    internal: true
};
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
class SmartAcme {
    constructor(productionArg = false) {
        this.preparedBool = false;
        this.productionBool = productionArg;
    }
    /**
     * prepares the SmartAcme class
     */
    prepareAcme() {
        let done = q.defer();
        if (this.preparedBool === false) {
            this.getAcmeUrls()
                .then(() => {
                return this.createKeyPair();
            })
                .then((x) => {
                console.log('prepared smartacme instance');
                done.resolve();
            });
        }
        else {
            done.resolve();
        }
        return done.promise;
    }
    /**
     * creates an account if not currently present in module
     */
    createAccount() {
        let done = q.defer();
        this.prepareAcme()
            .then(() => {
            return this.createKeyPair();
        })
            .then(() => {
            let options = {
                newRegUrl: this.acmeUrls.newReg,
                email: 'domains@lossless.org',
                accountKeypair: {
                    privateKeyPem: this.keyPair
                },
                agreeToTerms: function (tosUrl, done) {
                    done(null, tosUrl);
                }
            };
            ACME.registerNewAccount(options, (err, regr) => {
                if (err) {
                    console.log(err);
                    done.reject(err);
                }
                done.resolve(regr);
            }); // returns "regr" registration data
        }).catch(err => { console.log(err); });
        return done.promise;
    }
    /**
     * creates a keyPair
     */
    createKeyPair() {
        let done = q.defer();
        RSA.generateKeypair(bitlen, exp, options, (err, keypair) => {
            if (err) {
                console.log(err);
                done.reject(err);
            }
            console.log(keypair);
            this.keyPair = keypair;
        });
        done.resolve();
        return done.promise;
    }
    /**
     * gets the Acme Urls
     */
    getAcmeUrls() {
        let done = q.defer();
        ACME.getAcmeUrls(ACME.stagingServerUrl, (err, urls) => {
            if (err) {
                throw err;
            }
            this.acmeUrls = urls;
            console.log(this.acmeUrls);
            done.resolve();
        });
        return done.promise;
    }
}
exports.SmartAcme = SmartAcme;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuc21hcnRhY21lLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSwwQkFBdUI7QUFDdkIsdUJBQXNCO0FBTXRCLElBQUksSUFBSSxHQUFHLE9BQU8sQ0FBQyxjQUFjLENBQUMsQ0FBQyxJQUFJLENBQUMsTUFBTSxFQUFFLENBQUE7QUFDaEQsSUFBSSxHQUFHLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFDLEdBQUcsQ0FBQTtBQUVuQyxJQUFJLE1BQU0sR0FBRyxJQUFJLENBQUE7QUFDakIsSUFBSSxHQUFHLEdBQUcsS0FBSyxDQUFBO0FBQ2YsSUFBSSxPQUFPLEdBQUc7SUFDVixNQUFNLEVBQUUsSUFBSTtJQUNaLEdBQUcsRUFBRSxJQUFJO0lBQ1QsUUFBUSxFQUFFLElBQUk7Q0FDakIsQ0FBQTtBQUNEOztHQUVHO0FBQ0g7SUFLSSxZQUFZLGdCQUF5QixLQUFLO1FBSjFDLGlCQUFZLEdBQVksS0FBSyxDQUFBO1FBS3pCLElBQUksQ0FBQyxjQUFjLEdBQUcsYUFBYSxDQUFBO0lBQ3ZDLENBQUM7SUFFRDs7T0FFRztJQUNILFdBQVc7UUFDUCxJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7UUFDcEIsRUFBRSxDQUFDLENBQUMsSUFBSSxDQUFDLFlBQVksS0FBSyxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQzlCLElBQUksQ0FBQyxXQUFXLEVBQUU7aUJBQ2IsSUFBSSxDQUFDO2dCQUNGLE1BQU0sQ0FBQyxJQUFJLENBQUMsYUFBYSxFQUFFLENBQUE7WUFDL0IsQ0FBQyxDQUFDO2lCQUNELElBQUksQ0FBQyxDQUFDLENBQUM7Z0JBQ0osT0FBTyxDQUFDLEdBQUcsQ0FBQyw2QkFBNkIsQ0FBQyxDQUFBO2dCQUMxQyxJQUFJLENBQUMsT0FBTyxFQUFFLENBQUE7WUFDbEIsQ0FBQyxD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