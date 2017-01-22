"use strict";
require("typings-test");
const should = require("should");
const cflare = require("cflare");
const qenv = require("qenv");
let testQenv = new qenv.Qenv(process.cwd(), process.cwd() + '/.nogit');
// import the module to test
const smartacme = require("../dist/index");
let myCflareAccount = new cflare.CflareAccount();
myCflareAccount.auth({
    email: process.env.CF_EMAIL,
    key: process.env.CF_KEY
});
describe('smartacme', function () {
    let testSmartAcme;
    let testAcmeAccount;
    let testAcmeCert;
    let testChallenge;
    it('should create a valid instance', function (done) {
        this.timeout(10000);
        testSmartAcme = new smartacme.SmartAcme();
        testSmartAcme.init().then(() => {
            should(testSmartAcme).be.instanceOf(smartacme.SmartAcme);
            done();
        }).catch(err => { done(err); });
    });
    it('should have created keyPair', function () {
        should(testSmartAcme.acmeUrl).be.of.type('string');
    });
    it('should register a new account', function (done) {
        this.timeout(10000);
        testSmartAcme.createAcmeAccount().then(x => {
            testAcmeAccount = x;
            done();
        }).catch(err => {
            console.log(err);
            done(err);
        });
    });
    it('should create a AcmeCert', function () {
        testAcmeAccount.createAcmeCert('test1.bleu.de').then(x => {
            testAcmeCert = x;
            should(testAcmeAccount).be.instanceOf(smartacme.AcmeCert);
        });
    });
    it('should get a challenge for a AcmeCert', function (done) {
        this.timeout(10000);
        testAcmeCert.requestChallenge().then((challengeAccepted) => {
            console.log(challengeAccepted);
            testChallenge = challengeAccepted;
            done();
        });
    });
    it('should set the challenge', function (done) {
        this.timeout(30000);
        myCflareAccount.createRecord(testChallenge.domainNamePrefixed, 'TXT', testChallenge.dnsKeyHash).then(() => {
            done();
        });
    });
    it('should check for a DNS record', function (done) {
        this.timeout(40000);
        testAcmeCert.checkDns().then(x => {
            console.log(x);
            done();
        });
    });
    it('should poll for validation of a challenge', function (done) {
        this.timeout(700000);
        testAcmeCert.requestValidation().then(x => {
            console.log(x);
            done();
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFDaEMsaUNBQWdDO0FBQ2hDLDZCQUE0QjtBQUU1QixJQUFJLFFBQVEsR0FBRyxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxFQUFFLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxTQUFTLENBQUMsQ0FBQTtBQUV0RSw0QkFBNEI7QUFDNUIsMkNBQTBDO0FBRTFDLElBQUksZUFBZSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFBO0FBQ2hELGVBQWUsQ0FBQyxJQUFJLENBQUM7SUFDakIsS0FBSyxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUTtJQUMzQixHQUFHLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxNQUFNO0NBQzFCLENBQUMsQ0FBQTtBQUVGLFFBQVEsQ0FBQyxXQUFXLEVBQUU7SUFDbEIsSUFBSSxhQUFrQyxDQUFBO0lBQ3RDLElBQUksZUFBc0MsQ0FBQTtJQUMxQyxJQUFJLFlBQWdDLENBQUE7SUFDcEMsSUFBSSxhQUFvRCxDQUFBO0lBRXhELEVBQUUsQ0FBQyxnQ0FBZ0MsRUFBRSxVQUFVLElBQUk7UUFDL0MsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQixhQUFhLEdBQUcsSUFBSSxTQUFTLENBQUMsU0FBUyxFQUFFLENBQUE7UUFDekMsYUFBYSxDQUFDLElBQUksRUFBRSxDQUFDLElBQUksQ0FBQztZQUN0QixNQUFNLENBQUMsYUFBYSxDQUFDLENBQUMsRUFBRSxDQUFDLFVBQVUsQ0FBQyxTQUFTLENBQUMsU0FBUyxDQUFDLENBQUE7WUFDeEQsSUFBSSxFQUFFLENBQUE7UUFDVixDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQSxDQUFD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