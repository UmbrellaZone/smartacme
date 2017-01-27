"use strict";
require("typings-test");
const smartchai_1 = require("smartchai");
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
        testSmartAcme = new smartacme.SmartAcme(false);
        testSmartAcme.init().then(() => {
            smartchai_1.expect(testSmartAcme).to.be.instanceOf(smartacme.SmartAcme);
            done();
        }).catch(err => { done(err); });
    });
    it('should have created keyPair', function () {
        smartchai_1.expect(testSmartAcme.acmeUrl).to.be.a('string');
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
        testAcmeAccount.createAcmeCert('test2.bleu.de').then(x => {
            testAcmeCert = x;
            smartchai_1.expect(testAcmeAccount).to.be.instanceOf(smartacme.AcmeCert);
        });
    });
    it('should get a challenge for a AcmeCert', function (done) {
        this.timeout(10000);
        testAcmeCert.requestChallenge().then((challengeChosen) => {
            console.log(challengeChosen);
            testChallenge = challengeChosen;
            done();
        });
    });
    it('should set the challenge', function (done) {
        this.timeout(20000);
        myCflareAccount.createRecord(testChallenge.domainNamePrefixed, 'TXT', testChallenge.dnsKeyHash).then(() => {
            done();
        });
    });
    it('should check for a DNS record', function (done) {
        this.timeout(20000);
        testAcmeCert.checkDns().then(x => {
            console.log(x);
            done();
        });
    });
    it('should accept the challenge', function (done) {
        this.timeout(10000);
        testAcmeCert.acceptChallenge().then(() => { done(); });
    });
    it('should poll for validation of a challenge', function (done) {
        this.timeout(10000);
        testAcmeCert.requestValidation().then(x => {
            console.log(x);
            done();
        });
    });
    it('should remove the challenge', function (done) {
        this.timeout(20000);
        myCflareAccount.removeRecord(testChallenge.domainNamePrefixed, 'TXT').then(() => {
            done();
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQix5Q0FBa0M7QUFDbEMsaUNBQWdDO0FBQ2hDLDZCQUE0QjtBQUU1QixJQUFJLFFBQVEsR0FBRyxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxFQUFFLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxTQUFTLENBQUMsQ0FBQTtBQUV0RSw0QkFBNEI7QUFDNUIsMkNBQTBDO0FBRTFDLElBQUksZUFBZSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFBO0FBQ2hELGVBQWUsQ0FBQyxJQUFJLENBQUM7SUFDakIsS0FBSyxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUTtJQUMzQixHQUFHLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxNQUFNO0NBQzFCLENBQUMsQ0FBQTtBQUVGLFFBQVEsQ0FBQyxXQUFXLEVBQUU7SUFDbEIsSUFBSSxhQUFrQyxDQUFBO0lBQ3RDLElBQUksZUFBc0MsQ0FBQTtJQUMxQyxJQUFJLFlBQWdDLENBQUE7SUFDcEMsSUFBSSxhQUFrRCxDQUFBO0lBRXRELEVBQUUsQ0FBQyxnQ0FBZ0MsRUFBRSxVQUFVLElBQUk7UUFDL0MsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQixhQUFhLEdBQUcsSUFBSSxTQUFTLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQzlDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQyxJQUFJLENBQUM7WUFDdEIsa0JBQU0sQ0FBQyxhQUFhLENBQUMsQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLFVBQVUsQ0FBQyxTQUFTLENBQUMsU0FBUyxDQUFDLENBQUE7WUFDM0QsSUFBSSxFQUFFLENBQUE7UUFDVixDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxNQUFNLElBQUksQ0FB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