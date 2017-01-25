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
        testSmartAcme = new smartacme.SmartAcme(false);
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
        testAcmeAccount.createAcmeCert('carglide.com').then(x => {
            testAcmeCert = x;
            should(testAcmeAccount).be.instanceOf(smartacme.AcmeCert);
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
        this.timeout(10000);
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
        this.timeout(700000);
        testAcmeCert.requestValidation().then(x => {
            console.log(x);
            done();
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFDaEMsaUNBQWdDO0FBQ2hDLDZCQUE0QjtBQUU1QixJQUFJLFFBQVEsR0FBRyxJQUFJLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsRUFBRSxFQUFFLE9BQU8sQ0FBQyxHQUFHLEVBQUUsR0FBRyxTQUFTLENBQUMsQ0FBQTtBQUV0RSw0QkFBNEI7QUFDNUIsMkNBQTBDO0FBRTFDLElBQUksZUFBZSxHQUFHLElBQUksTUFBTSxDQUFDLGFBQWEsRUFBRSxDQUFBO0FBQ2hELGVBQWUsQ0FBQyxJQUFJLENBQUM7SUFDakIsS0FBSyxFQUFFLE9BQU8sQ0FBQyxHQUFHLENBQUMsUUFBUTtJQUMzQixHQUFHLEVBQUUsT0FBTyxDQUFDLEdBQUcsQ0FBQyxNQUFNO0NBQzFCLENBQUMsQ0FBQTtBQUVGLFFBQVEsQ0FBQyxXQUFXLEVBQUU7SUFDbEIsSUFBSSxhQUFrQyxDQUFBO0lBQ3RDLElBQUksZUFBc0MsQ0FBQTtJQUMxQyxJQUFJLFlBQWdDLENBQUE7SUFDcEMsSUFBSSxhQUFrRCxDQUFBO0lBRXRELEVBQUUsQ0FBQyxnQ0FBZ0MsRUFBRSxVQUFVLElBQUk7UUFDL0MsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQixhQUFhLEdBQUcsSUFBSSxTQUFTLENBQUMsU0FBUyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQzlDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsQ0FBQyxJQUFJLENBQUM7WUFDdEIsTUFBTSxDQUFDLGFBQWEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQyxDQUFBO1lBQ3hELElBQUksRUFBRSxDQUFBO1FBQ1YsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUcsTUFBTSxJQUFJLENBQUMsR0FBRyxDQUFD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