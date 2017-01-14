"use strict";
require("typings-test");
const should = require("should");
// import the module to test
const smartacme = require("../dist/index");
describe('smartacme', function () {
    let testAcme;
    let testChallenge;
    it('should create a valid instance', function () {
        this.timeout(10000);
        testAcme = new smartacme.SmartAcme();
        should(testAcme).be.instanceOf(smartacme.SmartAcme);
    });
    it('should have created keyPair', function () {
        should(testAcme.acmeUrl).be.of.type('string');
    });
    it('should register a new account', function (done) {
        this.timeout(10000);
        testAcme.createAccount().then(x => {
            done();
        }).catch(err => {
            console.log(err);
            done(err);
        });
    });
    it('should agree to ToS', function (done) {
        this.timeout(10000);
        testAcme.agreeTos().then(() => {
            done();
        });
    });
    it('should request a challenge for a domain', function (done) {
        this.timeout(10000);
        testAcme.requestChallenge('bleu.de').then((challengeAccepted) => {
            console.log(challengeAccepted);
            testChallenge = challengeAccepted;
            done();
        });
    });
    it('should poll for validation of a challenge', function (done) {
        this.timeout(10000);
        testAcme.validate(testChallenge).then(x => {
            done();
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFFaEMsNEJBQTRCO0FBQzVCLDJDQUEwQztBQUUxQyxRQUFRLENBQUMsV0FBVyxFQUFFO0lBQ2xCLElBQUksUUFBNkIsQ0FBQTtJQUNqQyxJQUFJLGFBQW9ELENBQUE7SUFDeEQsRUFBRSxDQUFDLGdDQUFnQyxFQUFFO1FBQ2pDLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUE7UUFDbkIsUUFBUSxHQUFHLElBQUksU0FBUyxDQUFDLFNBQVMsRUFBRSxDQUFBO1FBQ3BDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQyxFQUFFLENBQUMsVUFBVSxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUMsQ0FBQTtJQUN2RCxDQUFDLENBQUMsQ0FBQTtJQUVGLEVBQUUsQ0FBQyw2QkFBNkIsRUFBRTtRQUM5QixNQUFNLENBQUMsUUFBUSxDQUFDLE9BQU8sQ0FBQyxDQUFDLEVBQUUsQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFBO0lBQ2pELENBQUMsQ0FBQyxDQUFBO0lBRUYsRUFBRSxDQUFDLCtCQUErQixFQUFFLFVBQVUsSUFBSTtRQUM5QyxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ25CLFFBQVEsQ0FBQyxhQUFhLEVBQUUsQ0FBQyxJQUFJLENBQUMsQ0FBQztZQUMzQixJQUFJLEVBQUUsQ0FBQTtRQUNWLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHO1lBQ1IsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUNoQixJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDYixDQUFDLENBQUMsQ0FBQTtJQUNOLENBQUMsQ0FBQyxDQUFBO0lBRUYsRUFBRSxDQUFDLHFCQUFxQixFQUFFLFVBQVMsSUFBSTtRQUNuQyxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ25CLFFBQVEsQ0FBQyxRQUFRLEVBQUUsQ0FBQyxJQUFJLENBQUM7WUFDckIsSUFBSSxFQUFFLENBQUE7UUFDVixDQUFDLENBQUMsQ0FBQTtJQUNOLENBQUMsQ0FBQyxDQUFBO0lBRUYsRUFBRSxDQUFDLHlDQUF5QyxFQUFFLFVBQVMsSUFBSTtRQUN2RCxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ25CLFFBQVEsQ0FBQyxnQkFBZ0IsQ0FBQyxTQUFTLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxpQkFBaUI7WUFDeEQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO1lBQzlCLGFBQWEsR0FBRyxpQkFBaUIsQ0FBQTtZQUNqQyxJQUFJLEVBQUUsQ0FBQTtRQUNWLENBQUMsQ0FBQyxDQUFBO0lBQ04sQ0FBQyxDQUFDLENBQUE7SUFFRixFQUFFLENBQUMsMkNBQTJDLEVBQUMsVUFBUyxJQUFJO1FBQ3hELElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUE7UUFDbkIsUUFBUSxDQUFDLFFBQVEsQ0FBQyxhQUFhLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQztZQUNuQyxJQUFJLEVBQUUsQ0FBQTtRQUNWLENBQUMsQ0FBQyxDQUFBO0lBQ04sQ0FBQyxDQUFDLENBQUE7QUFDTixDQUFDLENBQUMsQ0FBQSJ9