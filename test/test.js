"use strict";
require("typings-test");
const should = require("should");
// import the module to test
const smartacme = require("../dist/index");
describe('smartacme', function () {
    let testSmartAcme;
    let testAcmeAccount;
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
        testSmartAcme.createAccount().then(x => {
            done();
        }).catch(err => {
            console.log(err);
            done(err);
        });
    });
    it.skip('should request a cert for a domain', function (done) {
        this.timeout(10000);
        testAcmeAccount.requestChallenge('bleu.de').then((challengeAccepted) => {
            console.log(challengeAccepted);
            testChallenge = challengeAccepted;
            done();
        });
    });
    it.skip('should poll for validation of a challenge', function (done) {
        this.timeout(10000);
        testSmartAcme.validate(testChallenge).then(x => {
            done();
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFHaEMsNEJBQTRCO0FBQzVCLDJDQUEwQztBQUUxQyxRQUFRLENBQUMsV0FBVyxFQUFFO0lBQ2xCLElBQUksYUFBa0MsQ0FBQTtJQUN0QyxJQUFJLGVBQXNDLENBQUE7SUFDMUMsSUFBSSxhQUFvRCxDQUFBO0lBQ3hELEVBQUUsQ0FBQyxnQ0FBZ0MsRUFBRSxVQUFVLElBQUk7UUFDL0MsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQixhQUFhLEdBQUcsSUFBSSxTQUFTLENBQUMsU0FBUyxFQUFFLENBQUE7UUFDekMsYUFBYSxDQUFDLElBQUksRUFBRSxDQUFDLElBQUksQ0FBQztZQUN0QixNQUFNLENBQUMsYUFBYSxDQUFDLENBQUMsRUFBRSxDQUFDLFVBQVUsQ0FBQyxTQUFTLENBQUMsU0FBUyxDQUFDLENBQUE7WUFDeEQsSUFBSSxFQUFFLENBQUE7UUFDVixDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsR0FBRyxNQUFNLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQSxDQUFDLENBQUMsQ0FBQyxDQUFBO0lBQ2xDLENBQUMsQ0FBQyxDQUFBO0lBRUYsRUFBRSxDQUFDLDZCQUE2QixFQUFFO1FBQzlCLE1BQU0sQ0FBQyxhQUFhLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUE7SUFDdEQsQ0FBQyxDQUFDLENBQUE7SUFFRixFQUFFLENBQUMsK0JBQStCLEVBQUUsVUFBVSxJQUFJO1FBQzlDLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUE7UUFDbkIsYUFBYSxDQUFDLGFBQWEsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQ2hDLElBQUksRUFBRSxDQUFBO1FBQ1YsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUc7WUFDUixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO1lBQ2hCLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUNiLENBQUMsQ0FBQyxDQUFBO0lBQ04sQ0FBQyxDQUFDLENBQUE7SUFFRixFQUFFLENBQUMsSUFBSSxDQUFDLG9DQUFvQyxFQUFFLFVBQVUsSUFBSTtRQUN4RCxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ25CLGVBQWUsQ0FBQyxnQkFBZ0IsQ0FBQyxTQUFTLENBQUMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxpQkFBaUI7WUFDL0QsT0FBTyxDQUFDLEdBQUcsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFBO1lBQzlCLGFBQWEsR0FBRyxpQkFBaUIsQ0FBQTtZQUNqQyxJQUFJLEVBQUUsQ0FBQTtRQUNWLENBQUMsQ0FBQyxDQUFBO0lBQ04sQ0FBQyxDQUFDLENBQUE7SUFFRixFQUFFLENBQUMsSUFBSSxDQUFDLDJDQUEyQyxFQUFFLFVBQVUsSUFBSTtRQUMvRCxJQUFJLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFBO1FBQ25CLGFBQWEsQ0FBQyxRQUFRLENBQUMsYUFBYSxDQUFDLENBQUMsSUFBSSxDQUFDLENBQUM7WUFDeEMsSUFBSSxFQUFFLENBQUE7UUFDVixDQUFDLENBQUMsQ0FBQTtJQUNOLENBQUMsQ0FBQyxDQUFBO0FBQ04sQ0FBQyxDQUFDLENBQUEifQ==