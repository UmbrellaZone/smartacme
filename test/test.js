"use strict";
require("typings-test");
const should = require("should");
// import the module to test
const smartacme = require("../dist/index");
describe('smartacme', function () {
    let testAcme;
    it('should create a valid instance', function () {
        this.timeout(10000);
        testAcme = new smartacme.SmartAcme();
        should(testAcme).be.instanceOf(smartacme.SmartAcme);
    });
    it('should get the ACME urls', function (done) {
        testAcme.getAcmeUrls().then(() => { done(); });
    });
    it('should prepare the Instance', function (done) {
        testAcme.prepareAcme().then(done);
    });
    it('should have created keyPair', function () {
    });
    it('should register a new account', function (done) {
        testAcme.createAccount().then(x => {
            console.log(x);
            done();
        }).catch(err => {
            console.log(err);
            done(err);
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFFaEMsNEJBQTRCO0FBQzVCLDJDQUEwQztBQUUxQyxRQUFRLENBQUMsV0FBVyxFQUFFO0lBQ2xCLElBQUksUUFBNkIsQ0FBQTtJQUNqQyxFQUFFLENBQUMsZ0NBQWdDLEVBQUU7UUFDakMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQixRQUFRLEdBQUcsSUFBSSxTQUFTLENBQUMsU0FBUyxFQUFFLENBQUE7UUFDcEMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0lBQ3ZELENBQUMsQ0FBQyxDQUFBO0lBRUYsRUFBRSxDQUFDLDBCQUEwQixFQUFFLFVBQVUsSUFBSTtRQUN6QyxRQUFRLENBQUMsV0FBVyxFQUFFLENBQUMsSUFBSSxDQUFDLFFBQVEsSUFBSSxFQUFFLENBQUEsQ0FBQyxDQUFDLENBQUMsQ0FBQTtJQUNqRCxDQUFDLENBQUMsQ0FBQTtJQUVGLEVBQUUsQ0FBQyw2QkFBNkIsRUFBRSxVQUFVLElBQUk7UUFDNUMsUUFBUSxDQUFDLFdBQVcsRUFBRSxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsQ0FBQTtJQUNyQyxDQUFDLENBQUMsQ0FBQTtJQUNGLEVBQUUsQ0FBQyw2QkFBNkIsRUFBRTtJQUVsQyxDQUFDLENBQUMsQ0FBQTtJQUNGLEVBQUUsQ0FBQywrQkFBK0IsRUFBRSxVQUFVLElBQUk7UUFDOUMsUUFBUSxDQUFDLGFBQWEsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQzNCLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFDZCxJQUFJLEVBQUUsQ0FBQTtRQUNWLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxHQUFHO1lBQ1IsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUNoQixJQUFJLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDYixDQUFDLENBQUMsQ0FBQTtJQUNOLENBQUMsQ0FBQyxDQUFBO0FBQ04sQ0FBQyxDQUFDLENBQUEifQ==