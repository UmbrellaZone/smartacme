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
    it('should have created keyPair', function () {
        should(testAcme.acmeUrl).be.of.type('string');
    });
    it('should register a new account', function (done) {
        this.timeout(40000);
        testAcme.createAccount().then(x => {
            done();
        }).catch(err => {
            console.log(err);
            done(err);
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFFaEMsNEJBQTRCO0FBQzVCLDJDQUEwQztBQUUxQyxRQUFRLENBQUMsV0FBVyxFQUFFO0lBQ2xCLElBQUksUUFBNkIsQ0FBQTtJQUNqQyxFQUFFLENBQUMsZ0NBQWdDLEVBQUU7UUFDakMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsQ0FBQTtRQUNuQixRQUFRLEdBQUcsSUFBSSxTQUFTLENBQUMsU0FBUyxFQUFFLENBQUE7UUFDcEMsTUFBTSxDQUFDLFFBQVEsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxVQUFVLENBQUMsU0FBUyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0lBQ3ZELENBQUMsQ0FBQyxDQUFBO0lBQ0YsRUFBRSxDQUFDLDZCQUE2QixFQUFFO1FBQzlCLE1BQU0sQ0FBQyxRQUFRLENBQUMsT0FBTyxDQUFDLENBQUMsRUFBRSxDQUFDLEVBQUUsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUE7SUFDakQsQ0FBQyxDQUFDLENBQUE7SUFDRixFQUFFLENBQUMsK0JBQStCLEVBQUUsVUFBVSxJQUFJO1FBQzlDLElBQUksQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUE7UUFDbkIsUUFBUSxDQUFDLGFBQWEsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDO1lBQzNCLElBQUksRUFBRSxDQUFBO1FBQ1YsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLEdBQUc7WUFDUixPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFBO1lBQ2hCLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQTtRQUNiLENBQUMsQ0FBQyxDQUFBO0lBQ04sQ0FBQyxDQUFDLENBQUE7QUFDTixDQUFDLENBQUMsQ0FBQSJ9