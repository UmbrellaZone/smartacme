"use strict";
require("typings-test");
const should = require("should");
// import the module to test
const smartacme = require("../dist/index");
describe('smartacme', function () {
    let testAcme;
    it('should create a valid instance', function () {
        testAcme = new smartacme.SmartAcme();
        should(testAcme).be.instanceOf(smartacme.SmartAcme);
    });
    it('should register a new account', function () {
        testAcme.createAccount();
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IjtBQUFBLHdCQUFxQjtBQUNyQixpQ0FBZ0M7QUFFaEMsNEJBQTRCO0FBQzVCLDJDQUEwQztBQUUxQyxRQUFRLENBQUMsV0FBVyxFQUFFO0lBQ2xCLElBQUksUUFBNkIsQ0FBQTtJQUNqQyxFQUFFLENBQUMsZ0NBQWdDLEVBQUU7UUFDakMsUUFBUSxHQUFHLElBQUksU0FBUyxDQUFDLFNBQVMsRUFBRSxDQUFBO1FBQ3BDLE1BQU0sQ0FBQyxRQUFRLENBQUMsQ0FBQyxFQUFFLENBQUMsVUFBVSxDQUFDLFNBQVMsQ0FBQyxTQUFTLENBQUMsQ0FBQTtJQUN2RCxDQUFDLENBQUMsQ0FBQTtJQUNGLEVBQUUsQ0FBQywrQkFBK0IsRUFBRTtRQUNoQyxRQUFRLENBQUMsYUFBYSxFQUFFLENBQUE7SUFDNUIsQ0FBQyxDQUFDLENBQUE7QUFDTixDQUFDLENBQUMsQ0FBQSJ9