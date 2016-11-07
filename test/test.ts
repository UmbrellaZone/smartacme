import 'typings-test'
import * as should from 'should'

// import the module to test
import * as smartacme from '../dist/index'

describe('smartacme', function(){
    let testAcme: smartacme.SmartAcme
    it('should create a valid instance', function(){
        testAcme = new smartacme.SmartAcme()
        should(testAcme).be.instanceOf(smartacme.SmartAcme)
    })
    it('should have created keyPair', function() {
        
    })
    it('should register a new account', function() {
        testAcme.createAccount()
    })
})
