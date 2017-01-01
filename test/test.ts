import 'typings-test'
import * as should from 'should'

// import the module to test
import * as smartacme from '../dist/index'

describe('smartacme', function () {
    let testAcme: smartacme.SmartAcme
    
    it('should create a valid instance', function () {
        this.timeout(10000)
        testAcme = new smartacme.SmartAcme()
        should(testAcme).be.instanceOf(smartacme.SmartAcme)
    })
    
    it('should have created keyPair', function () {
        should(testAcme.acmeUrl).be.of.type('string')
    })

    it('should register a new account', function (done) {
        this.timeout(10000)
        testAcme.createAccount().then(x => {
            done()
        }).catch(err => {
            console.log(err)
            done(err)
        })
    })

    it('should agree to ToS', function(done) {
        this.timeout(10000)
        testAcme.agreeTos().then(() => {
            done()
        })
    })

    it('should request a challenge for a domain', function(done) {
        this.timeout(10000)
        testAcme.requestChallenge('bleu.de').then(() => {
            done()
        })
    })
})
