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

    it('should get the ACME urls', function (done) {
        testAcme.getAcmeUrls().then(() => { done() })
    })

    it('should prepare the Instance', function (done) {
        testAcme.prepareAcme().then(done)
    })
    it('should have created keyPair', function () {

    })
    it('should register a new account', function (done) {
        testAcme.createAccount().then(x => {
            console.log(x)
            done()
        }).catch(err => {
            console.log(err)
            done(err)
        })
    })
})
