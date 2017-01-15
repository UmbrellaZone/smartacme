import 'typings-test'
import * as should from 'should'
import * as cflare from 'cflare'
import * as qenv from 'qenv'

// import the module to test
import * as smartacme from '../dist/index'

describe('smartacme', function () {
    let testSmartAcme: smartacme.SmartAcme
    let testAcmeAccount: smartacme.AcmeAccount
    let testAcmeCert: smartacme.AcmeCert
    let testChallenge: smartacme.ISmartAcmeChallengeAccepted
    
    it('should create a valid instance', function (done) {
        this.timeout(10000)
        testSmartAcme = new smartacme.SmartAcme()
        testSmartAcme.init().then(() => {
            should(testSmartAcme).be.instanceOf(smartacme.SmartAcme)
            done()
        }).catch(err => { done(err) })
    })

    it('should have created keyPair', function () {
        should(testSmartAcme.acmeUrl).be.of.type('string')
    })

    it('should register a new account', function (done) {
        this.timeout(10000)
        testSmartAcme.createAccount().then(x => {
            testAcmeAccount = x
            done()
        }).catch(err => {
            console.log(err)
            done(err)
        })
    })

    it('should create a AcmeCert', function() {
        testAcmeAccount.createAcmeCert('test1.bleu.de').then(x => {
            testAcmeCert = x
            should(testAcmeAccount).be.instanceOf(smartacme.AcmeCert)
        })
    })

    it('should get a challenge for a AcmeCert', function (done) {
        this.timeout(10000)
        testAcmeCert.requestChallenge().then((challengeAccepted) => {
            console.log(challengeAccepted)
            testChallenge = challengeAccepted
            done()
        })
    })

    it('should check for a DNS record', function(done) {
        testAcmeCert.checkDns().then(x => {
            console.log(x)
            done()
        })
    })

    it.skip('should poll for validation of a challenge', function (done) {
        this.timeout(10000)
        testAcmeCert.requestValidation().then(x => {
            done()
        })
    })
})
