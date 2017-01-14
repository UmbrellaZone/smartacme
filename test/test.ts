import 'typings-test'
import * as should from 'should'
import * as cflare from 'cflare'

// import the module to test
import * as smartacme from '../dist/index'

describe('smartacme', function () {
    let testSmartAcme: smartacme.SmartAcme
    let testAcmeAccount: smartacme.AcmeAccount
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
            done()
        }).catch(err => {
            console.log(err)
            done(err)
        })
    })

    it.skip('should request a cert for a domain', function (done) {
        this.timeout(10000)
        testAcmeAccount.requestChallenge('bleu.de').then((challengeAccepted) => {
            console.log(challengeAccepted)
            testChallenge = challengeAccepted
            done()
        })
    })

    it.skip('should poll for validation of a challenge', function (done) {
        this.timeout(10000)
        testSmartAcme.validate(testChallenge).then(x => {
            done()
        })
    })
})
