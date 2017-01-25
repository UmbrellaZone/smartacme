import 'typings-test'
import * as should from 'should'
import * as cflare from 'cflare'
import * as qenv from 'qenv'

let testQenv = new qenv.Qenv(process.cwd(), process.cwd() + '/.nogit')

// import the module to test
import * as smartacme from '../dist/index'

let myCflareAccount = new cflare.CflareAccount()
myCflareAccount.auth({
    email: process.env.CF_EMAIL,
    key: process.env.CF_KEY
})

describe('smartacme', function () {
    let testSmartAcme: smartacme.SmartAcme
    let testAcmeAccount: smartacme.AcmeAccount
    let testAcmeCert: smartacme.AcmeCert
    let testChallenge: smartacme.ISmartAcmeChallengeChosen
    
    it('should create a valid instance', function (done) {
        this.timeout(10000)
        testSmartAcme = new smartacme.SmartAcme(false)
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
        testSmartAcme.createAcmeAccount().then(x => {
            testAcmeAccount = x
            done()
        }).catch(err => {
            console.log(err)
            done(err)
        })
    })

    it('should create a AcmeCert', function() {
        testAcmeAccount.createAcmeCert('carglide.com').then(x => {
            testAcmeCert = x
            should(testAcmeAccount).be.instanceOf(smartacme.AcmeCert)
        })
    })

    it('should get a challenge for a AcmeCert', function (done) {
        this.timeout(10000)
        testAcmeCert.requestChallenge().then((challengeChosen) => {
            console.log(challengeChosen)
            testChallenge = challengeChosen
            done()
        })
    })

    it('should set the challenge', function(done) {
        this.timeout(10000)
        myCflareAccount.createRecord(
            testChallenge.domainNamePrefixed,
            'TXT', testChallenge.dnsKeyHash
        ).then(() => {
            done()
        })
    })

    it('should check for a DNS record', function(done) {
        this.timeout(20000)
        testAcmeCert.checkDns().then(x => {
            console.log(x)
            done()
        })
    })

    it('should accept the challenge', function(done){
        this.timeout(10000)
        testAcmeCert.acceptChallenge().then(() => { done() })
    })

    it('should poll for validation of a challenge', function (done) {
        this.timeout(700000)
        testAcmeCert.requestValidation().then(x => {
            console.log(x)
            done()
        })
    })
})
