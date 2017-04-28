import { expect, tap } from 'tapbundle'
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

let testSmartAcme: smartacme.SmartAcme
let testAcmeAccount: smartacme.AcmeAccount
let testAcmeCert: smartacme.AcmeCert
let testChallenge: smartacme.ISmartAcmeChallengeChosen

tap.test('smartacme -> should create a valid instance', async (tools) => {
  tools.timeout(10000)
  testSmartAcme = new smartacme.SmartAcme(false)
  await testSmartAcme.init().then(async () => {
    expect(testSmartAcme).to.be.instanceOf(smartacme.SmartAcme)
  })
})

tap.test('smartacme -> should have created keyPair', async () => {
  expect(testSmartAcme.acmeUrl).to.be.a('string')
})

tap.test('smartacme -> should register a new account', async (tools) => {
  tools.timeout(10000)
  await testSmartAcme.createAcmeAccount().then(async x => {
    testAcmeAccount = x
  })
})

tap.test('smartacme -> should create a AcmeCert', async () => {
  await testAcmeAccount.createAcmeCert('test2.bleu.de').then(async x => {
    testAcmeCert = x
    expect(testAcmeAccount).to.be.instanceOf(smartacme.AcmeCert)
  })
})

tap.test('smartacme -> should get a challenge for a AcmeCert', async (tools) => {
  tools.timeout(10000)
  await testAcmeCert.requestChallenge().then(async (challengeChosen) => {
    console.log(challengeChosen)
    testChallenge = challengeChosen
  })
})

tap.test('smartacme -> should set the challenge', async (tools) => {
  tools.timeout(20000)
  await myCflareAccount.createRecord(
    testChallenge.domainNamePrefixed,
    'TXT', testChallenge.dnsKeyHash
  )
})

tap.test('smartacme -> should check for a DNS record', async (tools) => {
  tools.timeout(20000)
  await testAcmeCert.checkDns().then(x => {
    console.log(x)
  })
})

tap.test('smartacme -> should accept the challenge', async (tools) => {
  tools.timeout(10000)
  await testAcmeCert.acceptChallenge()
})

tap.test('smartacme -> should poll for validation of a challenge', async (tools) => {
  tools.timeout(10000)
  await testAcmeCert.requestValidation().then(async x => {
    console.log(x)
  })
})

tap.test('smartacme -> should remove the challenge', async (tools) => {
  tools.timeout(20000)
  await myCflareAccount.removeRecord(
    testChallenge.domainNamePrefixed,
    'TXT'
  )
})

tap.start()
