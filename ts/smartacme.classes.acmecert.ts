import * as q from 'q'

import * as plugins from './smartacme.plugins'
import * as helpers from './smartacme.helpers'

import { SmartAcme, IRsaKeypair } from './smartacme.classes.smartacme'
import { AcmeAccount } from './smartacme.classes.acmeaccount'

/**
 * types of challenges supported by letsencrypt and this module
 */
export type TChallengeType = 'dns-01' | 'http-01'

/**
 * values that a challenge's status can have
 */
export type TChallengeStatus = 'pending'

export interface ISmartAcmeChallenge {
    uri: string
    status: TChallengeStatus
    type: TChallengeType
    token: string
    keyAuthorization: string
}

export interface ISmartAcmeChallengeChosen extends ISmartAcmeChallenge {
    dnsKeyHash: string
    domainName: string
    domainNamePrefixed: string
}

export interface IAcmeCsrConstructorOptions {
    bit: number,
    key: string,
    domain: string,
    country: string,
    country_short: string,
    locality: string,
    organization: string,
    organization_short: string,
    password: string,
    unstructured: string,
    subject_alt_names: string[]
}

// Dnsly instance (we really just need one)
let myDnsly = new plugins.dnsly.Dnsly('google')

/**
 * class AcmeCert represents a cert for domain
 */
export class AcmeCert {
    domainName: string
    attributes
    fullchain: string
    parentAcmeAccount: AcmeAccount
    csr
    validFrom: Date
    validTo: Date
    keypair: IRsaKeypair
    keyPairFinal: IRsaKeypair
    chosenChallenge: ISmartAcmeChallengeChosen
    dnsKeyHash: string
    constructor(optionsArg: IAcmeCsrConstructorOptions, parentAcmeAccount: AcmeAccount) {
        this.domainName = optionsArg.domain
        this.parentAcmeAccount = parentAcmeAccount
        this.keypair = helpers.createKeypair(optionsArg.bit)
        let privateKeyForged = plugins.nodeForge.pki.privateKeyFromPem(this.keypair.privateKey)
        let publicKeyForged = plugins.nodeForge.pki.publicKeyToPem(
            plugins.nodeForge.pki.setRsaPublicKey(privateKeyForged.n, privateKeyForged.e)
        )
        this.keyPairFinal = {
            privateKey: privateKeyForged,
            publicKey: publicKeyForged
        }

        // set dates
        this.validFrom = new Date()
        this.validTo = new Date()
        this.validTo.setDate(this.validFrom.getDate() + 90)

        // set attributes
        this.attributes = [
            { name: 'commonName', value: optionsArg.domain },
            { name: 'countryName', value: optionsArg.country },
            { shortName: 'ST', value: optionsArg.country_short },
            { name: 'localityName', value: optionsArg.locality },
            { name: 'organizationName', value: optionsArg.organization },
            { shortName: 'OU', value: optionsArg.organization_short },
            { name: 'challengePassword', value: optionsArg.password },
            { name: 'unstructuredName', value: optionsArg.unstructured }
        ]

        // set up csr
        this.csr = plugins.nodeForge.pki.createCertificationRequest()
        this.csr.setSubject(this.attributes)
        this.csr.setAttributes(this.attributes)
    }

    /**
     * requests a challenge for a domain
     * @param domainNameArg - the domain name to request a challenge for
     * @param challengeType - the challenge type to request
     */
    requestChallenge(challengeTypeArg: TChallengeType = 'dns-01') {
        let done = q.defer<ISmartAcmeChallengeChosen>()
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.newAuthz(
            {
                identifier: {
                    type: 'dns',
                    value: this.domainName
                }
            },
            this.parentAcmeAccount.parentSmartAcme.keyPair,
            (err, res) => {
                if (err) {
                    console.error('smartacme: something went wrong:')
                    console.log(err)
                    done.reject(err)
                }
                let preChosenChallenge = res.body.challenges.filter(x => {
                    return x.type === challengeTypeArg
                })[0]

                /**
                 * the key is needed to accept the challenge
                 */
                let authKey: string = plugins.rawacme.keyAuthz(
                    preChosenChallenge.token,
                    this.parentAcmeAccount.parentSmartAcme.keyPair.publicKey
                )

                /**
                 * needed in case selected challenge is of type dns-01
                 */
                this.dnsKeyHash = plugins.rawacme.dnsKeyAuthzHash(authKey) // needed if dns challenge is chosen
                /**
                 * the return challenge
                 */
                this.chosenChallenge = {
                    uri: preChosenChallenge.uri,
                    type: preChosenChallenge.type,
                    token: preChosenChallenge.token,
                    keyAuthorization: authKey,
                    status: preChosenChallenge.status,
                    dnsKeyHash: this.dnsKeyHash,
                    domainName: this.domainName,
                    domainNamePrefixed: helpers.prefixName(this.domainName)
                }
                done.resolve(this.chosenChallenge)
            }
        )
        return done.promise
    }

    /**
     * checks if DNS records are set, will go through a max of 30 cycles
     */
    async checkDns(cycleArg = 1) {
        let result = await myDnsly.checkUntilAvailable(helpers.prefixName(this.domainName), 'TXT', this.dnsKeyHash)
        if (result) {
            console.log('DNS is set!')
            return
        } else {
            throw new Error('DNS not set!')
        }
    }

    /**
     * validates a challenge, only call after you have set the challenge at the expected location
     */
    async requestValidation() {
        let makeRequest = () => {
            let done = q.defer()
            this.parentAcmeAccount.parentSmartAcme.rawacmeClient.poll(this.chosenChallenge.uri, async (err, res) => {
                if (err) {
                    console.log(err)
                    return
                }
                console.log(`Validation response:`)
                console.log(JSON.stringify(res.body))
                if (res.body.status === 'pending' || res.body.status === 'invalid') {
                    await plugins.smartdelay.delayFor(3000)
                    makeRequest().then((x: any) => { done.resolve(x) })
                } else {
                    console.log('perfect!')
                    done.resolve(res.body)
                }
            })
            return done.promise
        }
        await makeRequest()
    }

    /**
     * requests a certificate
     */
    requestCert() {
        let done = q.defer()
        let payload = {
            csr: plugins.rawacme.base64.encode(
                plugins.rawacme.toDer(
                    plugins.nodeForge.pki.certificationRequestToPem(
                        this.csr
                    )
                )
            ),
            notBefore: this.validFrom.toISOString(),
            notAfter: this.validTo.toISOString()
        }
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.newCert(
            payload,
            helpers.createKeypair(),
            (err, res) => {
                if (err) {
                    console.log(err)
                    done.reject(err)
                }
                console.log(res.body)
                done.resolve(res.body)
            })
        return done.promise
    }

    /**
     * getCertificate - takes care of cooldown, validation polling and certificate retrieval
     */
    getCertificate() {

    }

    /**
     * accept a challenge - for private use only
     */
    acceptChallenge() {
        let done = q.defer()
        this.parentAcmeAccount.parentSmartAcme.rawacmeClient.post(
            this.chosenChallenge.uri,
            {
                resource: 'challenge',
                keyAuthorization: this.chosenChallenge.keyAuthorization
            },
            this.parentAcmeAccount.parentSmartAcme.keyPair,
            (err, res) => {
                if (err) {
                    console.log(err)
                    done.reject(err)
                }
                done.resolve(res.body)
            }
        )
        return done.promise
    }
}
