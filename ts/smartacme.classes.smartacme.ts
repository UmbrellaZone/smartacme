import 'typings-global'
import * as q from 'q'
import * as path from 'path'
let rsaKeygen = require('rsa-keygen')
import * as smartfile from 'smartfile'
import * as smartstring from 'smartstring'
let rawacme = require('rawacme')
import * as paths from './smartacme.paths'

import { SmartacmeHelper, IRsaKeypair } from './smartacme.classes.helper'

export type TChallenge = 'dns-01' | 'http-01'


/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export class SmartAcme {
    helper: SmartacmeHelper // bundles helper methods that would clutter the main SmartAcme class
    acmeUrl: string // the acme url to use
    productionBool: boolean // a boolean to quickly know wether we are in production or not
    keyPair: IRsaKeypair // the keyPair needed for account creation
    location: string
    link: string
    rawacmeClient
    JWK

    /**
     * the constructor for class SmartAcme
     */
    constructor(productionArg: boolean = false) {
        this.productionBool = productionArg
        this.helper = new SmartacmeHelper(this)
        this.keyPair = this.helper.createKeypair()
        if (this.productionBool) {
            this.acmeUrl = rawacme.LETSENCRYPT_URL
        } else {
            this.acmeUrl = rawacme.LETSENCRYPT_STAGING_URL
        }
    }

    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAccount() {
        let done = q.defer()
        rawacme.createClient(
            {
                url: this.acmeUrl,
                publicKey: this.keyPair.publicKey,
                privateKey: this.keyPair.privateKey
            },
            (err, client) => {
                if (err) {
                    console.error('smartacme: something went wrong:')
                    console.log(err)
                    done.reject(err)
                    return
                }

                // make client available in class 
                this.rawacmeClient = client

                // create the registration
                client.newReg(
                    {
                        contact: ['mailto:domains@lossless.org']
                    },
                    (err, res) => {
                        if (err) {
                            console.error('smartacme: something went wrong:')
                            console.log(err)
                            done.reject(err)
                            return
                        }
                        this.JWK = res.body.key
                        this.link = res.headers.link
                        console.log(this.link)
                        this.location = res.headers.location
                        done.resolve()
                    })

            }
        )
        return done.promise
    }

    agreeTos() {
        let done = q.defer()
        let tosPart = this.link.split(',')[1]
        let tosLinkPortion = tosPart.split(';')[0]
        let url = tosLinkPortion.split(';')[0].trim().replace(/[<>]/g, '')
        this.rawacmeClient.post(this.location, { Agreement: url, resource: 'reg' }, (err, res) => {
            if (err) {
                console.log(err)
                done.reject(err)
                return
            }
            done.resolve()
        })
        return done.promise
    }

    /**
     * requests a challenge for a domain
     * @param domainNameArg - the domain name to request a challenge for
     * @param challengeType - the challenge type to request
     */
    requestChallenge(domainNameArg: string, challengeTypeArg: TChallenge = 'dns-01') {
        let done = q.defer()
        this.rawacmeClient.newAuthz(
            {
                identifier: {
                    type: 'dns',
                    value: domainNameArg
                }
            },
            this.keyPair,
            (err, res) => {
                if (err) {
                    console.error('smartacme: something went wrong:')
                    console.log(err)
                    done.reject(err)
                }
                console.log(JSON.stringify(res.body))
                let dnsChallenge = res.body.challenges.filter(x => {
                    return x.type === challengeTypeArg
                })[0]
                this.acceptChallenge(dnsChallenge)
                    .then(x => {
                        done.resolve(x)
                    })
            }
        )
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
    private acceptChallenge(challenge) {
        let done = q.defer()

        let authKey: string = rawacme.keyAuthz(challenge.token, this.keyPair.publicKey)
        let dnsKeyHash: string = rawacme.dnsKeyAuthzHash(authKey) // needed if dns challenge is chosen

        console.log(authKey)

        this.rawacmeClient.post(
            challenge.uri,
            {
                resource: 'challenge',
                keyAuthorization: authKey
            },
            this.keyPair,
            (err, res) => {
                if (err) {
                    console.log(err)
                    done.reject(err)
                }
                console.log('acceptChallenge:')
                console.log(JSON.stringify(res.body))
                done.resolve(dnsKeyHash)
            }
        )
        return done.promise
    }


}
