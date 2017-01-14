// third party modules
import * as q from 'q' // promises
import * as plugins from './smartacme.plugins'
import * as helpers from './smartacme.helpers'

export interface IRsaKeypair {
    publicKey: string
    privateKey: string
}

export type TChallengeType = 'dns-01' | 'http-01'
export type TChallengeStatus = 'pending'

export interface ISmartAcmeChallenge {
    uri: string
    status: TChallengeStatus
    type: TChallengeType
    token: string
    keyAuthorization: string
}

export interface ISmartAcmeChallengeAccepted extends ISmartAcmeChallenge {
    keyHash: string
}

/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export class SmartAcme {
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
        this.keyPair = helpers.createKeypair()
        if (this.productionBool) {
            this.acmeUrl = plugins.rawacme.LETSENCRYPT_URL
        } else {
            this.acmeUrl = plugins.rawacme.LETSENCRYPT_STAGING_URL
        }
    }

    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAccount() {
        let done = q.defer()
        plugins.rawacme.createClient(
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
    requestChallenge(domainNameArg: string, challengeTypeArg: TChallengeType = 'dns-01') {
        let done = q.defer<ISmartAcmeChallengeAccepted>()
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
                    .then((x: ISmartAcmeChallengeAccepted) => {
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
     * validates a challenge
     */
    validate(challenge: ISmartAcmeChallengeAccepted) {
        let done = q.defer()
        this.rawacmeClient.poll(challenge.uri, function(err, res) {
            if (err) {
                console.log(err)
                done.reject(err)
            }
            console.log(res.status)
            console.log(JSON.stringify(res.body))
            done.resolve()
        })
        return done.promise
    }


    /**
     * accept a challenge - for private use only
     */
    private acceptChallenge(challenge: ISmartAcmeChallenge) {
        let done = q.defer()

        /**
         * the key is needed to accept the challenge
         */
        let authKey: string = plugins.rawacme.keyAuthz(challenge.token, this.keyPair.publicKey)

        /**
         * needed in case selected challenge is of type dns-01
         */
        let keyHash: string = plugins.rawacme.dnsKeyAuthzHash(authKey) // needed if dns challenge is chosen

        /**
         * the return challenge
         */
        let returnDNSChallenge: ISmartAcmeChallengeAccepted = {
            uri: challenge.uri,
            type: challenge.type,
            token: challenge.token,
            keyAuthorization: challenge.keyAuthorization,
            keyHash: keyHash,
            status: challenge.status
        }

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
                done.resolve(returnDNSChallenge)
            }
        )
        return done.promise
    }


}
