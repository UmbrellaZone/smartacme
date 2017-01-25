// third party modules
import * as q from 'q' // promises
import * as plugins from './smartacme.plugins'
import * as helpers from './smartacme.helpers'

import { AcmeAccount } from './smartacme.classes.acmeaccount'

/**
 * a rsa keypair needed for account creation and subsequent requests
 */
export interface IRsaKeypair {
    publicKey: string
    privateKey: string
}

export { AcmeAccount } from './smartacme.classes.acmeaccount'
export { AcmeCert, ISmartAcmeChallenge, ISmartAcmeChallengeChosen } from './smartacme.classes.acmecert'

/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export class SmartAcme {
    acmeUrl: string // the acme url to use for this instance
    productionBool: boolean // a boolean to quickly know wether we are in production or not
    keyPair: IRsaKeypair // the keyPair needed for account creation
    rawacmeClient

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
     * init the smartacme instance
     */
    init() {
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
                done.resolve()
            }
        )
        return done.promise
    }

    /**
     * creates an account if not currently present in module
     * @executes ASYNC
     */
    createAcmeAccount() {
        let done = q.defer<AcmeAccount>()
        let acmeAccount = new AcmeAccount(this)
        acmeAccount.register().then(() => {
            return acmeAccount.agreeTos()
        }).then(() => {
            done.resolve(acmeAccount)
        })
        return done.promise
    }
}
