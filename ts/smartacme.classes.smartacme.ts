import 'typings-global'
import * as q from 'q'
import * as path from 'path'
let rsaKeygen = require('rsa-keygen')
import * as smartfile from 'smartfile'
import * as smartstring from 'smartstring'
let rawacme = require('rawacme')
import * as paths from './smartacme.paths'

import { SmartacmeHelper, IRsaKeypair } from './smartacme.classes.helper'

/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export class SmartAcme {
    helper: SmartacmeHelper // bundles helper methods that would clutter the main SmartAcme class
    acmeUrl: string // the acme url to use
    productionBool: boolean // a boolean to quickly know wether we are in production or not
    keyPair: IRsaKeypair // the keyPair needed for account creation
    JWK

    /**
     * the constructor for class SmartAcme
     */
    constructor(productionArg: boolean = false) {
        this.productionBool = productionArg
        this.helper = new SmartacmeHelper()
        this.keyPair = this.helper.createKeypair()
        if (this.productionBool) {
            this.acmeUrl = rawacme.LETSENCRYPT_STAGING_URL
        } else {
            this.acmeUrl = rawacme.LETSENCRYPT_URL
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
                        console.log(this.JWK)
                        done.resolve()
                    })

            }
        )
        return done.promise
    }
}
