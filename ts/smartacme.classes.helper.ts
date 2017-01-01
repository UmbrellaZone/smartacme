import 'typings-global'
import * as q from 'q'
let rsaKeygen = require('rsa-keygen')

import { SmartAcme } from './smartacme.classes.smartacme'

export interface IRsaKeypair {
    publicKey: string
    privateKey: string
}

export class SmartacmeHelper {
    parentSmartAcme: SmartAcme

    constructor(smartAcmeArg: SmartAcme) {
        this.parentSmartAcme = smartAcmeArg
    }

    /**
     * creates a keypair to use with requests and to generate JWK from
     */
    createKeypair(bit = 2048): IRsaKeypair {
        let result = rsaKeygen.generate(bit)
        return {
            publicKey: result.public_key,
            privateKey: result.private_key
        }
    }

    /**
     * getReg
     * @executes ASYNC
     */
    getReg() {
        let done = q.defer()
        let body = { resource: 'reg' }
        this.parentSmartAcme.rawacmeClient.post(
            this.parentSmartAcme.location,
            body, this.parentSmartAcme.keyPair,
            (err, res) => {
                if (err) {
                    console.error('smartacme: something went wrong:')
                    console.log(err)
                    done.reject(err)
                    return
                }
                console.log(JSON.stringify(res.body))
                done.resolve()
            }
        )
        return done.promise
    }
}