import 'typings-global'
import * as q from 'q'

import * as plugins from './smartacme.plugins'

import { SmartAcme, IRsaKeypair } from './smartacme.classes.smartacme'



/**
 * creates a keypair to use with requests and to generate JWK from
 */
export let createKeypair = (bit = 2048): IRsaKeypair => {
    let result = plugins.rsaKeygen.generate(bit)
    return {
        publicKey: result.public_key,
        privateKey: result.private_key
    }
}

/**
 * gets an existing registration
 * @executes ASYNC
 */
let getReg = (smartAcmeArg: SmartAcme) => {
    let done = q.defer()
    let body = { resource: 'reg' }
    smartAcmeArg.rawacmeClient.post(
        smartAcmeArg.location,
        body, smartAcmeArg.keyPair,
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
