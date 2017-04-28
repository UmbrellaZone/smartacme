import 'typings-global'
import * as q from 'smartq'

import * as plugins from './smartacme.plugins'

import { SmartAcme, IRsaKeypair } from './smartacme.classes.smartacme'
import { AcmeAccount } from './smartacme.classes.acmeaccount'

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
 * prefix a domain name to make sure it complies with letsencrypt
 */
export let prefixName = (domainNameArg: string): string => {
  return '_acme-challenge.' + domainNameArg
}

/**
 * gets an existing registration
 * @executes ASYNC
 */
let getReg = (SmartAcmeArg: SmartAcme, location: string) => {
  let done = q.defer()
  let body = { resource: 'reg' }
  SmartAcmeArg.rawacmeClient.post(
    location,
    body,
    SmartAcmeArg.keyPair,
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
