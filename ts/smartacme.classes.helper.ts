import 'typings-global'
let rsaKeygen = require('rsa-keygen')

export interface IRsaKeypair {
    publicKey: string
    privateKey: string
}

export class SmartacmeHelper {
    createKeypair(bit = 2048): IRsaKeypair {
        let result = rsaKeygen.generate(bit)
         return {
            publicKey:  result.public_key,
            privateKey: result.private_key
         }
    }
}