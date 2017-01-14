import * as plugins from './smartacme.plugins'
import * as helpers from './smartacme.helpers'

import { IRsaKeypair } from './smartacme.classes.smartacme'

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

export class AcmeCsr {
    validFrom: Date
    validTo: Date
    keypair: IRsaKeypair
    keyPairForged: IRsaKeypair
    constructor(optionsArg: IAcmeCsrConstructorOptions) {
        this.keypair = helpers.createKeypair(optionsArg.bit)
        let privateKeyForged = plugins.nodeForge.pki.privateKeyFromPem(this.keypair.privateKey)
        let publicKeyForged = plugins.nodeForge.pki.publicKeyToPem(
            plugins.nodeForge.pki.setRsaPublicKey(privateKeyForged.n, privateKeyForged.e)
        )
        this.keyPairForged = {
            privateKey: privateKeyForged,
            publicKey: publicKeyForged
        }

        // set dates
        this.validFrom = new Date()
        this.validTo = new Date()
        this.validTo.setDate(this.validFrom.getDate() + 90)

        // create the csr
        let attributes = [
            { name: "commonName", value: domain },
            { name: "countryName", value: country },
            { shortName: "ST", value: country_short },
            { name: "localityName", value: locality },
            { name: "organizationName", value: organization },
            { shortName: "OU", value: organization_short }
        ]

    }
}
