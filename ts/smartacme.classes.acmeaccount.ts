import * as q from 'q'

import * as plugins from './smartacme.plugins'
import * as helpers from './smartacme.helpers'

import { SmartAcme, IRsaKeypair } from './smartacme.classes.smartacme'
import { AcmeCert } from './smartacme.classes.acmecert'

/**
 * class AcmeAccount represents an AcmeAccount
 */
export class AcmeAccount {
    parentSmartAcme: SmartAcme
    location: string
    link: string
    JWK
    constructor(smartAcmeParentArg: SmartAcme) {
        this.parentSmartAcme = smartAcmeParentArg
    }

    /**
     * register the account with letsencrypt
     */
    register() {
        let done = q.defer()
        this.parentSmartAcme.rawacmeClient.newReg(
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
        return done.promise
    }

    /**
     * agree to letsencrypr terms of service
     */
    agreeTos() {
        let done = q.defer()
        let tosPart = this.link.split(',')[1]
        let tosLinkPortion = tosPart.split(';')[0]
        let url = tosLinkPortion.split(';')[0].trim().replace(/[<>]/g, '')
        this.parentSmartAcme.rawacmeClient.post(this.location, { Agreement: url, resource: 'reg' }, (err, res) => {
            if (err) {
                console.log(err)
                done.reject(err)
                return
            }
            done.resolve()
        })
        return done.promise
    }

    createAcmeCert(
        domainNameArg: string,
        countryArg = 'Germany',
        countryShortArg = 'DE',
        city = 'Bremen',
        companyArg = 'Some Company',
        companyShortArg = 'SC'

    ) {
        let done = q.defer<AcmeCert>()
        let acmeCert = new AcmeCert(
            {
                bit: 2064,
                key: null, // not needed right now
                domain: domainNameArg,
                country: countryArg,
                country_short: countryShortArg,
                locality: city,
                organization: companyArg,
                organization_short: companyShortArg,
                password: null,
                unstructured: null,
                subject_alt_names: null
            },
            this
        )
        done.resolve(acmeCert)
        return done.promise
    }
}
