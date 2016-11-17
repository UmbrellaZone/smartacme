import 'typings-global'
import * as q from 'q'
import * as path from 'path'
import * as smartfile from 'smartfile'
import * as smartstring from 'smartstring'
import * as paths from './smartacme.paths'

let ACME = require('le-acme-core').ACME.create()
let RSA = require('rsa-compat').RSA

let bitlen = 1024
let exp = 65537
let options = {
    public: true,
    pem: true,
    internal: true
}
/**
 * class SmartAcme exports methods for maintaining SSL Certificates
 */
export class SmartAcme {
    preparedBool: boolean = false
    acmeUrls: any
    productionBool: boolean
    keyPair: any
    constructor(productionArg: boolean = false) {
        this.productionBool = productionArg
    }

    /**
     * prepares the SmartAcme class
     */
    prepareAcme() {
        let done = q.defer()
        if (this.preparedBool === false) {
            this.getAcmeUrls()
                .then(() => {
                    return this.createKeyPair()
                })
                .then((x) => {
                    console.log('prepared smartacme instance')
                    done.resolve()
                })
        } else {
            done.resolve()
        }
        return done.promise
    }

    /**
     * creates an account if not currently present in module
     */
    createAccount() {
        let done = q.defer()
        this.prepareAcme()
            .then(() => {
                let options = {
                    newRegUrl: this.acmeUrls.newReg,
                    email: 'domains@lossless.org', // valid email (server checks MX records)
                    accountKeypair: { // privateKeyPem or privateKeyJwt 
                        privateKeyPem: this.keyPair
                    },
                    agreeToTerms: function (tosUrl, done) {
                        done(null, tosUrl)
                    }
                }
                ACME.registerNewAccount(options, (err, regr) => {
                    if(err) {
                        console.log(err)
                        done.reject(err)
                    }
                    done.resolve(regr)
                })
            }).catch(err => { console.log(err) })

        return done.promise
    }

    /**
     * creates a keyPair
     */
    createKeyPair() {
        let done = q.defer()
        RSA.generateKeypair(bitlen, exp, options, (err, keypair) => {
            if (err) {
                console.log(err)
                done.reject(err)
            }
            console.log(keypair)
            this.keyPair = keypair
        })
        done.resolve()
        return done.promise
    }

    /**
     * gets the Acme Urls
     */
    getAcmeUrls() {
        let done = q.defer()
        ACME.getAcmeUrls(ACME.stagingServerUrl, (err, urls) => {
            if (err) {
                throw err
            }
            this.acmeUrls = urls
            console.log(this.acmeUrls)
            done.resolve()
        })
        return done.promise
    }
}
