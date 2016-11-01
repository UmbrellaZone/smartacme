import * as plugins from './smartacme.plugins'
import * as acmeclient from './smartacme.classes.acmeclient'

export class SmartAcme {
    acmeAccount: AcmeAccount
    acmeClient: acmeclient.AcmeClient
    constructor(directoryUrlArg: string = 'https://acme-staging.api.letsencrypt.org/directory') {
        this.acmeClient = new acmeclient.AcmeClient(directoryUrlArg)
    }

    createAccount() {
        this.acmeClient.createAccount('test@bleu.de',(answer) => {
            console.log(answer)
        })
    }
}

export class AcmeAccount {

}
