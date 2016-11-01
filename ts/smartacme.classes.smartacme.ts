import * as plugins from './smartacme.plugins'
import * as acmeclient from './smartacme.classes.acmeclient'

export class SmartAcme {
    acmeClient: acmeclient.AcmeClient
    constructor(directoryUrlArg: string = 'https://acme-staging.api.letsencrypt.org/directory') {
        this.acmeClient = new acmeclient.AcmeClient(directoryUrlArg)
    }
}
