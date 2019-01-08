import * as plugins from './smartacme.plugins';
import { CertManager } from './smartacme.classes.certmanager';
import { CertRemoteHandler } from './smartacme.classes.certremotehandler';

/**
 *
 */
export interface ISmartAcmeOptions {
  accountPrivateKey?: string;
  accountEmail: string;
  setChallenge: (domainName: string, keyAuthorization: string) => Promise<any>;
  removeChallenge: (domainName: string) => Promise<any>;
  mongoDescriptor: plugins.smartdata.IMongoDescriptor;
}

export class SmartAcme {
  private options: ISmartAcmeOptions;

  // the acme client
  private client: any;
  private smartdns = new plugins.smartdns.Smartdns();

  // the account private key
  private privateKey: string;

  // challenge fullfillment
  private setChallenge: (domainName: string, keyAuthorization: string) => Promise<any>;
  private removeChallenge: (domainName: string) => Promise<any>;

  // certmanager
  private certmanager: CertManager;
  private certremoteHandler: CertRemoteHandler;

  constructor(optionsArg: ISmartAcmeOptions) {
    this.options = optionsArg;
  }

  public async init() {
    this.privateKey = this.options.accountPrivateKey || (await plugins.acme.forge.createPrivateKey());
    this.setChallenge = this.options.setChallenge;
    this.removeChallenge = this.options.removeChallenge;

    this.certmanager = new CertManager({
      mongoDescriptor: this.options.mongoDescriptor
    });
    await this.certmanager.init();
    this.certremoteHandler = new CertRemoteHandler();

    this.client = new plugins.acme.Client({
      directoryUrl: plugins.acme.directory.letsencrypt.staging,
      accountKey: this.privateKey
    });

    /* Register account */
    await this.client.createAccount({
      termsOfServiceAgreed: true,
      contact: [`mailto:${this.options.accountEmail}`]
    });
  }

  public async getCertificateForDomain(domainArg: string) {
    const domain = domainArg;

    const retrievedCertificate = await this.certmanager.retrieveCertificate(domain);

    if(retrievedCertificate) {
      return retrievedCertificate;
    }

    /* Place new order */
    const order = await this.client.createOrder({
      identifiers: [{ type: 'dns', value: domain }, { type: 'dns', value: `*.${domain}` }]
    });

    /* Get authorizations and select challenges */
    const authorizations = await this.client.getAuthorizations(order);

    for (const authz of authorizations) {
      console.log(authz);
      const domainDnsName: string = `_acme-challenge.${authz.identifier.value}`;
      const dnsChallenge: string = authz.challenges.find(challengeArg => {
        return challengeArg.type === 'dns-01';
      });
      // process.exit(1);
      const keyAuthorization: string = await this.client.getChallengeKeyAuthorization(dnsChallenge);

      try {
        /* Satisfy challenge */
        await this.setChallenge(domainDnsName, keyAuthorization);
        await this.smartdns.checkUntilAvailable(domainDnsName, 'TXT', keyAuthorization, 100, 5000);

        /* Verify that challenge is satisfied */
        await this.client.verifyChallenge(authz, dnsChallenge);

        /* Notify ACME provider that challenge is satisfied */
        await this.client.completeChallenge(dnsChallenge);

        /* Wait for ACME provider to respond with valid status */
        await this.client.waitForValidStatus(dnsChallenge);
      } finally {
        /* Clean up challenge response */
        try {
          await this.removeChallenge(domainDnsName);
        } catch (e) {
          console.log(e);
        }
      }
    }

    /* Finalize order */
    const [key, csr] = await plugins.acme.forge.createCsr({
      commonName: `*.${domain}`,
      altNames: [domain]
    });

    await this.client.finalizeOrder(order, csr);
    const cert = await this.client.getCertificate(order);

    /* Done */
    console.log(`CSR:\n${csr.toString()}`);
    console.log(`Private key:\n${key.toString()}`);
    console.log(`Certificate:\n${cert.toString()}`);

    this.certmanager.storeCertificate(key.toString(), cert.toString(), csr.toString());
  }

  toStorageObject() {}
}
