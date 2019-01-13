import * as plugins from './smartacme.plugins';
import { Cert } from './smartacme.classes.cert';
import { CertManager } from './smartacme.classes.certmanager';
import { CertMatcher } from './smartacme.classes.certmatcher';

import * as interfaces from './interfaces';
import { request } from 'http';

/**
 * the options for the class @see SmartAcme
 */
export interface ISmartAcmeOptions {
  accountPrivateKey?: string;
  accountEmail: string;
  mongoDescriptor: plugins.smartdata.IMongoDescriptor;
  setChallenge: (domainName: string, keyAuthorization: string) => Promise<any>;
  removeChallenge: (domainName: string) => Promise<any>;
  validateRemoteRequest: () => Promise<boolean>;
  environment: 'production' | 'integration';
}

/**
 * class SmartAcme
 * can be used for setting up communication with an ACME authority
 * 
 * ```ts
 * const mySmartAcmeInstance = new SmartAcme({
 *  // see ISmartAcmeOptions for options
 * })
 * ```
 */
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
  private validateRemoteRequest: () => Promise<boolean>;

  // certmanager
  private certmanager: CertManager;
  private certmatcher: CertMatcher;
  private certremoteHandler: plugins.smartexpress.Handler;

  constructor(optionsArg: ISmartAcmeOptions) {
    this.options = optionsArg;
  }

  /**
   * inits the instance
   * ```ts
   * await myCloudlyInstance.init() // does not support options
   * ```
   */
  public async init() {
    this.privateKey =
      this.options.accountPrivateKey || (await plugins.acme.forge.createPrivateKey());
    this.setChallenge = this.options.setChallenge;
    this.removeChallenge = this.options.removeChallenge;

    // CertMangaer
    this.certmanager = new CertManager(this, {
      mongoDescriptor: this.options.mongoDescriptor
    });
    await this.certmanager.init();

    // CertMatcher
    this.certmatcher = new CertMatcher();

    // CertRemoteHandler
    this.certremoteHandler = new plugins.smartexpress.Handler('POST', async (req, res) => {
      const requestBody: interfaces.ICertRemoteRequest = req.body;
      const status: interfaces.TCertStatus = await this.certmanager.getCertificateStatus(requestBody.domainName);
      const existingCertificate = await this.certmanager.retrieveCertificate(
        requestBody.domainName
      );
      let response: interfaces.ICertRemoteResponse;
      switch (status) {
         case 'existing':
          response = {
            status,
            certificate: {
              created: existingCertificate.created,
              csr: existingCertificate.csr,
              domainName: existingCertificate.domainName,
              privateKey: existingCertificate.privateKey,
              publicKey: existingCertificate.publicKey
            }
          };
          break;
        default:
          response = {
            status
          };
          break;
      }
      res.status(200);
      res.send(response);
      res.end();
    });

    // ACME Client
    this.client = new plugins.acme.Client({
      directoryUrl: (() => {
        if(this.options.environment === 'production') {
          return plugins.acme.directory.letsencrypt.production;
        } else {
          return plugins.acme.directory.letsencrypt.staging;
        }
      })(),
      accountKey: this.privateKey
    });

    /* Register account */
    await this.client.createAccount({
      termsOfServiceAgreed: true,
      contact: [`mailto:${this.options.accountEmail}`]
    });
  }

  public async stop() {
    await this.certmanager.smartdataDb.close();
  }

  public async getCertificateForDomain(domainArg: string): Promise<Cert> {
    const certDomain = this.certmatcher.getCertificateDomainNameByDomainName(domainArg);

    const retrievedCertificate = await this.certmanager.retrieveCertificate(certDomain);

    if (retrievedCertificate) {
      return retrievedCertificate;
    }

    /* Place new order */
    const order = await this.client.createOrder({
      identifiers: [{ type: 'dns', value: certDomain }, { type: 'dns', value: `*.${certDomain}` }]
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
        console.log('Cool down an extra 60 second for region availability');
        await plugins.smartdelay.delayFor(60000);

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
      commonName: `*.${certDomain}`,
      altNames: [certDomain]
    });

    await this.client.finalizeOrder(order, csr);
    const cert = await this.client.getCertificate(order);

    /* Done */
    console.log(`CSR:\n${csr.toString()}`);
    console.log(`Private key:\n${key.toString()}`);
    console.log(`Certificate:\n${cert.toString()}`);

    await this.certmanager.storeCertificate({
      domainName: certDomain,
      privateKey: key.toString(),
      publicKey: cert.toString(),
      csr: csr.toString(),
      created: Date.now()
    });

    const newCertificate = await this.certmanager.retrieveCertificate(certDomain);
    return newCertificate;
  }
}
