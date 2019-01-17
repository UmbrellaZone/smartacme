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
  environment: 'production' | 'integration';
  logger?: plugins.smartlog.Smartlog;
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
  public logger: plugins.smartlog.Smartlog;

  // the account private key
  private privateKey: string;

  // challenge fullfillment
  private setChallenge: (domainName: string, keyAuthorization: string) => Promise<any>;
  private removeChallenge: (domainName: string) => Promise<any>;

  // certmanager
  private certmanager: CertManager;
  private certmatcher: CertMatcher;

  /**
   * the remote handler to hand the request and response to.
   */
  public certremoteHandler = async (
    req: plugins.smartexpress.Request,
    res: plugins.smartexpress.Response
  ) => {
    const requestBody: interfaces.ICertRemoteRequest = req.body;
    this.logger.log('ok', `got certificate request for ${requestBody.domainName}`);
    const certDomain = this.certmatcher.getCertificateDomainNameByDomainName(
      requestBody.domainName
    );
    this.logger.log('ok', `mapping ${requestBody.domainName} to ${certDomain}`);
    let status: interfaces.TCertStatus = await this.certmanager.getCertificateStatus(certDomain);
    let response: interfaces.ICertRemoteResponse;
    switch (status) {
      case 'existing':
        this.logger.log('ok', `certificate exists for ${certDomain}. Sending certificate!`);
        response = {
          status,
          certificate: await (await this.certmanager.retrieveCertificate(
            certDomain
          )).createSavableObject()
        };
        break;
      default:
        if (status === 'nonexisting') {
          this.getCertificateForDomain(certDomain);
          status = 'pending';
        }
        response = {
          status
        };
        break;
    }
    res.status(200);
    res.send(response);
    res.end();
  }

  constructor(optionsArg: ISmartAcmeOptions) {
    this.options = optionsArg;
    this.options.logger
      ? (this.logger = optionsArg.logger)
      : (this.logger = plugins.smartlog.defaultLogger);
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

    // ACME Client
    this.client = new plugins.acme.Client({
      directoryUrl: (() => {
        if (this.options.environment === 'production') {
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
    } else {
      await this.certmanager.announceCertificate(certDomain);
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

    await this.certmanager.storeCertificate({
      id: plugins.smartunique.shortId(),
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
