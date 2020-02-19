import * as plugins from './smartacme.plugins';
import { Cert } from './smartacme.classes.cert';
import { CertManager } from './smartacme.classes.certmanager';
import { CertMatcher } from './smartacme.classes.certmatcher';

/**
 * the options for the class @see SmartAcme
 */
export interface ISmartAcmeOptions {
  accountPrivateKey?: string;
  accountEmail: string;
  mongoDescriptor: plugins.smartdata.IMongoDescriptor;
  setChallenge: (dnsChallengeArg: plugins.tsclass.network.IDnsChallenge) => Promise<any>;
  removeChallenge: (dnsChallengeArg: plugins.tsclass.network.IDnsChallenge) => Promise<any>;
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
  private smartdns = new plugins.smartdns.Smartdns({});
  public logger: plugins.smartlog.Smartlog;

  // the account private key
  private privateKey: string;

  // challenge fullfillment
  private setChallenge: (dnsChallengeArg: plugins.tsclass.network.IDnsChallenge) => Promise<any>;
  private removeChallenge: (dnsChallengeArg: plugins.tsclass.network.IDnsChallenge) => Promise<any>;

  // certmanager
  private certmanager: CertManager;
  private certmatcher: CertMatcher;

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
      this.options.accountPrivateKey || (await plugins.acme.forge.createPrivateKey()).toString();
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

  /**
   * gets a certificate
   * it runs through the following steps
   *
   * * look in the database
   * * if in the database and still valid return it
   * * if not in the database announce it
   * * then get it from letsencrypt
   * * store it
   * * remove it from the pending map (which it go onto by announcing it)
   * * retrieve it from the databse and return it
   *
   * @param domainArg
   */
  public async getCertificateForDomain(domainArg: string): Promise<Cert> {
    const certDomainName = this.certmatcher.getCertificateDomainNameByDomainName(domainArg);
    const retrievedCertificate = await this.certmanager.retrieveCertificate(certDomainName);

    if (!retrievedCertificate && await this.certmanager.interestMap.checkInterest(certDomainName)) {
      const existingCertificateInterest = this.certmanager.interestMap.findInterest(certDomainName);
      const certificate = existingCertificateInterest.interestFullfilled;
      return certificate;
    } else if (retrievedCertificate && !retrievedCertificate.shouldBeRenewed()) {
      return retrievedCertificate;
    } else if (retrievedCertificate && retrievedCertificate.shouldBeRenewed()) {
      // await retrievedCertificate.delete();
    }

    // lets make sure others get the same interest
    const currentDomainInterst = await this.certmanager.interestMap.addInterest(certDomainName);
    

    /* Place new order */
    const order = await this.client.createOrder({
      identifiers: [
        { type: 'dns', value: certDomainName },
        { type: 'dns', value: `*.${certDomainName}` }
      ]
    });

    /* Get authorizations and select challenges */
    const authorizations = await this.client.getAuthorizations(order);

    for (const authz of authorizations) {
      console.log(authz);
      const fullHostName: string = `_acme-challenge.${authz.identifier.value}`;
      const dnsChallenge: string = authz.challenges.find(challengeArg => {
        return challengeArg.type === 'dns-01';
      });
      // process.exit(1);
      const keyAuthorization: string = await this.client.getChallengeKeyAuthorization(dnsChallenge);

      try {
        /* Satisfy challenge */
        await this.setChallenge({
          hostName: fullHostName,
          challenge: keyAuthorization
        });
        await this.smartdns.checkUntilAvailable(fullHostName, 'TXT', keyAuthorization, 100, 5000);
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
          await this.removeChallenge({
            hostName: fullHostName,
            challenge: keyAuthorization
          });
        } catch (e) {
          console.log(e);
        }
      }
    }

    /* Finalize order */
    const [key, csr] = await plugins.acme.forge.createCsr({
      commonName: `*.${certDomainName}`,
      altNames: [certDomainName]
    });

    await this.client.finalizeOrder(order, csr);
    const cert = await this.client.getCertificate(order);

    /* Done */

    await this.certmanager.storeCertificate({
      id: plugins.smartunique.shortId(),
      domainName: certDomainName,
      privateKey: key.toString(),
      publicKey: cert.toString(),
      csr: csr.toString(),
      created: Date.now(),
      validUntil:
        Date.now() +
        plugins.smarttime.getMilliSecondsFromUnits({
          days: 90
        })
    });

    const newCertificate = await this.certmanager.retrieveCertificate(certDomainName);
    currentDomainInterst.fullfillInterest(newCertificate);
    currentDomainInterst.destroy();
    return newCertificate;
  }
}
