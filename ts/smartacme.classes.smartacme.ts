import * as plugins from './smartacme.plugins';

/**
 *
 */
export interface ISmartAcmeStorage {}

export class SmartAcme {
  // the acme client
  private client: any;

  // the account private key
  private privateKey: string;

  // challenge fullfillment
  private setChallenge: (authz, challenge, keyAuthorization) => Promise<any>;
  private removeChallenge: (authz, challenge, keyAuthorization) => Promise<any>;

  public async init(optionsArg: {
    accountPrivateKey?: string;
    accountEmail: string;
    setChallenge: (authz, challenge, keyAuthorization) => Promise<any>;
    removeChallenge: (authz, challenge, keyAuthorization) => Promise<any>;
  }) {
    this.privateKey = optionsArg.accountPrivateKey || (await plugins.acme.forge.createPrivateKey());
    this.setChallenge = optionsArg.setChallenge;
    this.removeChallenge = optionsArg.removeChallenge;
    this.client = new plugins.acme.Client({
      directoryUrl: plugins.acme.directory.letsencrypt.staging,
      accountKey: this.privateKey
    });

    /* Register account */
    await this.client.createAccount({
      termsOfServiceAgreed: true,
      contact: [`mailto:${optionsArg.accountEmail}`]
    });
  }

  public async getCertificateForDomain(domainArg: string) {
    const domain = domainArg;

    /* Place new order */
    const order = await this.client.createOrder({
      identifiers: [{ type: 'dns', value: domain }, { type: 'dns', value: `*.${domain}` }]
    });

    /* Get authorizations and select challenges */
    const authorizations = await this.client.getAuthorizations(order);

    const promises = authorizations.map(async authz => {
      const challenge = authz.challenges.pop();
      const keyAuthorization = await this.client.getChallengeKeyAuthorization(challenge);

      try {
        /* Satisfy challenge */
        await this.setChallenge(authz, challenge, keyAuthorization);

        /* Verify that challenge is satisfied */
        await this.client.verifyChallenge(authz, challenge);

        /* Notify ACME provider that challenge is satisfied */
        await this.client.completeChallenge(challenge);

        /* Wait for ACME provider to respond with valid status */
        await this.client.waitForValidStatus(challenge);
      } finally {
        /* Clean up challenge response */
        try {
          await this.removeChallenge(authz, challenge, keyAuthorization);
        } catch (e) {
          console.log(e);
        }
      }
    });

    /* Wait for challenges to complete */
    await Promise.all(promises);

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
  }

  toStorageObject () {};
}
