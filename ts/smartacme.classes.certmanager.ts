import * as plugins from './smartacme.plugins';
import { Cert } from './smartacme.classes.cert';
import { SmartAcme } from './smartacme.classes.smartacme';

import * as interfaces from './interfaces';

export class CertManager {
  // =========
  // STATIC
  // =========
  public static activeDB: plugins.smartdata.SmartdataDb;

  // =========
  // INSTANCE
  // =========
  private mongoDescriptor: plugins.smartdata.IMongoDescriptor;
  public smartdataDb: plugins.smartdata.SmartdataDb;

  public pendingMap: plugins.lik.Stringmap;

  constructor(
    smartAcmeArg: SmartAcme,
    optionsArg: {
      mongoDescriptor: plugins.smartdata.IMongoDescriptor;
    }
  ) {
    this.mongoDescriptor = optionsArg.mongoDescriptor;
  }

  public async init() {
    // Smartdata DB
    this.smartdataDb = new plugins.smartdata.SmartdataDb(this.mongoDescriptor);
    await this.smartdataDb.init();
    CertManager.activeDB = this.smartdataDb;

    // Pending Map
    this.pendingMap = new plugins.lik.Stringmap();
  }

  /**
   * retrieves a certificate
   * @returns the Cert class or null
   * @param domainName the domain Name to retrieve the vcertificate for
   */
  public async retrieveCertificate(domainName: string): Promise<Cert> {
    await this.checkCerts();
    const existingCertificate: Cert = await Cert.getInstance({
      domainName
    });

    if (existingCertificate) {
      return existingCertificate;
    } else {
      return null;
    }
  }

  /**
   * stores the certificate
   * @param optionsArg
   */
  public async storeCertificate(optionsArg: interfaces.ICert) {
    const cert = new Cert(optionsArg);
    await cert.save();
    this.pendingMap.removeString(optionsArg.domainName);
  }

  public async deleteCertificate(domainNameArg: string) {}

  /**
   * announce a certificate as being in the process of being retrieved
   */
  public async announceCertificate(domainNameArg: string) {
    this.pendingMap.addString(domainNameArg);
  }

  /**
   * gets the status of a certificate by certDomain name
   * @param certDomainArg
   */
  public async getCertificateStatus(certDomainArg: string): Promise<interfaces.TCertStatus> {
    const isPending = this.pendingMap.checkString(certDomainArg);
    if (isPending) {
      return 'pending';
    }

    // otherwise lets continue
    const existingCertificate = await this.retrieveCertificate(certDomainArg);
    if (existingCertificate) {
      return 'existing';
    }

    return 'nonexisting';
  }

  /**
   * checks all certs for expiration
   */
  private async checkCerts() {
    // TODO
  }
}
