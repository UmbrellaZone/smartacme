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

  constructor(smartAcmeArg: SmartAcme,optionsArg: {
    mongoDescriptor: plugins.smartdata.IMongoDescriptor;
  }) {
    this.mongoDescriptor = optionsArg.mongoDescriptor;
  }

  public async init () {
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

    if(existingCertificate) {
      return existingCertificate;
    } else {
      return null;
    }

  }

  /**
   * stores the certificate with the 
   * @param publicKeyArg 
   * @param privateKeyArg 
   * @param csrArg 
   */
  public async storeCertificate(optionsArg: interfaces.ICert) {
    const cert = new Cert(optionsArg);
    await cert.save();
  }

  public async deleteCertificate(domainNameArg: string) {

  }

  public async getCertificateStatus(domainNameArg: string): Promise<interfaces.TCertStatus> {
    const isPending = this.pendingMap.checkString('domainNameArg');
    if (isPending) {
      return 'pending';
    }

    // otherwise lets continue
    const existingCertificate = this.retrieveCertificate(domainNameArg);
    if (existingCertificate) {
      return 'existing';
    }

    return 'nonexisting';
  }

  /**
   * checks all certs for expiration
   */
  private async checkCerts() {};
}
