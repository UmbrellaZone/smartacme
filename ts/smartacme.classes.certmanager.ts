import * as plugins from './smartacme.plugins';
import { Cert } from './smartacme.classes.cert';


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

  constructor(optionsArg: {
    mongoDescriptor: plugins.smartdata.IMongoDescriptor;
  }) {
    this.mongoDescriptor = optionsArg.mongoDescriptor;
  }

  public async init () {
    this.smartdataDb = new plugins.smartdata.SmartdataDb(this.mongoDescriptor);
    await this.smartdataDb.init();
    CertManager.activeDB = this.smartdataDb;
  };

  /**
   * retrieves a certificate
   * @returns the Cert class or null
   * @param domainName the domain Name to retrieve the vcertificate for
   */
  public async retrieveCertificate(domainName: string): Promise<Cert> {
    const existingCertificate: Cert = await Cert.getInstance({
      name: domainName
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
  public async storeCertificate(privateKeyArg: string, publicKeyArg: string, csrArg: string) {
    const cert = new Cert(privateKeyArg, publicKeyArg, csrArg);
    cert.save();
  };

  public async deleteCertificate(domainName: string) {

  };

  /**
   * checks all certs for expiration
   */
  checkCerts() {}
}
