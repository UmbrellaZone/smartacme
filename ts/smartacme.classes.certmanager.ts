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

  public interestMap: plugins.lik.InterestMap<string, Cert>;

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
    this.interestMap = new plugins.lik.InterestMap((certName) => certName);
  }

  /**
   * retrieves a certificate
   * @returns the Cert class or null
   * @param certDomainNameArg the domain Name to retrieve the vcertificate for
   */
  public async retrieveCertificate(certDomainNameArg: string): Promise<Cert> {
    const existingCertificate: Cert = await Cert.getInstance<Cert>({
      domainName: certDomainNameArg,
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
  public async storeCertificate(optionsArg: plugins.tsclass.network.ICert) {
    const cert = new Cert(optionsArg);
    await cert.save();
    const interest = this.interestMap.findInterest(cert.domainName);
    if (interest) {
      interest.fullfillInterest(cert);
      interest.markLost();
    }
  }

  public async deleteCertificate(certDomainNameArg: string) {
    const cert: Cert = await Cert.getInstance<Cert>({
      domainName: certDomainNameArg,
    });
    await cert.delete();
  }
}
