import * as plugins from './smartacme.plugins';
import * as interfaces from './interfaces';

/**
 * certmatcher is responsible for matching certificates
 */
export class CertMatcher {
  /**
   * creates a domainName for the certificate that will include the broadest scope
   * for wild card certificates
   * @param domainNameArg the domainNameArg to create the scope from
   */
  public getCertificateDomainNameByDomainName(domainNameArg: string): string {
    const originalDomain = new plugins.smartstring.Domain(domainNameArg);
    if (!originalDomain.level4) {
      return `${originalDomain.level2}.${originalDomain.level1}`;
    }
  }
}
