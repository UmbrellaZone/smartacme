import * as plugins from './smartacme.plugins';

export class CertMatcher {
  public getCertificateDomainNameByDomainName(domainNameArg: string): string {
    const originalDomain = new plugins.smartstring.Domain(domainNameArg);
    if (!originalDomain.level4) {
      return `${originalDomain.level2}.${originalDomain.level1}`;
    }
  }
}
