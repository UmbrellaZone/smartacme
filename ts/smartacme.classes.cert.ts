import * as plugins from './smartacme.plugins';

import * as interfaces from './interfaces';

import { CertManager } from './smartacme.classes.certmanager';

import { Collection, svDb, unI } from '@pushrocks/smartdata';

@plugins.smartdata.Collection(() => {
  return CertManager.activeDB;
})
export class Cert extends plugins.smartdata.SmartDataDbDoc<Cert> implements interfaces.ICert {
  @unI()
  public id: string;

  @svDb()
  public domainName: string;

  @svDb()
  public created: number;

  @svDb()
  public privateKey: string;

  @svDb()
  public publicKey: string;

  @svDb()
  public csr: string;

  /**
   * computed value for when the certificate is still valid
   */
  get validUntil(): number {
    return (
      this.created +
      plugins.smarttime.getMilliSecondsFromUnits({
        days: 90
      })
    );
  }

  get isStillValid(): boolean {
    const shouldBeValitAtLeastUntil =
      Date.now() +
      plugins.smarttime.getMilliSecondsFromUnits({
        days: 10
      });
    return this.validUntil >= shouldBeValitAtLeastUntil;
  }

  constructor(optionsArg: interfaces.ICert) {
    super();
    if (optionsArg) {
      Object.keys(optionsArg).forEach(key => {
        this[key] = optionsArg[key];
      });
    }
  }
}
