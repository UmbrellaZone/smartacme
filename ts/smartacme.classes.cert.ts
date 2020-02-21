import * as plugins from './smartacme.plugins';

import * as interfaces from './interfaces';

import { CertManager } from './smartacme.classes.certmanager';

import { Collection, svDb, unI } from '@pushrocks/smartdata';

@plugins.smartdata.Collection(() => {
  return CertManager.activeDB;
})
export class Cert extends plugins.smartdata.SmartDataDbDoc<Cert, plugins.tsclass.network.ICert>
  implements plugins.tsclass.network.ICert {
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

  @svDb()
  public validUntil: number;

  public isStillValid(): boolean {
    return this.validUntil >= Date.now();
  }

  public shouldBeRenewed(): boolean {
    const shouldBeValidAtLeastUntil =
      Date.now() +
      plugins.smarttime.getMilliSecondsFromUnits({
        days: 10
      });
    return !(this.validUntil >= shouldBeValidAtLeastUntil);
  }

  public update(certDataArg: plugins.tsclass.network.ICert) {
    Object.keys(certDataArg).forEach(key => {
      this[key] = certDataArg[key];
    });
  }

  constructor(optionsArg: plugins.tsclass.network.ICert) {
    super();
    if (optionsArg) {
      Object.keys(optionsArg).forEach(key => {
        this[key] = optionsArg[key];
      });
    }
  }
}
