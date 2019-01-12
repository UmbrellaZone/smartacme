import * as plugins from './smartacme.plugins';

import * as interfaces from './interfaces';

import { CertManager } from './smartacme.classes.certmanager';

import { Collection, svDb, unI } from '@pushrocks/smartdata';
import { ICert } from './interfaces';

@plugins.smartdata.Collection(() => {
  return CertManager.activeDB;
})
export class Cert extends plugins.smartdata.SmartDataDbDoc<Cert> implements interfaces.ICert {
  @unI()
  public index: string;

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

  constructor(optionsArg: ICert) {
    super();
    if (optionsArg) {
      Object.keys(optionsArg).forEach(key => {
        this[key] = optionsArg[key];
      });
    }
  }
}
