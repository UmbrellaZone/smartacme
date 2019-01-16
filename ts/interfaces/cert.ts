export type TCertStatus = 'existing' | 'nonexisting' | 'pending' | 'failed';

export interface ICert {
  id: string;
  domainName: string;
  created: number;
  privateKey: string;
  publicKey: string;
  csr: string;
}