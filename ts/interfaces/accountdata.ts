export interface IAccountData {
  id: number;
  key: { kty: 'RSA'; n: string; e: string; kid: string };
  contact: string[];
  initialIp: string;
  createdAt: string;
  status: string;
}
