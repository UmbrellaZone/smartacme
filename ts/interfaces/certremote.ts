import { ICert, TCertStatus } from './cert';

export interface ICertRemoteRequest {
  secret: string;
  domainName: string;
}

export interface ICertRemoteResponse {
  status: TCertStatus;
  certificate?: ICert;
}
