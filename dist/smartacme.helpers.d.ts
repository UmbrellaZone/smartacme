import 'typings-global';
import { IRsaKeypair } from './smartacme.classes.smartacme';
/**
 * creates a keypair to use with requests and to generate JWK from
 */
export declare let createKeypair: (bit?: number) => IRsaKeypair;
