
import {blake2b} from 'blakejs';
import base from 'base-x';


export class SS58 {
  public arraytoHex(bytes:Uint8Array) {
    var a = [];
    for(const byte of bytes){
      a.push(('0' + (byte & 0xFF).toString(16)).slice(-2));
    }
    return a.join('');
  }

  public ss58_decode(address) {
    const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const bs58 = base(BASE58);
    var a = null;
    try {
      a = bs58.decode(address);
    }catch (e) {
      return null;
    }

    if (a[0] == 42) {
      if (a.length == 32 + 1 + 2) {
        const address = a.slice(0, 33);
        const checksum_prefix:Uint8Array = new TextEncoder().encode("SS58PRE");
        const bytes = new Uint8Array([ ...checksum_prefix, ...address ]);
        const checksum = blake2b(bytes);
        if (a[33] == checksum[0] && a[34] == checksum[1]) {
          return this.arraytoHex(address.slice(1));
        } else {
          // invalid checksum
          return null;
        }
      } else {
        // Invalid length.
        return null;
      }
    } else {
      // Invalid version.
      return null;
    }
  }

  public hexToArray(hex:string) {
    var a = [];
    for(var i = 0; i < 64 ; i+= 2){
      // console.log(hex.slice(i, i+2));
      a.push(parseInt(hex.slice(i, i+2), 16));
    }
    return new Uint8Array(a);
  }

  public ss58_encode(address:string) {
    const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const bs58 = base(BASE58);
    var a = null;

    if (address.length == 66) {
      a = address.slice(2);
    }else if (address.length == 64) {
      a = address;
    }else{
      return null;
    }

    const checksum_prefix:Uint8Array = new TextEncoder().encode("SS58PRE");
    const address_bytes = this.hexToArray(a);
    const bytes = new Uint8Array([... checksum_prefix, 42, ...address_bytes]);
    const checksum = blake2b(bytes);
    const complete = new Uint8Array([42, ...this.hexToArray(a), checksum[0], checksum[1]]);

    return bs58.encode(complete);
  }

}
