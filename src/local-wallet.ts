import { InputInfo, Wallet } from "@sensible-contract/abstract-wallet";
import * as bsv from "@sensible-contract/bsv";
import { Message } from "@sensible-contract/bsv";

export class LocalWallet implements Wallet {
  privateKey: bsv.PrivateKey;
  network: bsv.Networks.Type;
  constructor(privateKey: bsv.PrivateKey, network?: bsv.Networks.Type) {
    this.privateKey = privateKey;
    this.network = network;
  }

  async getPublicKey() {
    return this.privateKey.publicKey.toString();
  }

  async getAddress() {
    return this.privateKey.toAddress(this.network).toString();
  }

  async signTransaction(txHex: string, inputInfos: InputInfo[]) {
    const tx = new bsv.Transaction(txHex);
    let sigResults = inputInfos.map((v) => {
      let sighash = bsv.Transaction.Sighash.sighash(
        tx,
        v.sighashType,
        v.inputIndex,
        new bsv.Script(v.scriptHex),
        new bsv.crypto.BN(v.satoshis)
      ).toString("hex");

      var sig = bsv.crypto.ECDSA.sign(
        Buffer.from(sighash, "hex"),
        this.privateKey,
        "little"
      )
        .set({
          nhashtype: v.sighashType,
        })
        .toString();
      return { sig, publicKey: this.privateKey.publicKey.toString() };
    });
    return sigResults;
  }

  async signMessage(message: string) {
    return bsv.Message.sign(message, this.privateKey);
  }

  static createRandom(network?: bsv.Networks.Type): LocalWallet {
    return new LocalWallet(new bsv.PrivateKey(null, network));
  }

  static fromMnemonic(
    mnemonic: string,
    path: string = "m/44'/0'/0'/0/0",
    passphrase = "",
    network?: bsv.Networks.Type
  ): LocalWallet {
    let mne = new bsv.Mnemonic(mnemonic);
    return new LocalWallet(
      mne.toHDPrivateKey(passphrase, network).deriveChild(path).privateKey
    );
  }

  static fromWIF(wif: string) {
    return new LocalWallet(new bsv.PrivateKey(wif));
  }
}

export function verifyMessage(
  message: string,
  address: string,
  signature: string
) {
  try {
    return Message.verify(message, address, signature);
  } catch (e) {
    return false;
  }
}
