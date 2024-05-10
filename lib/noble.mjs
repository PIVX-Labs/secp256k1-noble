"use strict";
import * as secp from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
secp.etc.hmacSha256Sync = (k, ...m) =>
  hmac(sha256, k, secp.etc.concatBytes(...m));

export const {
  contextRandomize,
  privateKeyVerify,
  privateKeyNegate,
  privateKeyTweakAdd,
  privateKeyTweakMul,
  publicKeyVerify,
  publicKeyCrate,
  publicKeyConvert,
  publicKeyNegate,
  publicKeyCombine,
  publicKeyCreate,
  publicKeyTweakAdd,
  publicKeyTweakMul,
  signatureNormalize,
  signatureExport,
  signatureImport,
  ecdsaSign,
  ecdsaRecover,
  ecdsaVerify,
  ecdh,
} = {
  contextRandomize(seed) {
    return 0;
  },
  privateKeyVerify(privateKey) {
    return secp.utils.isValidPrivateKey(new Uint8Array(privateKey)) ? 0 : 1;
  },
  privateKeyNegate(privateKey) {
    try {
      privateKey.set(
        secp.etc.numberToBytesBE(
          secp.etc.mod(
            secp.CURVE.n - secp.utils.normPrivateKeyToScalar(privateKey),
            secp.CURVE.n,
          ),
        ),
      );

      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  /**
   * @param {Uint8Array} privateKey
   */
  privateKeyTweakAdd(privateKey, tweak) {
    try {
      const tweakNum = secp.etc.bytesToNumberBE(tweak);
      if (tweakNum >= secp.CURVE.n) {
        return 1;
      }
      const res = secp.etc.numberToBytesBE(
        secp.etc.mod(
          secp.utils.normPrivateKeyToScalar(privateKey) + tweakNum,
          secp.CURVE.n,
        ),
      );
      secp.utils.normPrivateKeyToScalar(res);
      privateKey.set(res);
      return 0;
    } catch (e) {
      return 1;
    }
  },
  privateKeyTweakMul(privateKey, tweak) {
    try {
      const tweakNum = secp.etc.bytesToNumberBE(tweak);
      const privKeyNum = secp.utils.normPrivateKeyToScalar(privateKey);
      console.log(privKeyNum, tweakNum);
      if (tweakNum === 0n || tweakNum >= secp.CURVE.n) return 1;
      const res = secp.etc.numberToBytesBE(
        secp.etc.mod(privKeyNum * tweakNum, secp.CURVE.n),
      );
      secp.utils.normPrivateKeyToScalar(res);
      privateKey.set(res);
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  publicKeyVerify(publicKey) {
    try {
      secp.ProjectivePoint.fromHex(publicKey);
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  publicKeyCreate(output, privateKey) {
    try {
      output.set(secp.getPublicKey(privateKey, output.length === 33));
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  publicKeyConvert(output, publicKey) {
    try {
      output.set(
        secp.ProjectivePoint.fromHex(publicKey).toRawBytes(
          output.length === 33,
        ),
      );
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  publicKeyNegate(output, publicKey) {
    try {
      output.set(
        secp.ProjectivePoint.fromHex(publicKey)
          .negate()
          .toRawBytes(output.length === 33),
      );
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  publicKeyCombine(output, publicKeys) {
    try {
      const point = publicKeys
        .map((p) => secp.ProjectivePoint.fromHex(p))
        .reduce((acc, p) => acc.add(p));
      if (point.px === 0n && point.pz === 0n) return 2;
      output.set(point.toRawBytes(output.length === 33));
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  publicKeyTweakAdd(output, publicKey, tweak) {
    try {
      const tweakNum = secp.etc.bytesToNumberBE(tweak);
      if (tweakNum === 0n || tweakNum >= secp.CURVE.n) return 2;
      const point = secp.ProjectivePoint.fromHex(publicKey).add(
        secp.ProjectivePoint.BASE.mul(tweakNum),
      );
      if (point.px === 0n && point.pz === 0n) return 2;
      output.set(point.toRawBytes(output.length === 33));
      return 0;
    } catch (e) {
      if (e.message.includes("scalar")) return 2;
      return 1;
    }
  },
  publicKeyTweakMul(output, publicKey, tweak) {
    try {
      const tweakNum = secp.etc.bytesToNumberBE(tweak);
      if (tweakNum === 0n || tweakNum >= secp.CURVE.n) return 2;
      output.set(
        secp.ProjectivePoint.fromHex(publicKey)
          .mul(tweakNum)
          .toRawBytes(output.length === 33),
      );
      return 0;
    } catch (e) {
      if (e.message.includes("scalar")) return 2;
      return 1;
    }
  },
  signatureNormalize(signature) {
    try {
      const sign = secp.Signature.fromCompact(signature);
      console.log(sign.s, secp.CURVE.n >> 1n, sign.s > secp.CURVE.n >> 1n);
      if (sign.s > secp.CURVE.n >> 1n) {
        signature.set(secp.etc.numberToBytesBE(secp.CURVE.n - sign.s), 32);
      }
      return 0;
    } catch (e) {
      console.error(e);
      return 1;
    }
  },
  signatureExport(signature) {
    throw new Error("unimplemented");
    //return secp.Signature.fromHex(signature).
  },
  signatureImport(signature) {
    throw new Error("unimplemented");
  },
  ecdsaSign(obj, message, privateKey, data, noncefn) {
    let nonce;
    if (noncefn) {
      nonce = noncefn(message, privateKey, null, data, 0);
      if (!(nonce instanceof Uint8Array) || nonce.length !== 32) return 1;
    }
    let sig;
    try {
      sig = secp.sign(message, privateKey, {
        extraEntropy: nonce,
      });
    } catch (e) {
      console.error(e);
      return 1;
    }
    obj.signature.set(secp.etc.numberToBytesBE(sig.r), 0);
    obj.signature.set(secp.etc.numberToBytesBE(sig.s), 32);
    obj.recid = sig.recovery;
    return 0;
  },
  ecdsaVerify(sig, message, publicKey) {
    try {
      secp.ProjectivePoint.fromHex(publicKey);
    } catch (e) {
      return 2;
    }
    return secp.verify(sig, message, publicKey) ? 0 : 3;
  },
  ecdsaRecover(output, sig, recid, msg32) {
    let signature;
    try {
      signature = secp.Signature.fromCompact(sig).addRecoveryBit(recid);
    } catch (e) {
      return 1;
    }

    try {
      output.set(
        signature.recoverPublicKey(msg32).toRawBytes(output.length === 33),
      );
    } catch (e) {
      console.error(e);
      return 2;
    }
    return 0;
  },
  ecdh(output, publicKey, privateKey, data, hashfn, xbuf, ybuf) {
    let publicPoint, privateNumber;
    try {
      publicPoint = secp.ProjectivePoint.fromHex(publicKey);
    } catch (e) {
      return 1;
    }
    try {
      privateNumber = secp.utils.normPrivateKeyToScalar(privateKey);
    } catch (e) {
      return 2;
    }
    const point = publicPoint.mul(privateNumber);
    if (hashfn === undefined) {
      const data = point.toRawBytes();
      output.set(sha256(data));
    } else {
      if (!xbuf) xbuf = new Uint8Array(32);
      xbuf.set(secp.etc.numberToBytesBE(point.x));
      if (!ybuf) ybuf = new Uint8Array(32);
      ybuf.set(secp.etc.numberToBytesBE(point.y));
      const hash = hashfn(xbuf, ybuf, data);
      const isValid =
        hash instanceof Uint8Array && hash.length === output.length;
      if (!isValid) return 2;
      output.set(hash);
    }
    return 0;

    //throw new Error("unimplemented");
  },
};
