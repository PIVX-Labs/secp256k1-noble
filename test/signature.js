const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('signatureNormalize', (t) => {
    t.test('arg: invalid signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.signatureNormalize(null)
      }, /^Error: Expected signature to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureNormalize(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/, 'should have length 64')

      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.signatureNormalize(signature)
      }, /^Error: Signature could not be parsed$/, 'should throw error for invalid signature: r equal to N')

      t.end()
    })

    t.test('do not change valid signature (s equal to N/2)', (t) => {
      const signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, 'be', 32),
        util.ec.nh.toArrayLike(Buffer, 'be', 32)
      ])
      const result = secp256k1.signatureNormalize(Buffer.from(signature))
      t.same(result, signature)
      t.end()
    })

    t.test('normalize signature (s equal to N/2 + 1)', (t) => {
      const signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, 'be', 32),
        util.ec.nh.toArrayLike(Buffer, 'be', 32)
      ])
      const signature1 = new util.BN(signature).iaddn(1).toArrayLike(Buffer, 'be', 64)
      const result = secp256k1.signatureNormalize(signature1)
      t.same(result, signature)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      const sigObj = util.sign(message, privateKey)
      const result = secp256k1.signatureNormalize(sigObj.signature, Buffer.alloc)
      t.same(result, sigObj.signatureLowS)
    })

    t.end()
  })
}
