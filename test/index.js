const test = require('tape')
const util = require('./util.js')


function testAPI (secp256k1, description) {
  test(description, (t) => {
    util.setSeed(util.env.seed)

    require('./context.js')(t, secp256k1)
    require('./privatekey.js')(t, secp256k1)
    require('./publickey.js')(t, secp256k1)
    require('./signature.js')(t, secp256k1)
    require('./ecdsa.js')(t, secp256k1)
    require('./ecdh.js')(t, secp256k1)

    t.end()
  })
}

//if (!process.browser) testAPI(import('../bindings'), 'secp256k1 bindings')
(async () => {
    testAPI(await import('../index.mjs'), 'Noble secp256k1 bindings')
})()
