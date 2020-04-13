const sodium = require('sodium-native')
const assert = require('assert')
// const zero = sodium.sodium_memzero

module.exports = encoder
module.exports.encryptionKey = encryptionKey
module.exports.KEYBYTES = sodium.crypto_secretbox_KEYBYTES

function encoder (encryptionKey, opts = {}) {
  assert(Buffer.isBuffer(encryptionKey), 'encryption key must be a buffer')
  assert(encryptionKey.length === sodium.crypto_stream_KEYBYTES, `cobox-crypto: key must be a buffer of length ${sodium.crypto_stream_KEYBTES}`)

  opts.valueEncoding = _resolveStringEncoder(opts.valueEncoding)

  const nonce = opts.nonce || generateNonce()
  // TODO use separate nonce for rx and tx
  const rx = sodium.crypto_stream_xor_instance(nonce, encryptionKey)
  const tx = sodium.crypto_stream_xor_instance(nonce, encryptionKey)

  const encode = function (message) {
    // TODO should be able to do in-place encryption
    // const ciphertext = sodium.sodium_malloc(message.length)
    const ciphertext = Buffer.alloc(message.length)
    tx.update(ciphertext, message)
    return ciphertext
  }

  const decode = function (ciphertext) {
    // const message = sodium.sodium_malloc(ciphertext.length)
    const message = Buffer.alloc(ciphertext.length)
    rx.update(message, ciphertext)
    return message
  }

  return (opts.valueEncoding && typeof opts.valueEncoding.encode === 'function')
    ? { // Run originally provided encoder
      encode (message, buffer, offset) {
        return encode(opts.valueEncoding.encode(message, buffer, offset))
      },
      decode (ciphertext, start, end) {
        return opts.valueEncoding.decode(decode(ciphertext), start, end)
      },
      nonce
    }
    : { encode, decode, nonce }
}

function encryptionKey () {
  const key = sodium.sodium_malloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(key)
  return key
}

function _resolveStringEncoder (encoder) {
  if (encoder === 'json') {
    return {
      encode: (msg) => Buffer.from(JSON.stringify(msg)),
      decode: (msg) => JSON.parse(msg.toString())
    }
  }

  if ((encoder === 'utf-8') || (encoder === 'utf8')) {
    return {
      encode: (msg) => Buffer.from(msg),
      decode: (msg) => msg.toString()
    }
  }
  return encoder
}

function generateNonce () {
  const nonce = Buffer.alloc(sodium.crypto_stream_NONCEBYTES)
  sodium.randombytes_buf(nonce)
  return nonce
}
