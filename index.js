const sodium = require('sodium-native')
const assert = require('assert')
const zero = sodium.sodium_memzero

module.exports = function encoder (encryptionKey, opts = {}) {
  assert(Buffer.isBuffer(encryptionKey), 'encryption key must be a buffer')
  assert(encryptionKey.length === sodium.crypto_secretbox_KEYBYTES, `cobox-crypto: key must be a buffer of length ${sodium.crypto_secretbox_KEYBYTES}`)

  opts.valueEncoding = _resolveStringEncoder(opts.valueEncoding)

  return {
    encode (message, buffer, offset) {
      // Run originally provided encoder if any
      if (opts.valueEncoding && typeof opts.valueEncoding.encode === 'function') {
        message = opts.valueEncoding.encode(message, buffer, offset)
      }
      if (!Buffer.isBuffer(message)) message = Buffer.from(message, 'utf-8')
      const ciphertext = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)
      const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
      sodium.randombytes_buf(nonce)
      sodium.crypto_secretbox_easy(ciphertext, message, nonce, encryptionKey)
      zero(message)
      return Buffer.concat([nonce, ciphertext])
    },

    decode (buffer, start, end) {
      const nonce = buffer.slice(0, sodium.crypto_secretbox_NONCEBYTES)
      const messageWithMAC = buffer.slice(sodium.crypto_secretbox_NONCEBYTES)
      const message = Buffer.alloc(messageWithMAC.length - sodium.crypto_secretbox_MACBYTES)
      assert(
        sodium.crypto_secretbox_open_easy(message, messageWithMAC, nonce, encryptionKey),
        'Decryption failed!'
      )
      // Run originally provided encoder if any
      if (opts.valueEncoding && typeof opts.valueEncoding.decode === 'function') {
        return opts.valueEncoding.decode(message, start, end)
      } else {
        return message
      }
    }
  }
}

function _resolveStringEncoder (encoder) {
  if (encoder === 'json') {
    return {
      encode: (msg) => Buffer.from(JSON.stringify(msg)),
      decode: (msg) => JSON.parse(msg.toString())
    }
  }

  if (encoder === 'utf-8') {
    return {
      encode: (msg) => Buffer.from(msg),
      decode: (msg) => msg.toString()
    }
  }
  return encoder
}
