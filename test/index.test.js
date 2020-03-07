const { describe } = require('tape-plus')
const hypercore = require('hypercore')
const hyperdrive = require('hyperdrive')
const path = require('path')
const fs = require('fs')
const sodium = require('sodium-native')
const ram = require('random-access-memory')

const secretBoxEncoder = require('../secret-box')
const chacha20Encoder = require('../cha20stream')
const chacha20InstanceEncoder = require('../cha20stream-instance')
const XOREncoder = require('../XOR-stream')

const { cleanup, tmp } = require('./util')
describe('secretbox', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypt and decrypt a message', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key, { valueEncoding: 'utf-8' })

    const encrypted = encoder.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')

    const message = encoder.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })

  context('hypercore - encrypts the log', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key, { valueEncoding: 'utf-8' })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(encoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same('boop', entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypts the log, using JSON encoding', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key, { valueEncoding: 'json' })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(message.boop, entry.boop, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key)
    const feed = hypercore(ram, { valueEncoding: encoder })
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to decrypt ${endRead - startRead} ms`)
          cleanup(storage, next)
        })
      }
    })
  })

  context('hyperdrive - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key)
    const drive = hyperdrive(ram, { valueEncoding: encoder })
    drive.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        drive.writeFile(`block${i}.data`, block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(drive.content.length, drive.content.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        cleanup(storage, next)
        // const startRead = Date.now()
        // const readStream = feed.createReadStream()
        // readStream.on('data', (chunk) => {
        // })
        // readStream.on('end', () => {
        //   const endRead = Date.now()
        //   console.log(`Time taken to decrypt ${endRead - startRead} ms`)
        //   cleanup(storage, next)
        // })
      }
    })
  })
})

describe('crypto_stream_chacha20_XOR_instance', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypt and decrypt a message', (assert, next) => {
    const key = chacha20InstanceEncoder.encryptionKey()
    const encoder1 = chacha20InstanceEncoder(key, { valueEncoding: 'utf-8' })
    const encoder2 = chacha20InstanceEncoder(key, { valueEncoding: 'utf-8', nonce: encoder1.nonce })

    const encrypted = encoder1.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')

    const message = encoder2.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })

  context('hypercore - encrypt the log - binary encoding', (assert, next) => {
    const key = chacha20InstanceEncoder.encryptionKey()
    const encoder = chacha20InstanceEncoder(key)
    const testEncoder = chacha20InstanceEncoder(key, { nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = Buffer.from('boop beep beep boop')

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), message.toString(), 'log entry is encrypted')
      assert.same(testEncoder.decode(data).toString(), message.toString(), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(entry.toString(), message.toString(), 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })
  context('hypercore - encrypt the log - utf-8 encoding', (assert, next) => {
    const key = chacha20InstanceEncoder.encryptionKey()
    const encoder = chacha20InstanceEncoder(key, { valueEncoding: 'utf-8' })
    const testEncoder = chacha20InstanceEncoder(key, { valueEncoding: 'utf-8', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(testEncoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same('boop', entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt the log - json encoding', (assert, next) => {
    const key = chacha20InstanceEncoder.encryptionKey()
    const encoder = chacha20InstanceEncoder(key, { valueEncoding: 'json' })
    const testEncoder = chacha20InstanceEncoder(key, { valueEncoding: 'json', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      const data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), JSON.stringify(message), 'log entry is unreadable')
      const plain = testEncoder.decode(data)
      assert.same(JSON.stringify(plain), JSON.stringify(message), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error on read entry')
        assert.same(message.boop, entry.boop, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = chacha20InstanceEncoder.encryptionKey()
    const encoder = chacha20InstanceEncoder(key)
    const feed = hypercore(ram, { valueEncoding: encoder })
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to decrypt ${endRead - startRead} ms`)
          cleanup(storage, next)
        })
      }
    })
  })

  context('hyperdrive - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = chacha20InstanceEncoder.encryptionKey()
    const encoder = chacha20InstanceEncoder(key)
    const drive = hyperdrive(ram, { valueEncoding: encoder })
    drive.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        drive.writeFile(`block${i}.data`, block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(drive.content.length, drive.content.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        cleanup(storage, next)
        // const startRead = Date.now()
        // const readStream = feed.createReadStream()
        // readStream.on('data', (chunk) => {
        // })
        // readStream.on('end', () => {
        //   const endRead = Date.now()
        //   console.log(`Time taken to decrypt ${endRead - startRead} ms`)
        //   cleanup(storage, next)
        // })
      }
    })
  })
})

describe('crypto_stream_chacha20_XOR', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypt and decrypt a message', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder1 = chacha20Encoder(key, { valueEncoding: 'utf-8' })
    const encoder2 = chacha20Encoder(key, { valueEncoding: 'utf-8', nonce: encoder1.nonce })

    const encrypted = encoder1.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')

    const message = encoder2.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })

  context('hypercore - encrypt the log - binary encoding', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key)
    const testEncoder = chacha20Encoder(key, { nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = Buffer.from('boop beep beep boop')

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), message.toString(), 'log entry is encrypted')
      assert.same(testEncoder.decode(data).toString(), message.toString(), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(entry.toString(), message.toString(), 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })
  context('hypercore - encrypt the log - utf-8 encoding', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key, { valueEncoding: 'utf-8' })
    const testEncoder = chacha20Encoder(key, { valueEncoding: 'utf-8', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(testEncoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same('boop', entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt the log - json encoding', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key, { valueEncoding: 'json' })
    const testEncoder = chacha20Encoder(key, { valueEncoding: 'json', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      const data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), JSON.stringify(message), 'log entry is unreadable')
      const plain = testEncoder.decode(data)
      assert.same(JSON.stringify(plain), JSON.stringify(message), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error on read entry')
        assert.same(message.boop, entry.boop, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key)
    const feed = hypercore(ram, { valueEncoding: encoder })
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to decrypt ${endRead - startRead} ms`)
          cleanup(storage, next)
        })
      }
    })
  })

  context('hyperdrive - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key)
    const drive = hyperdrive(ram, { valueEncoding: encoder })
    drive.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        drive.writeFile(`block${i}.data`, block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(drive.content.length, drive.content.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        cleanup(storage, next)
        // const startRead = Date.now()
        // const readStream = feed.createReadStream()
        // readStream.on('data', (chunk) => {
        // })
        // readStream.on('end', () => {
        //   const endRead = Date.now()
        //   console.log(`Time taken to decrypt ${endRead - startRead} ms`)
        //   cleanup(storage, next)
        // })
      }
    })
  })
})

describe('crypto_stream_XOR', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypt and decrypt a message', (assert, next) => {
    const key = XOREncoder.encryptionKey()
    const encoder1 = XOREncoder(key, { valueEncoding: 'utf-8' })
    const encoder2 = XOREncoder(key, { valueEncoding: 'utf-8', nonce: encoder1.nonce })

    const encrypted = encoder1.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')

    const message = encoder2.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })

  context('hypercore - encrypt the log - binary encoding', (assert, next) => {
    const key = XOREncoder.encryptionKey()
    const encoder = XOREncoder(key)
    const testEncoder = XOREncoder(key, { nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = Buffer.from('boop beep beep boop')

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), message.toString(), 'log entry is encrypted')
      assert.same(testEncoder.decode(data).toString(), message.toString(), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(entry.toString(), message.toString(), 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })
  context('hypercore - encrypt the log - utf-8 encoding', (assert, next) => {
    const key = XOREncoder.encryptionKey()
    const encoder = XOREncoder(key, { valueEncoding: 'utf-8' })
    const testEncoder = XOREncoder(key, { valueEncoding: 'utf-8', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(testEncoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same('boop', entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt the log - json encoding', (assert, next) => {
    const key = XOREncoder.encryptionKey()
    const encoder = XOREncoder(key, { valueEncoding: 'json' })
    const testEncoder = XOREncoder(key, { valueEncoding: 'json', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      const data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), JSON.stringify(message), 'log entry is unreadable')
      const plain = testEncoder.decode(data)
      assert.same(JSON.stringify(plain), JSON.stringify(message), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error on read entry')
        assert.same(message.boop, entry.boop, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = XOREncoder.encryptionKey()
    const encoder = XOREncoder(key)
    const feed = hypercore(ram, { valueEncoding: encoder })
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to decrypt ${endRead - startRead} ms`)
          cleanup(storage, next)
        })
      }
    })
  })

  context('hyperdrive - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = XOREncoder.encryptionKey()
    const encoder = XOREncoder(key)
    const drive = hyperdrive(ram, { valueEncoding: encoder })
    drive.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        drive.writeFile(`block${i}.data`, block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(drive.content.length, drive.content.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        cleanup(storage, next)
        // const startRead = Date.now()
        // const readStream = feed.createReadStream()
        // readStream.on('data', (chunk) => {
        // })
        // readStream.on('end', () => {
        //   const endRead = Date.now()
        //   console.log(`Time taken to decrypt ${endRead - startRead} ms`)
        //   cleanup(storage, next)
        // })
      }
    })
  })
})

describe('no encryption', (context) => {
  context('hypercore - add 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const feed = hypercore(ram)
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to add data ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to read data ${endRead - startRead} ms`)
          next()
        })
      }
    })
  })

  context('hyperdrive - add 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const drive = hyperdrive(ram)
    drive.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        drive.writeFile(`block${i}.data`, block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(drive.content.length, drive.content.byteLength / (1024 * 1024))
        console.log(`Time taken to add data ${end - start} ms`)
        next()
        // const startRead = Date.now()
        // const readStream = feed.createReadStream()
        // readStream.on('data', (chunk) => {
        // })
        // readStream.on('end', () => {
        //   const endRead = Date.now()
        //   console.log(`Time taken to decrypt ${endRead - startRead} ms`)
        //   cleanup(storage, next)
        // })
      }
    })
  })
})
