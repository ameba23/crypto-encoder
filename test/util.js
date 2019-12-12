const tmpdir = require('tmp').dirSync
const mkdirp = require('mkdirp')
const rimraf = require('rimraf')

function cleanup (dirs, cb) {
  if (!cb) cb = noop
  if (!Array.isArray(dirs)) dirs = [dirs]
  var pending = 1

  function next (n) {
    var dir = dirs[n]
    if (!dir) return done()
    ++pending
    process.nextTick(next, n + 1)

    rimraf(dir, (err) => {
      if (err) return done(err)
      done()
    })
  }

  function done (err) {
    if (err) {
      pending = Infinity
      return cb(err)
    }
    if (!--pending) return cb()
  }

  next(0)
}

function tmp () {
  var path = tmpdir().name
  mkdirp.sync(path)
  return path
}

function noop () {}

module.exports = { cleanup, tmp }
