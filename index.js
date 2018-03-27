var fs = require('fs')
var jwt = require('jsonwebtoken')

var priv = fs.readFileSync('./private.pem')
var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: 'ES256' })

console.log(token)

var pub = fs.readFileSync('./public.pem')
var decoded = jwt.verify(token, pub, { algorithms: ['ES256'] })

console.log(decoded)
