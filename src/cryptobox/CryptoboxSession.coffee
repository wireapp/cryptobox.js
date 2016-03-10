Proteus = require 'proteus'

module.exports = class CryptoboxSession
  ###
  @param id [String] Unique session identifier
  @param pk_store [Proteus.session.PreKeyStore] Pre-key store
  @param session [Proteus.session.Session] Proteus session
  ###
  constructor: (@id, @pk_store, @session) ->
    Object.freeze @

  ###
  @param plaintext [String] Text to be encrypted
  @return [ArrayBuffer] CBOR representation of a message envelope which holds the encrypted text
  ###
  encrypt: (plaintext) ->
    return @session.encrypt(plaintext).serialise()

  decrypt: (ciphertext) ->
    envelope = Proteus.message.Envelope.deserialise ciphertext
    return @session.decrypt @pk_store, envelope

  fingerprint_local: ->
    return @session.local_identity.public_key.fingerprint()

  fingerprint_remote: ->
    return @session.remote_identity.fingerprint()
