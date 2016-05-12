Proteus = require 'proteus'

CryptoboxStore = require './CryptoboxStore'
CryptoboxSession = require './CryptoboxSession'

class ReadOnlyStore extends Proteus.session.PreKeyStore
  constructor: (@store) ->
    @removed_prekeys = []

  get_prekey: (prekey_id) ->
      if @removed_prekeys.indexOf(prekey_id) isnt -1
        return new Promise (resolve, reject) ->
          resolve null
      return @store.load_prekey prekey_id

  remove: (prekey_id) ->
    return new Promise (resolve, reject) =>
      @removed_prekeys.push prekey_id
      resolve()

module.exports = class Cryptobox
  constructor: (@store) ->
    return new Promise (resolve, reject) =>
      # XXX: no access to proteus internal funcs, replace with typescript annotation
      # Proteus.util.TypeUtil.assert_is_instance cryptobox.CryptoboxStore, @store

      @identity = @store.load_identity()

      if not @identity
        @identity = Proteus.keys.IdentityKeyPair.new()
        @store.save_identity @identity

      Object.freeze @
      resolve @

  ###
  @param client_id [String] Client ID
  @param pre_key_bundle [ArrayBuffer] Serialized Pre-Key Bundle
  ###
  session_from_prekey: (client_id, pre_key_bundle) ->
    return new Promise (resolve, reject) =>
      bundle = Proteus.keys.PreKeyBundle.deserialise pre_key_bundle
      pk_store = new ReadOnlyStore @store
      session = Proteus.session.Session.init_from_prekey @identity, bundle

      resolve new CryptoboxSession client_id, pk_store, session

  session_from_message: (session_id, envelope) ->
    return new Promise (resolve, reject) =>
      env = Proteus.message.Envelope.deserialise envelope
      pk_store = new ReadOnlyStore @store
      [session, plaintext] = Proteus.session.Session.init_from_message @identity, pk_store, env

      resolve [new CryptoboxSession(session_id, pk_store, session), plaintext]

  session_load: (session_id) ->
    return new Promise (resolve, reject) =>
      session = @store.load_session @identity, session_id
      if not session
        reject null

      pk_store = new ReadOnlyStore @store

      resolve new cryptobox.CryptoboxSession session_id, pk_store, session

  session_save: (session) ->
    return new Promise (resolve, reject) =>
      @store.save_session session.id, session.session

      for pk in session.pk_store.removed_prekeys
        @store.delete_prekey pk

      resolve(true)

  session_delete: (session_id) ->
    return new Promise (resolve, reject) =>
      @store.delete_session session_id

      resolve(true)

  new_prekey: (prekey_id) ->
    return new Promise (resolve, reject) =>
      pk = Proteus.keys.PreKey.new prekey_id
      @store.add_prekey pk
      .then =>
        resolve Proteus.keys.PreKeyBundle.new(@identity.public_key, pk).serialise()
      .catch (error) ->
        reject error
