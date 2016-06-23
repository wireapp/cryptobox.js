module.exports = class TestStore extends cryptobox.CryptoboxStore
  constructor: ->
    @identity = Proteus.keys.IdentityKeyPair.new()
    @sessions = {}
    @prekeys = {}

  load_identity: ->
    return new Promise (resolve, reject) =>
      resolve @identity

  save_identity: (identity) ->
    return new Promise (resolve, reject) =>
      @identity = identity
      resolve()

  load_session: (identity, session_id) ->
    return new Promise (resolve, reject) =>
      serialised = @sessions[session_id]
      if not serialised
        resolve undefined

      resolve Proteus.session.Session.deserialise identity, serialised

  save_session: (session_id, session) ->
    return new Promise (resolve, reject) =>
      @sessions[session_id] = session.serialise()
      resolve()

  delete_session: (session_id) ->
    return new Promise (resolve, reject) =>
      delete @sessions[session_id]
      resolve()

  add_prekey: (prekey) ->
    return new Promise (resolve, reject) =>
      @prekeys[prekey.key_id] = prekey.serialise()
      resolve()

  load_prekey: (prekey_id) ->
    return new Promise (resolve, reject) =>
      serialised = @prekeys[prekey_id]
      if not serialised
        resolve undefined

      resolve Proteus.keys.PreKey.deserialise serialised

  delete_prekey: (prekey_id) ->
    return new Promise (resolve, reject) =>
      delete @prekeys[prekey_id]
      resolve()
