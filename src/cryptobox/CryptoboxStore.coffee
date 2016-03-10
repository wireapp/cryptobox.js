module.exports = class CryptoboxStore
  load_identity: ->
  save_identity: (identity) ->

  load_session: (identity, session_id) ->
  save_session: (session_id, session) ->
  delete_session: (session_id) ->

  load_prekey: (prekey_id) ->
  add_prekey: (key) ->
  delete_prekey: (prekey_id) ->
