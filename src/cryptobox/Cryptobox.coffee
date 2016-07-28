#
# Wire
# Copyright (C) 2016 Wire Swiss GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/.
#

Proteus = require 'proteus'

CryptoboxStore = require './CryptoboxStore'
CryptoboxSession = require './CryptoboxSession'

class ReadOnlyStore extends Proteus.session.PreKeyStore
  constructor: (@store) ->
    @removed_prekeys = []

  get_prekey: (prekey_id) ->
    return new Promise (resolve, reject) =>
      if @removed_prekeys.indexOf(prekey_id) isnt -1
        resolve null

      @store.load_prekey prekey_id
      .then (pk) ->
        resolve pk

      .catch (e) ->
        reject e

  remove: (prekey_id) ->
    return new Promise (resolve, reject) =>
      @removed_prekeys.push prekey_id
      resolve()

module.exports = class Cryptobox
  constructor: (@store) ->
    return new Promise (resolve, reject) =>
      # XXX: no access to proteus internal funcs, replace with typescript annotation
      # Proteus.util.TypeUtil.assert_is_instance cryptobox.CryptoboxStore, @store

      @store.load_identity()
      .then (id) =>
        if not id
          @identity = Proteus.keys.IdentityKeyPair.new()
          @store.save_identity @identity
          .then ->
            Object.freeze @
            resolve @

        else
          @identity = id
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

      Proteus.session.Session.init_from_prekey @identity, bundle
      .then (session) ->
        resolve new CryptoboxSession client_id, pk_store, session

      .catch (e) ->
        reject e

  session_from_message: (session_id, envelope) ->
    return new Promise (resolve, reject) =>
      env = Proteus.message.Envelope.deserialise envelope
      pk_store = new ReadOnlyStore @store

      Proteus.session.Session.init_from_message @identity, pk_store, env
      .then ([session, plaintext]) ->
        resolve [new CryptoboxSession(session_id, pk_store, session), plaintext]

      .catch (e) ->
        reject e

  session_load: (session_id) ->
    return new Promise (resolve, reject) =>
      @store.load_session @identity, session_id
      .then (session) =>
        if not session
          resolve null

        pk_store = new ReadOnlyStore @store
        resolve new cryptobox.CryptoboxSession session_id, pk_store, session

  session_save: (session) ->
    return new Promise (resolve, reject) =>
      @store.save_session session.id, session.session
      .then =>
        Promise.all(session.pk_store.removed_prekeys.map((pk) => @store.delete_prekey pk))

      .then ->
        resolve()

  session_delete: (session_id) ->
    return @store.delete_session session_id

  new_prekey: (prekey_id) ->
    return new Promise (resolve, reject) =>
      pk = Proteus.keys.PreKey.new prekey_id
      @store.add_prekey pk
      .then =>
        resolve Proteus.keys.PreKeyBundle.new(@identity.public_key, pk).serialise()
      .catch (error) ->
        reject error
