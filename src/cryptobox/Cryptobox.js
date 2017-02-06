
/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

const Proteus = require('proteus');

const CryptoboxStore = require('./CryptoboxStore');
const CryptoboxSession = require('./CryptoboxSession');

class ReadOnlyStore extends Proteus.session.PreKeyStore {
  constructor (store) {
    super();
    this.store = store;
    this.removed_prekeys = [];
  }

  get_prekey (prekey_id) {
    return new Promise ((resolve, reject) => {
      if (this.removed_prekeys.indexOf(prekey_id) !== -1) {
        resolve(null);
      }

      this.store.load_prekey(prekey_id)
      .then ((pk) => {
        resolve(pk);
      })

      .catch ((e) => {
        reject(e);
      });
    });
  }

  remove (prekey_id) {
    return new Promise ((resolve, reject) => {
      this.removed_prekeys.push(prekey_id);
      resolve();
    });
  }
}

module.exports = class Cryptobox {
  constructor (store) {
    this.store = store;
    return new Promise ((resolve, reject) => {
      // XXX: no access to proteus internal funcs, replace with typescript annotation
      // Proteus.util.TypeUtil.assert_is_instance cryptobox.CryptoboxStore, this.store

      this.store.load_identity()
      .then ((id) => {
        if (!id) {
          this.identity = Proteus.keys.IdentityKeyPair.new();
          this.store.save_identity(this.identity)
          .then(() => {
            Object.freeze(this);
            resolve(this);
          });
        } else {
          this.identity = id;
          Object.freeze(this);
          resolve(this);
        }
      });
    });
  }
  /*
   * this.param client_id [String] Client ID
   * this.param pre_key_bundle [ArrayBuffer] Serialized Pre-Key Bundle
   */
  session_from_prekey (client_id, pre_key_bundle) {
    return new Promise ((resolve, reject) => {
      const bundle = Proteus.keys.PreKeyBundle.deserialise(pre_key_bundle);
      const pk_store = new ReadOnlyStore(this.store);

      Proteus.session.Session.init_from_prekey(this.identity, bundle)
      .then ((session) => {
        resolve (new CryptoboxSession(client_id, pk_store, session));
      })

      .catch ((e) => {
        reject(e);
      });
    });
  }

  session_from_message (session_id, envelope) {
    return new Promise ((resolve, reject) => {
      const env = Proteus.message.Envelope.deserialise(envelope);
      const pk_store = new ReadOnlyStore(this.store);

      Proteus.session.Session.init_from_message(this.identity, pk_store, env)
      .then (([session, plaintext]) => {
        resolve ([new CryptoboxSession(session_id, pk_store, session), plaintext]);
      })

      .catch ((e) => {
        reject(e);
      });
    });
  }

  session_load (session_id) {
    return new Promise ((resolve, reject) => {
      this.store.load_session(this.identity, session_id)
      .then((session) => {
        if (!session) {
          resolve(null);
        }

        const pk_store = new ReadOnlyStore(this.store);
        resolve (new cryptobox.CryptoboxSession(session_id, pk_store, session));
      });
    });
  }

  session_save (session) {
    return new Promise ((resolve, reject) => {
      this.store.save_session(session.id, session.session)
      .then(() => {
        Promise.all(session.pk_store.removed_prekeys.map((pk) => this.store.delete_prekey(pk)));
      })

      .then(() => {
        resolve();
      });
    });
  }

  session_delete (session_id) {
    return this.store.delete_session(session_id);
  }

  new_prekey (prekey_id) {
    return new Promise ((resolve, reject) => {
      const pk = Proteus.keys.PreKey.new(prekey_id);
      this.store.add_prekey(pk)
      .then(() => {
        resolve(Proteus.keys.PreKeyBundle.new(this.identity.public_key, pk).serialise());
      })
      .catch ((error) => {
        reject(error);
      });
    });
  }
};
