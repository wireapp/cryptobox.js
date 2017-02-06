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

module.exports = class TestStore extends cryptobox.CryptoboxStore {

  constructor() {
    super();
    this.identity = Proteus.keys.IdentityKeyPair.new();
    this.sessions = {};
    this.prekeys = {};
  }

  load_identity() {
    return new Promise((resolve, reject) => {
      return resolve(this.identity);
    });
  }

  save_identity(identity) {
    return new Promise((resolve, reject) => {
      this.identity = identity;
      return resolve();
    });
  }

  load_session(identity, session_id) {
    return new Promise((resolve, reject) => {
      const serialised = this.sessions[session_id];
      if (!serialised) {
        resolve(undefined);
      }
      return resolve(Proteus.session.Session.deserialise(identity, serialised));
    });
  }

  save_session(session_id, session) {
    return new Promise((resolve, reject) => {
      this.sessions[session_id] = session.serialise();
      return resolve();
    });
  }

  delete_session(session_id) {
    return new Promise((resolve, reject) => {
      delete this.sessions[session_id];
      return resolve();
    });
  }

  add_prekey(prekey) {
    return new Promise((resolve, reject) => {
      this.prekeys[prekey.key_id] = prekey.serialise();
      return resolve();
    });
  }

  load_prekey(prekey_id) {
    return new Promise((resolve, reject) => {
      const serialised = this.prekeys[prekey_id];
      if (!serialised) {
        resolve(undefined);
      }
      return resolve(Proteus.keys.PreKey.deserialise(serialised));
    });
  }

  delete_prekey(prekey_id) {
    return new Promise((resolve, reject) => {
      delete this.prekeys[prekey_id];
      return resolve();
    });
  }
};
