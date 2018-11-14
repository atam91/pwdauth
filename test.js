/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const assert = require("assert");
const moment = require("moment");
const nanoid = require("nanoid");
const isArray = require("lodash/isArray");
const isNil = require("lodash/isNil");
const isObject = require("lodash/isObject");
const isString = require("lodash/isString");

const authErrors = require("./authErrors");
const authenticate = require("./authenticate");
const authorize = require("./authorize");
const createPasswordHash = require("./createPasswordHash");
const createRequest = require("./createRequest");


window = { debugPwdauth: false };
const DEBUG_TEST = true;
console.log("test: pwdauth");

// prepare env

// DB access logic or cache lookup is implied here

var userInDB = {
    id: "login1",
    pwdHash: createPasswordHash("password1", "login1"),
    sessionKey: undefined,
    sessionStartTime: undefined,
    sessionDurationMinutes: 30,
    role: "admin",
    rights: ["foo1", "bar1"]
};

function createSession(user, request) {
    return new Promise(resolve => {
        userInDB.sessionKey = nanoid();
        userInDB.sessionStartTime = moment().format();

        return resolve({
            sessionKey: userInDB.sessionKey,
            user: user
        });
    });
}

function loadUserById(userId) {
    return new Promise(resolve => {
        if (userInDB.id === userId){
            return resolve(userInDB);
        }
        return resolve(null);
    });
}

function loadUserBySessionKey(sessionKey) {
    return new Promise(resolve => {
        if (userInDB.sessionKey === sessionKey) {
            return resolve(userInDB);
        }
        return resolve(null);
    });
}
// DB access logic or cache lookup ends here

function myAuthenticate(request) {
    return authenticate(loadUserById, createRequest, createSession, request);
}

function myAuthorize(token) {
    return authorize(loadUserBySessionKey, token);
}


async function main() {
    // process user input
    var userId = "login1";
    var pwdClear = "password1";
    var pwdHash = createPasswordHash(pwdClear, userId);
    DEBUG_TEST && console.log('___pwdHash', pwdHash);

    var timestamp = moment();
    var tokenRequest = createRequest(
        "/auth1",
        userId,
        pwdHash,
        timestamp.format()
    );
    DEBUG_TEST && console.log('___tokenRequest', tokenRequest);
// obtain token
    var token = await myAuthenticate(tokenRequest);

    ///console.log(token)

    assert(isObject(token));
    assert(isNil(token.error));

// get roles
    var user = await myAuthorize(token);

    assert(isString(user.id));
    assert.equal(user.id, 'login1');
    assert(isString(user.role));
    assert(isArray(user.rights));
    assert(isNil(user.error));
    assert.equal(user.rights.length, 2);


// test authenticate error messages


    assert.deepEqual(await authenticate({foo: "bar"}), { error: authErrors.INVALID_CALLBACK });
    assert.deepEqual(await myAuthenticate(null), { error: authErrors.REQUEST_NOT_WELL_FORMED });
    assert.deepEqual(await myAuthenticate("foo"), { error: authErrors.REQUEST_NOT_WELL_FORMED });
    assert.deepEqual(await myAuthenticate({foo: "bar"}), { error: authErrors.REQUEST_NOT_WELL_FORMED });
    assert.deepEqual(await myAuthenticate({
        path: "/auth1",
        key: userId,
        timestamp: timestamp.format("MM.DD.YYYY"),
        hmac: "..."
    }), { error: authErrors.INVALID_DATE_FORMAT });
    assert.deepEqual(await myAuthenticate({
        path: "/auth2",
        key: "foo1",
        timestamp: timestamp.format(),
        hmac: "..."
    }), { error: authErrors.INVALID_SESSION_KEY });
    assert.deepEqual(await myAuthenticate({
        path: "/auth2",
        key: userId,
        timestamp: timestamp.format(),
        hmac: "..."
    }), { error: authErrors.INVALID_SESSION_KEY });


// test authorize error messages

    assert.deepEqual(await authorize({foo: "bar"}), { error: authErrors.INVALID_CALLBACK });
    assert.deepEqual(await myAuthorize(null), { error: authErrors.TOKEN_NOT_WELL_FORMED });
    assert.deepEqual(await myAuthorize({foo: "bar"}), { error: authErrors.TOKEN_NOT_WELL_FORMED });
    assert.deepEqual(await myAuthorize({sessionKey: "foo"}), { error: authErrors.INVALID_TOKEN_HASH });
    userInDB.sessionStartTime = moment().add(-40, "minutes").format();
    assert.deepEqual(await myAuthorize(token), { error: authErrors.TOKEN_EXPIRED });
}


main()
    .then(() => { console.log('test success!'); });