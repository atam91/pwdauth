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
    userInDB.sessionKey = nanoid();
    userInDB.sessionStartTime = moment().format();
    return userInDB.sessionKey;
}

function loadUserById(userId) {
    if (userInDB.id === userId){
        return userInDB;
    }
    return null;
}

function loadUserBySessionKey(sessionKey) {
    if (userInDB.sessionKey === sessionKey){
        return userInDB;
    }
    return null;
}
// DB access logic or cache lookup ends here

function myAuthenticate(request) {
    return authenticate(loadUserById, createRequest, createSession, request);
}

function myAuthorize(token) {
    return authorize(loadUserBySessionKey, token);
}


// test success

// process user input
var userId = "login1";
var pwdClear = "password1";
var pwdHash = createPasswordHash(pwdClear, userId);
var timestamp = moment();
var tokenRequest = createRequest(
    "/auth1",
    userId,
    pwdHash,
    timestamp.format()
);
// obtain token
var token = myAuthenticate(tokenRequest);

assert(isObject(token));
assert(isNil(token.error));

// get roles
var user = myAuthorize(token);

assert(isString(user.id));
assert(isString(user.role));
assert(isArray(user.rights));
assert(isNil(user.error));
assert.equal(user.rights.length, 2);


// test authenticate error messages

assert.equal(authenticate({foo: "bar"}).error, authErrors.INVALID_CALLBACK);
assert.equal(myAuthenticate(null).error, authErrors.REQUEST_NOT_WELL_FORMED);
assert.equal(myAuthenticate("foo").error, authErrors.REQUEST_NOT_WELL_FORMED);
assert.equal(myAuthenticate({foo: "bar"}).error, authErrors.REQUEST_NOT_WELL_FORMED);
assert.equal(myAuthenticate({
    path: "/auth1",
    key: userId,
    timestamp: timestamp.format("MM.DD.YYYY"),
    hmac: "..."
}).error, authErrors.INVALID_DATE_FORMAT);
assert.equal(myAuthenticate({
    path: "/auth2",
    key: "foo1",
    timestamp: timestamp.format(),
    hmac: "..."
}).error, authErrors.USER_NOT_FOUND);
assert.equal(myAuthenticate({
    path: "/auth2",
    key: userId,
    timestamp: timestamp.format(),
    hmac: "..."
}).error, authErrors.INVALID_REQUEST_HASH);


// test authorize error messages

assert.equal(authorize({foo: "bar"}).error, authErrors.INVALID_CALLBACK);
assert.equal(myAuthorize(null).error, authErrors.TOKEN_NOT_WELL_FORMED);
assert.equal(myAuthorize({foo: "bar"}).error, authErrors.TOKEN_NOT_WELL_FORMED);
assert.equal(myAuthorize({sessionKey: "foo"}).error, authErrors.INVALID_TOKEN_HASH);
userInDB.sessionStartTime = moment().add(-40, "minutes").format();
assert.equal(myAuthorize(token).error, authErrors.TOKEN_EXPIRED);

console.log('test success!');