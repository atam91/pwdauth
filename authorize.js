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

const isArray = require("lodash/isArray");
const isEmpty = require("lodash/isEmpty");
const isFunction = require("lodash/isFunction");
const isObject = require("lodash/isObject");
const isString = require("lodash/isString");
const isInteger = require("lodash/isInteger");
const moment = require("moment");
const authErrors = require("./authErrors");


function authorize(loadUser, token) {
    // check callbacks
    if (!isFunction(loadUser)) {
        return Promise.resolve({
            error: authErrors.INVALID_CALLBACK
        });
    }

    // check token well-formed
    if (!isObject(token) ||
        !token.hasOwnProperty("sessionKey") || !isString(token.sessionKey) || isEmpty(token.sessionKey)) {
        return Promise.resolve({
            error: authErrors.TOKEN_NOT_WELL_FORMED
        });
    }

    // load user
    return loadUser(token.sessionKey)
        .then(function (user) {
            if (!isObject(user)) {
                return {
                    error: authErrors.INVALID_TOKEN_HASH
                };
            }
            if (!user.hasOwnProperty("sessionDurationMinutes") || !isInteger(user.sessionDurationMinutes) ||
                !user.hasOwnProperty("sessionStartTime") || !isString(user.sessionStartTime) || isEmpty(user.sessionStartTime) ||
                !user.hasOwnProperty("id") || !isString(user.id) || isEmpty(user.id) ||
                !user.hasOwnProperty("role") || !isString(user.role) || isEmpty(user.role) ||
                !user.hasOwnProperty("rights") || !isArray(user.rights)) {
                return {
                    error: authErrors.INVALID_USER_LOADED,
                    user: user
                };
            }

            // check expiry date
            var now = moment();
            var validUntil = moment(user.sessionStartTime).add(user.sessionDurationMinutes, "minutes");
            if (now.isAfter(validUntil)) {
                return {
                    error: authErrors.TOKEN_EXPIRED
                };
            }
            // return roles
            return user;
        });
}

module.exports = authorize;