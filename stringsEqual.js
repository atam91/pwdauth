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

const isEmpty = require("lodash/isEmpty");
const isString = require("lodash/isString");

// https://security.stackexchange.com/q/60750/166297
function stringsEqual(a, b) {
    if (!isString(a) || !isString(b) || isEmpty(a) || isEmpty(b)) {
        return false;
    }
    var mismatch = a.length === b.length ? 0 : 1;
    if (1 === mismatch) {
        b = a;
    }
    for (var i = 0, il = a.length; i < il; ++i) {
        mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    }
    return mismatch === 0;
}

module.exports = stringsEqual;