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

const isNil = require("lodash/isNil");
const isString = require("lodash/isString");
const isArray = require("lodash/isArray");
const sjcl = require("sjcl");
const utf8 = require("utf8");


function hmac(_key, string) {
    var key = sjcl.codec.utf8String.toBits(_key);
    var result = new sjcl.misc.hmac(key).encrypt(string);

    if (window && window.debugPwdauth) {
        console.log('__!__hmac_encrypt_with_encoding', _key, '=>', sjcl.codec.hex.fromBits(result));
    }

    return sjcl.codec.hex.fromBits(result);
}

function defaultString(str) {
    if (isString(str)) {
        return utf8.encode(str);
    } else if (!isNil(str)) {
        return utf8.encode(String(str));
    } else {
        return utf8.encode("");
    }
}
function defaultKey(key) {
    if(isArray(key)) {
        return key;
    } else {
        return defaultString(key);
    }
}


// https://github.com/bitwiseshiftleft/sjcl/issues/225
//
// python -c "import hashlib;print hashlib.sha256('foo').hexdigest()"
// 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
//
// python -c "import hashlib;print hashlib.sha256(u'привет'.encode('utf-8')).hexdigest()"
// 982c11281206e7b972ee4a5fcc85f362acf826314862212213de925079dc5652
//
// python -c "import hashlib;print hashlib.sha256('').hexdigest()"
// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//

module.exports = function(key, data, encoding) {
    var str = defaultString(data);
    var k = defaultKey(key);
    var result = hmac(k, str, encoding);

    if (window && window.debugPwdauth) {
        console.log('___hmac_sha256', k, str, encoding, '=>', result);
    }

    return result;
};