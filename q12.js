/* Copyright (C) 2007-2008 Jeffrey William Scudder
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// A global object to provide a namespace for all classes and functions.
var q12 = {};

/**
 * Find a DOM element in the  by id.
 *
 * @param {String} targetId The id of the element.
 * @return {DOM Element} The DOM element in the document with the id.
 */
q12.gid = function(targetId) {
  return document.getElementById(targetId);
};

/**
 * Creates a new DOM element with the desired tag.
 *
 * @param {String} tag The type of tag to be created.
 * @return {DOM Element} The new DOM element.
 */
q12.c = function(tag) {
  return document.createElement(tag);
};

/**
 * Creates a text element containing the specified text.
 *
 * @param {String} text The contents of the text node.
 * @param {DOM Element} The new text node.
 */
q12.t = function(text) {
  return document.createTextNode(text);
};

/**
 * Joins the list using the empty strings.
 *
 * @param {Array} list List The list to convert to a string.
 * @param {String} The contents of the array joined.
 */
q12.j = function(list) {
  return list.join('');
};

/**
 * Removes a DOM element from the document.
 *
 * @param domElement The element to delete.
 */
q12.d = function(domElement) {
  domElement.parentNode.removeChild(domElement);
}

// These need cross browser testing. (Beware IE's issue with innerHTML on a
// p tag).
/**
 * Escapes the string to safe text sets the contents of the Dom element.
 * This function uses q12's toHtml function to convert the text into a form
 * acceptable within HTML.
 *
 * @param {DOM Element} domElement The node whose contents should be set.
 * @param {String} textString The string which should be escaped to display
 *     as HTML.
 */
q12.setText = function(domElement, textString) {
  domElement.innerHTML = q12.toHtml(domElement);
};

/**
 * Escapes the string to safe text sets the contents of the Dom element.
 * This function uses q12's toHtml function to convert the text into a form
 * acceptable within HTML.
 *
 * @param {DOM Element} domElement The node whose contents should be set.
 * @param {String} htmlString A string of HTML to set the contents.
 */
q12.setHtml = function(domElement, htmlString) {
  domElement.innerHTML = htmlString;
};

/**
 * Creates a DOM tree from a simple list.
 * The structure of the tree passed in is as follows:
 * ['elementTag', 
 *  {attribute1: value,
 *   attribute2: value,
 *   style: {property1: value,
 *           property2: value}},
 *  'child text node',
 *  ['elementTag',
 *   {property: value},
 *   'grandchild text node'],
 *  'third node']
 * The above will result in a DOM node which has three child nodes, the
 * first and third will be text nodes because the values were strings.
 * The second child node will be a DOM node as well.
 *
 * @param {Array} t The tree's structure as a collection of strings, lists,
 *     and simple objects. The structure is as follows
 *     ['elementTag', {attributes}, child, child, child, ...]
 * @return {DOM Element} Returns a new DOM element.
 */
q12.tree = function(t) {
  // Create the node using the tag which is first in the list.
  var domNode = document.createElement(t[0]);
  // Add all HTML attributes to the node.
  for (var key in t[1]) {
    // The style attributes get special treatment.
    if (key == 'style') {
      for (var styleAttribute in t[1].style) {
        domNode.style[styleAttribute] = t[1].style[styleAttribute];
      }
    } else {
      domNode[key] = t[1][key];
    }
  }
  // Iterate over all child nodes, converting them to either text or HTML nodes.
  for (var index = 2, child; child = t[index]; index++) {
    if (typeof(child) == 'string') {
      domNode.appendChild(document.createTextNode(child));
    } else {
      // Build recursively.
      domNode.appendChild(q12['tree'](child));
    }
  }
  return domNode; 
}

/**
 * Forms a URL string from the components.
 *
 * @param {String} base The beginning of the URL.
 * @param {Object} params A dictionary of URL parameters and their values. 
 *     These keys and values are escaped and appended to the base of the 
 *     URL.
 * @return {String} A string composed of the base URL and the object's
 *     key values pairs as URL parameters.
 */ 
q12.url = function(base, params) {
  var parameters = [];
  for (key in params) {
    parameters.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
  }
  return [base, parameters.join('&')].join('?');
};

/**
 * Makes an HTTP request and sets a callback to be called on state 4.
 *
 * @param {String} httpVerb The HTTP action to perform, typical values
 *     are 'GET', 'POST', 'HEAD', 'PUT', 'DELETE'. 
 * @param {String} data The data to be sent with the request. Optional,
 *     should not be used in a GET, HEAD, or DELETE.
 * @param {String} url The URL to which the request will be made.
 * @param {Object} headers Key value pairs to include in the request as
 *     HTTP headers.
 * @param {Function} handler The funciton to be executed when the server's
 *     response has been fully received.
 */
q12.httpRequest = function(httpVerb, data, url, headers, handler) {
  var http = null;
  if (window.XMLHttpRequest) {
    http = new XMLHttpRequest();
  } else if (window.ActiveXObject) {
    http = new ActiveXObject('Microsoft.XMLHTTP');
  }
  if (http) {
    http.open(httpVerb, url, true);
    http.onreadystatechange = function() {
      if (http.readyState == 4) {
        handler(http);
      }
    };
    var propery = null;
    for (property in headers) {
      http.setRequestHeader(property, headers[property]);
    }
    http.send(data);
  } else {
    throw new Error('Unable to create the HTTP request object.');
  }
};

/**
 * Makes a GET request and calls the callback function.
 *
 * @param {String} url The target URL.
 * @param {Object} headers Key value pairs which are sent as HTTP 
 *     headers as part of the get request.
 * @param {Function} handler The function to be called when the server's
 *     response is ready.
 */
q12.get = function(url, headers, handler) {
  q12.httpRequest('GET', null, url, headers, handler);
};

q12.post = function(data, url, headers, handler) {
  q12.httpRequest('POST', data, url, headers, handler);
};

q12.put = function(data, url, headers, handler) {
  q12.httpRequest('PUT', data, url, headers, handler);
};

q12.del = function(url, headers, handler) {
  q12.httpRequest('DELETE', null, url, headers, handler);
};

q12.setCookie = function(name, value, days, path) {
  var expires = ''
  if (days) {
    var date = new Date();
    date.setTime(date.getTime() + (days*24*60*60*1000));
    expires = '; expires=' + date.toGMTString();
  }
  document.cookie = [name, '=', value, expires, '; path=', path].join(''); 
}

q12.getCookie = function(name) {
  var nameEQ = name + '=';
  var ca = document.cookie.split(';');
  for(var i = 0; i < ca.length; i++) {
    var c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1, c.length);
    }
    if (c.indexOf(nameEQ) == 0) {
      return c.substring(nameEQ.length, c.length);
    }
  }
  return null;
}

// Base 64 conversion code was written by Tyler Akins and has been placed 
// in the public domain.  It would be nice if you left this header intact.
// Base64 code from Tyler Akins -- http://rumkin.com
q12.b64KeyStr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw' + 
    'xyz0123456789+/=';

/**
 * Encodes the data in base64 encoding.
 *
 * @param {String} input The original data to be base 64 encoded.
 * @return {String} The input string in base64 encoding.
 */
q12.to64 = function(input) {
  var output = "";
  var chr1, chr2, chr3;
  var enc1, enc2, enc3, enc4;
  var i = 0;

  do {
    chr1 = input.charCodeAt(i++);
    chr2 = input.charCodeAt(i++);
    chr3 = input.charCodeAt(i++);

    enc1 = chr1 >> 2;
    enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
    enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
    enc4 = chr3 & 63;

    if (isNaN(chr2)) {
      enc3 = enc4 = 64;
    } else if (isNaN(chr3)) {
      enc4 = 64;
    }

    output = [output, q12.b64KeyStr.charAt(enc1), 
              q12.b64KeyStr.charAt(enc2), 
              q12.b64KeyStr.charAt(enc3), 
              q12.b64KeyStr.charAt(enc4)].join('');
  } while (i < input.length);
   
  return output;
};

/**
 * Decodes the data from base 64 encoding.
 * 
 * @param {String} input A base64 encoded stirng to be decoded.
 * @return {String} The data decoded from base64 encoding.
 */
q12.from64 = function(input) {
  var output = "";
  var chr1, chr2, chr3;
  var enc1, enc2, enc3, enc4;
  var i = 0;

  // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");

  do {
    enc1 = q12.b64KeyStr.indexOf(input.charAt(i++));
    enc2 = q12.b64KeyStr.indexOf(input.charAt(i++));
    enc3 = q12.b64KeyStr.indexOf(input.charAt(i++));
    enc4 = q12.b64KeyStr.indexOf(input.charAt(i++));

    chr1 = (enc1 << 2) | (enc2 >> 4);
    chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
    chr3 = ((enc3 & 3) << 6) | enc4;

    output = output + String.fromCharCode(chr1);

    if (enc3 != 64) {
      output = output + String.fromCharCode(chr2);
    }
    if (enc4 != 64) {
      output = output + String.fromCharCode(chr3);
    }
  } while (i < input.length);

  return output;
};

/**
 * Converts a string to into an equivalend form when displayed as HTML.
 * Performs HTML escaping on special characters in HTML and preserves 
 * spaces. The following characters are converted: &amp;, '&nbsp;&nbsp;',
 * &lt;, &gt;, &quot, and 
 * newline (converted to a line break).
 *
 * @param {String} input The original string to be escaped.
 * @return {String} An HTML version of the string.
 */
q12.toHtml = function(input) {
  // Replaces the following strings with their HTML code equivalents:
  // '&', '  ', '<', '>', '"', '\n'
  return input.replace(/&/g, '&amp;').replace(/  /g, '&nbsp;&nbsp;'
      ).replace(/</g, '&lt;').replace(/>/g, '&gt;'
          ).replace(/"/g, '&quot;').replace(/\n/g, '<br/>');
};

/**
 * Reverses the HTML escaping from toHtml. 
 *
 * @param {String} input The HTML escaped string to be unescaped back to
 *     the original text.
 * @return {String} The original string with HTML escaping reversed.
 */
q12.fromHtml = function(input) {
  // Reverses the escape characters produced by toHtml.
  return input.replace(/<br\/>/g, '\n').replace(/&quot;/g, '"'
      ).replace(/&gt;/g, '>').replace(/&lt;/g, '<'
          ).replace(/&nbsp;&nbsp;/g, '  ').replace(/&amp;/g, '&');
};

q12.toUrl = function(input) {
  return encodeURIComponent(input);
};

q12.fromUrl = function(input) {
  return decodeURIComponent(input);
};

// AES code copyright 2005-2007 Chris Veness under LGPL from 
// http://www.movable-type.co.uk/scripts/aes.html.
/**
 * AES Cipher function: encrypt 'input' with Rijndael algorithm
 *
 *   takes   byte-array 'input' (16 bytes)
 *           2D byte-array key schedule 'w' (Nr+1 x Nb bytes)
 *
 *   applies Nr rounds (10/12/14) using key schedule w for 'add round key' 
 *       stage
 *
 *   returns byte-array encrypted value (16 bytes)
 */
q12.cipher = function(input, w) { 
  // main Cipher function [§5.1]
  // block size (in words): no of columns in state (fixed at 4 for AES)
  var Nb = 4; 
  // no of rounds: 10/12/14 for 128/192/256-bit keys
  var Nr = w.length/Nb - 1; 

  // initialise 4xNb byte-array 'state' with input [§3.4]
  var state = [[],[],[],[]];
  for (var i=0; i<4*Nb; i++) state[i%4][Math.floor(i/4)] = input[i];

  state = q12.addRoundKey(state, w, 0, Nb);

  for (var round=1; round<Nr; round++) {
    state = q12.subBytes(state, Nb);
    state = q12.shiftRows(state, Nb);
    state = q12.mixColumns(state, Nb);
    state = q12.addRoundKey(state, w, round, Nb);
  }

  state = q12.subBytes(state, Nb);
  state = q12.shiftRows(state, Nb);
  state = q12.addRoundKey(state, w, Nr, Nb);

  // convert state to 1-d array before returning [§3.4]
  var output = new Array(4*Nb);
  for (var i=0; i<4*Nb; i++) output[i] = state[i%4][Math.floor(i/4)];
  return output;
};


q12.subBytes = function(s, Nb) {
  // apply SBox to state S [§5.1.1]
  for (var r=0; r<4; r++) {
    for (var c=0; c<Nb; c++) s[r][c] = q12.sbox[s[r][c]];
  }
  return s;
};


q12.shiftRows = function(s, Nb) {
  // shift row r of state S left by r bytes [§5.1.2]
  var t = new Array(4);
  for (var r=1; r<4; r++) {
    // shift into temp copy
    for (var c=0; c<4; c++) t[c] = s[r][(c+r)%Nb];
    // and copy back
    for (var c=0; c<4; c++) s[r][c] = t[c];
  }
  // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
  // see fp.gladman.plus.com/cryptography_technology/rijndael/aes.spec.311.pdf 
  return s;
};


q12.mixColumns = function(s, Nb) {
  // combine bytes of each col of state S [§5.1.3]
  for (var c=0; c<4; c++) {
    var a = new Array(4);
    // 'a' is a copy of the current column from 's'
    var b = new Array(4);
    // 'b' is a{02} in GF(2^8)
    for (var i=0; i<4; i++) {
      a[i] = s[i][c];
      b[i] = s[i][c]&0x80 ? s[i][c]<<1 ^ 0x011b : s[i][c]<<1;
    }
    // a[n] ^ b[n] is a{03} in GF(2^8)
    s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // 2*a0 + 3*a1 + a2 + a3
    s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 * 2*a1 + 3*a2 + a3
    s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + 2*a2 + 3*a3
    s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // 3*a0 + a1 + a2 + 2*a3
  }
  return s;
};


q12.addRoundKey = function(state, w, rnd, Nb) {
  // xor Round Key into state S [§5.1.4]
  for (var r=0; r<4; r++) {
    for (var c=0; c<Nb; c++) state[r][c] ^= w[rnd*4+c][r];
  }
  return state;
};


q12.keyExpansion = function(key) {
  // generate Key Schedule (byte-array Nr+1 x Nb) from Key [§5.2]
  // block size (in words): no of columns in state (fixed at 4 for AES)
  var Nb = 4;
  // key length (in words): 4/6/8 for 128/192/256-bit keys
  var Nk = key.length/4;
  // no of rounds: 10/12/14 for 128/192/256-bit keys
  var Nr = Nk + 6;

  var w = new Array(Nb*(Nr+1));
  var temp = new Array(4);

  for (var i=0; i<Nk; i++) {
    var r = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
    w[i] = r;
  }

  for (var i=Nk; i<(Nb*(Nr+1)); i++) {
    w[i] = new Array(4);
    for (var t=0; t<4; t++) temp[t] = w[i-1][t];
    if (i % Nk == 0) {
      temp = q12.subWord(q12.rotWord(temp));
      for (var t=0; t<4; t++) temp[t] ^= q12.rcon[i/Nk][t];
    } else if (Nk > 6 && i%Nk == 4) {
      temp = q12.subWord(temp);
    }
    for (var t=0; t<4; t++) w[i][t] = w[i-Nk][t] ^ temp[t];
  }

  return w;
};

q12.subWord = function(w) {
  // apply SBox to 4-byte word w
  for (var i=0; i<4; i++) w[i] = q12.sbox[w[i]];
  return w;
}

q12.rotWord = function(w) {
  // rotate 4-byte word w left by one byte
  w[4] = w[0];
  for (var i=0; i<4; i++) w[i] = w[i+1];
  return w;
};


// Sbox is pre-computed multiplicative inverse in GF(2^8) used in SubBytes and
//  KeyExpansion [§5.1.1]
q12.sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,
            0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,
            0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,
            0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,
            0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,
            0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,
            0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,
            0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
            0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,
            0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,
            0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,
            0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,
            0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,
            0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,
            0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,
            0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,
            0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,
            0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,
            0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];

// Rcon is Round Constant used for the Key Expansion 
// [1st col is 2^(r-1) in GF(2^8)] [§5.2]
q12.rcon = [ [0x00, 0x00, 0x00, 0x00],
             [0x01, 0x00, 0x00, 0x00],
             [0x02, 0x00, 0x00, 0x00],
             [0x04, 0x00, 0x00, 0x00],
             [0x08, 0x00, 0x00, 0x00],
             [0x10, 0x00, 0x00, 0x00],
             [0x20, 0x00, 0x00, 0x00],
             [0x40, 0x00, 0x00, 0x00],
             [0x80, 0x00, 0x00, 0x00],
             [0x1b, 0x00, 0x00, 0x00],
             [0x36, 0x00, 0x00, 0x00] ]; 


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/**
 * Use AES to encrypt 'plaintext' with 'password' using 'nBits' key, in 
 * 'Counter' mode of operation
 * - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 *   for each block
 *   - outputblock = cipher(counter, key)
 *   - cipherblock = plaintext xor outputblock
 */
q12.aesEncryptCtr = function(plaintext, password, nBits) {
  if (null == plaintext || plaintext.length == 0) {
    return '';
  }

  // standard allows 128/192/256 bit keys
  if (!(nBits==128 || nBits==192 || nBits==256)) return '';
	
  // for this example script, generate the key by applying Cipher to 1st 
  // 16/24/32 chars of password; 
  // for real-world applications, a more secure approach would be to hash the 
  // password e.g. with SHA-1
  // no bytes in key
  var nBytes = nBits/8; 
  var pwBytes = new Array(nBytes);
  for (var i=0; i<nBytes; i++) pwBytes[i] = password.charCodeAt(i) & 0xff;
  var key = q12.cipher(pwBytes, q12.keyExpansion(pwBytes));
  // key is now 16/24/32 bytes long
  key = key.concat(key.slice(0, nBytes-16));

  // initialise counter block (NIST SP800-38A §B.2): millisecond time-stamp for
  // nonce in 1st 8 bytes,
  // block counter in 2nd 8 bytes
  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
  var blockSize = 16;
  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
  var counterBlock = new Array(blockSize);
  // milliseconds since 1-Jan-1970
  var nonce = (new Date()).getTime();

  // encode nonce in two stages to cater for JavaScript 32-bit limit on 
  // bitwise ops
  for (var i=0; i<4; i++) counterBlock[i] = (nonce >>> i*8) & 0xff;
  for (var i=0; i<4; i++) counterBlock[i+4] = (nonce/0x100000000 >>> i*8)&0xff; 

  // generate key schedule - an expansion of the key into distinct Key Rounds 
  // for each round
  var keySchedule = q12.keyExpansion(key);

  var blockCount = Math.ceil(plaintext.length/blockSize);
  // ciphertext as array of strings
  var ciphertext = new Array(blockCount);
  
  for (var b=0; b<blockCount; b++) {
    // set counter (block #) in last 8 bytes of counter block 
    // (leaving nonce in 1st 8 bytes)
    // again done in two stages for 32-bit ops
    for (var c=0; c<4; c++) counterBlock[15-c] = (b >>> c*8) & 0xff;
    for (var c=0; c<4; c++) counterBlock[15-c-4] = (b/0x100000000 >>> c*8)

    // encrypt counter block
    var cipherCntr = q12.cipher(counterBlock, keySchedule);
    // calculate length of final block:
    var blockLength=b<blockCount-1?blockSize:(plaintext.length-1)%blockSize+1;

    var ct = '';
    for (var i=0; i<blockLength; i++) {  
      // -- xor plaintext with ciphered counter byte-by-byte --
      var plaintextByte = plaintext.charCodeAt(b*blockSize+i);
      var cipherByte = plaintextByte ^ cipherCntr[i];
      ct += String.fromCharCode(cipherByte);
    }
    // ct is now ciphertext for this block

    // escape troublesome characters in ciphertext
    ciphertext[b] = q12.escCtrlChars(ct);
  }

  // convert the nonce to a string to go on the front of the ciphertext
  var ctrTxt = '';
  for (var i=0; i<8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);
  ctrTxt = q12.escCtrlChars(ctrTxt);

  // use '-' to separate blocks, use Array.join to concatenate arrays of 
  // strings for efficiency
  return ctrTxt + '-' + ciphertext.join('-');
};


/** 
 * Use AES to decrypt 'ciphertext' with 'password' using 'nBits' key, in 
 * Counter mode of operation
 *
 *   for each block
 *   - outputblock = cipher(counter, key)
 *   - cipherblock = plaintext xor outputblock
 */
q12.aesDecryptCtr = function(ciphertext, password, nBits) {
  if (null == ciphertext || ciphertext.length == 0) {
    return '';
  }
  
  // standard allows 128/192/256 bit keys
  if (!(nBits==128 || nBits==192 || nBits==256)) return '';  

  var nBytes = nBits/8;  // no bytes in key
  var pwBytes = new Array(nBytes);
  for (var i=0; i<nBytes; i++) pwBytes[i] = password.charCodeAt(i) & 0xff;
  var pwKeySchedule = q12.keyExpansion(pwBytes);
  var key = q12.cipher(pwBytes, pwKeySchedule);
  key = key.concat(key.slice(0, nBytes-16));  // key is now 16/24/32 bytes long

  var keySchedule = q12.keyExpansion(key);

  // split ciphertext into array of block-length strings 
  ciphertext = ciphertext.split('-');  

  // recover nonce from 1st element of ciphertext
  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
  var blockSize = 16;
  var counterBlock = new Array(blockSize);
  var ctrTxt = q12.unescCtrlChars(ciphertext[0]);
  for (var i=0; i<8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

  var plaintext = new Array(ciphertext.length-1);

  for (var b=1; b<ciphertext.length; b++) {
    // set counter (block #) in last 8 bytes of counter block 
    // (leaving nonce in 1st 8 bytes)
    for (var c=0; c<4; c++) counterBlock[15-c] = ((b-1) >>> c*8) & 0xff;
    for (var c=0; c<4; c++)counterBlock[15-c-4]=((b/0x100000000-1)>>>c*8)&0xff;
    // encrypt counter block
    var cipherCntr = q12.cipher(counterBlock, keySchedule);

    ciphertext[b] = q12.unescCtrlChars(ciphertext[b]);

    var pt = '';
    for (var i=0; i<ciphertext[b].length; i++) {
      // -- xor plaintext with ciphered counter byte-by-byte --
      var ciphertextByte = ciphertext[b].charCodeAt(i);
      var plaintextByte = ciphertextByte ^ cipherCntr[i];
      pt += String.fromCharCode(plaintextByte);
    }
    // pt is now plaintext for this block

    plaintext[b-1] = pt;  // b-1 'cos no initial nonce block in plaintext
  }

  return plaintext.join('');
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

q12.escCtrlChars = function(str) {
  // escape control chars which might cause problems handling ciphertext
  return str.replace(/[\0\t\n\v\f\r\xa0!-]/g, 
      function(c) { return '!' + c.charCodeAt(0) + '!'; });
};  
// \xa0 to cater for bug in Firefox; include '-' to leave it free for use as a
// block marker

q12.unescCtrlChars = function(str) {
  // unescape potentially problematic control characters
  return str.replace(/!\d\d?\d?!/g, 
      function(c) { return String.fromCharCode(c.slice(1,-1)); });
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

// Back to code written by Jeffrey Scudder

q12.toAes = function(data, key) {
  return q12.aesEncryptCtr(data, key, 256);
};

q12.fromAes = function(data, key) {
  return q12.aesDecryptCtr(data, key, 256);
};

/**
 * Returns an array containing the state of a new ARC4 generator.
 */
q12.initArc4 = function() {
  // Initialize an array of ints 0-255 in order.
  // This array is copied and used as a base for all keys.
  x = [];
  for (var i = 0; i < 256; i++) {
    x.push(i);
  };
  x.push(0);
  x.push(0);
  return x;
};

q12.seedArc4Key = function(password) {
  // The generated key should have 258 integers. The first 256 are the values
  // in the key matrix (s) and the last 2 are the integer indicies for 
  // transforming s as it is used (i and j). 
  var s = q12.initArc4();  
  var j = 0;
  var temp;
  var passwordLength = password.length;
  for (var i = 0; i < 256; i++) {
    j = (j + s[i] + (password.charCodeAt(i % passwordLength))) % 256;
    temp = s[i];
    s[i] = s[j];
    s[j] = temp;
  }
  return s;
};

q12.stepArc4Key = function(keyArray) {
  var i = keyArray[256];
  var j = keyArray[257];
  var temp;
  i = (i + 1) % 256;
  j = (j + keyArray[i]) % 256;
  temp = keyArray[i];
  keyArray[i] = keyArray[j];
  keyArray[j] = temp;
  keyArray[256] = i;
  keyArray[257] = j;
};

q12.nextArc4Number = function(keyArray) {
  q12.stepArc4Key(keyArray);
  var i = keyArray[256];
  var j = keyArray[257];
  return keyArray[(keyArray[i] + keyArray[j]) % 256];
};

/**
 * Combines the data with a pseudo-random key stream to weakly encrypt it.
 * To decrypt the data, use this function on the ciphertext.
 *
 * @param {String} data The plaintext or ciphertext to be encoded be 
 *     combining it with a pseudo-random stream.
 * @param {String} key A passphrase used to generate a pseudo-random key 
 *     stream.
 */
q12.arc4 = function(data, key) {
  var cipher = [];
  var key = q12.seedArc4Key(key);
  // Skip the first 1,000 states in each of the keys since the key state is
  // initially pretty guessable.
  for (var j = 0; j < 1000; j++) {
    q12.stepArc4Key(key);
  }
  for (var i = 0; i < data.length; i++) {
    cipher.push(
        String.fromCharCode(data.charCodeAt(i) ^ q12.nextArc4Number(key)));
  }
  return cipher.join('');
};

/**
 * Turns an existing class into a q12 type class and inherits methods.
 *
 * Accepts a variable number of arguments, the first argument is the function
 * which acts as this class' constructor. All subsequent arguments are classes
 * whose class members and methods are copied to this class. The class created 
 * is similar to any other class, but it has at least two additional
 * methods: inherits (which takes a list of super classes) and method
 * (which adds a new method to the class).
 */
q12.Class = function() {
  var constructor = arguments[0];
  // Begin by adding the q12 specific methods (inherits and method).
  constructor.method = q12.Class.method;
  constructor.inherits = q12.Class.inherits;
  // Now inherit methods and class members from all of the super classes
  // passed into this function call.
  // Iterate thgout the super classes (arguments) beginning at the end of the
  // list so that in the event of a conflict in naming, the classes listed
  // first take precedent. (Note that the first argument is not inherited
  // because the first argument is the original constructor for this class.)
  for (var i = arguments.length-1; i > 0; i--) {
    q12.extendClass(constructor, arguments[i]);
  }
  return constructor;
};

/**
 * Adds the function as a new method with the provided name.
 *
 * @param {String} name The name to be given to the new method. The method
 *     may be invoked using dot notation on this name. For example
 *     newClass.method('foo', function() {...}); would allow you to call
 *     x = newClass(); x.foo();
 * @param {Function} logic The function to be executed when the method is
 *     invoked.
 */
q12.Class.method = function(name, logic) {
  this.prototype[name] = logic;
};

/**
 * Copies class members and methods from each class passed in.
 *
 * Takes any number of classes as arguments. The classes which are
 * listed first have priority when copying members and methods. For
 * example, if two classes have different implementations for the method
 * foo, the method belonging to the class listed first will be used.
 */
q12.Class.inherits = function() {
  // Inherit in reverse order so that the first listed class'
  // methods will have priority over the classes listed at the end.
  for (var i = arguments.length-1; i >= 0; i--) {
    q12.extendClass(this, arguments[i]);
  }
};

/**
 * Copies the members and methods of the target class into the new class.
 *
 * @param {Object} newClass The target class which will inherit the methods
 *     members of the parentClass.
 * @param {Object} parentClass The class whose members and prototype 
 *     methods should be copied into the new class.
 */
q12.extendClass = function(newClass, parentClass) {
  if (parentClass) {
    for (var prop in parentClass) {
      if (prop != 'prototype') {
        newClass[prop] = parentClass[prop];
      }
    }
    if (parentClass.prototype) {
      for (var proto in parentClass.prototype) {
        newClass.prototype[proto] = parentClass.prototype[proto];
      }
    }
  }
};

/**
 * Adds error message to the array if the condiction has not been met.
 *
 * @param {bool} condition The test condition which should be true.
 * @param {Array} messagesArray The list of test result messages which
 *     will be rendered when all tests are completed.
 * @param message The message which should be displayed if the test 
 *     condisiton is false.
 */
q12.assert = function(condition, messagesArray, message) {
  if (condition) {
    messagesArray.push('.');
  } else {
    messagesArray.push(['Failed: ', message, ' '].join(''));
  }
};
