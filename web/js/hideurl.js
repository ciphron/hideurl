/* 
 * by ciphron <ciphron@ciphron.org> - Feb 2013
 *
 * This file is licensed under GPL v3. It relies on SJCL, which is 
 * distributed under the terms of the BSD license, and on jQuery, which is
 * distributed under the terms of the MIT license.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 3 or later of the GNU General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


var SEPARATOR = ';'; /* separates components such as IV in ciphertext */
var MODE = 'ccm'; /* cipher mode of operation */
var TAG_SIZE = 64; /* bit length of MAC */
var KEY_SIZE = 128; / * bit length of symmetric key */
var ITERATIONS = 1024;


function loaded() {
  sjcl.random.startCollectors();
  document.getElementById("password").focus();
}

$(document).ready(function(){
    
    $('#encrypt').click(function() {
	encrypt_url();
    });

});

function show_message(message_content) {
    $('#message').html(
	"<div class=\"alert-success\">\n \
            <a class=\"close\">&times;</a>\n" +
	        message_content +
	"</div>\n"
    );
}

function show_error(message_content) {
    $('#message').html(
	"<div class=\"alert-error\">\n \
            <a class=\"close\">&times;</a>\n" +
	        message_content +
	"</div>\n"
    );
}


function encrypt_url() {

    var password = $('#password').val();
    var url = $('#url').val();


    /* TODO: proper URL validation! */

    /* If the scheme is missing, default to 'http' */
    if (!url.match('^[^:]+://')) {
	url = 'http://' + url;
    }

    try {
	var ciphertext = encrypt(password, url);

	ciphertext = encodeURIComponent(ciphertext);
	var enc_url = window.location.href.match('^([^?]*)')[1] + '?u=' + ciphertext;
  
	var content = "Your encrypted URL is\n<br/> \
<textarea cols=\"100\" readonly=\"true\" id=\"enc_url\" name=\"enc_url\">" + enc_url + "</textarea>";
	show_message(content);

	$('#enc_url').focus();
	$('#enc_url').select();

    }
    catch (err) {
	show_error('Encryption failed: ' + err);
    }

}

function decrypt_url(url_ct) {
    /* TODO: proper URL validation! */

    try {
	var password = $('#password').val();
	var ciphertext=decodeURIComponent(url_ct);

	var url = decrypt(password, ciphertext);
  
	show_message('Your decrypted URL is <a href="' + url + '">' + url + '</a>. You will be redirected now..');

	setTimeout(
	    function() {
		window.location.href = url;
	    },
	    2000
        );
	

    }
    catch (err) {
	show_error('Decryption failed: are you sure you entered the correct password?');

    }

}


/*
 * Encrypt and Decrypt below are based on the demo code at
 * http://bitwiseshiftleft.github.com/sjcl/demo/
 */

function encrypt(password, plaintext) {


    if (plaintext === '') {
	throw "Empty plaintext"; 
    }

    if (password.length == 0) {
      throw "need a password!";
    }

  
    /* block size is 4 words (whic hare 4 bytes) = 16 bytes */
    var iv = sjcl.random.randomWords(4, 0); 
    var salt = iv;


    var params = {
	iter:ITERATIONS,
	mode:MODE,
	ts:TAG_SIZE,
	ks:KEY_SIZE,
	iv:iv,
	salt:salt
    };

    var rp = {}; /* Returned parameters */
    var ct = sjcl.encrypt(password, plaintext, params, rp).replace(/,/g,",\n");

    return ct.match(/"iv":"([^"]*)"/)[1] + SEPARATOR +
	   ct.match(/"ct":"([^"]*)"/)[1];
}

/* Decryption  */
function decrypt(password, ct) {
    if (ct.length === 0) {
	throw "Invalid ciphertext";
    }
    if (!password) {
	throw "Can't decrypt: need a password!";
    }
  
    /*
      * ct consists of two components separated by SEPARATOR.
      * The first component is an IV. The second component is the ciphertext
      * blocks + tag
      */
    var components = ct.split(SEPARATOR);
    if (components.length < 2) {
	throw "Invalid ciphertext";
    }

    if (components[0].length === 0) {
      throw "Can't decrypt: need an IV!";
    }

    var iv = sjcl.codec.base64.toBits(components[0])
    var ciphertext = sjcl.codec.base64.toBits(components[1]);
  
    var params = {
	iter:ITERATIONS,
	salt:iv,
	ks:KEY_SIZE
    };

    var rp = sjcl.misc.cachedPbkdf2(password, params);
    var key = rp.key.slice(0, KEY_SIZE / 32);
    var cipher = new sjcl.cipher.aes(key);
    var decrypted = sjcl.mode[MODE].decrypt(cipher, ciphertext, iv, "",
					    TAG_SIZE);

    /* convert to UTF-8 */
    return sjcl.codec.utf8String.fromBits(decrypted);
}
