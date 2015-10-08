// Port by Kaerus, Anders Elo 2013

/*
 * Self Decrypting Archive
 * http://jgae.de/sda.htm
 */

/*global module */

module.exports = (function() {

    var hexcase = 0; /* hex output format. 0 - lowercase; 1 - uppercase        */
    var b64pad = ""; /* base-64 pad character. "=" for strict RFC compliance   */
    var chrsz = 8; /* bits per input character. 8 - ASCII; 16 - Unicode      */

    function SDA() {
        this.wbuffer = "";
    }

    /*
     * Calculate the MD5 of an array of little-endian words, and a bit length
     */
    function core_md5(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << ((len) % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        var a = 1732584193;
        var b = -271733879;
        var c = -1732584194;
        var d = 271733878;

        for (var i = 0; i < x.length; i += 16) {
            var olda = a;
            var oldb = b;
            var oldc = c;
            var oldd = d;

            a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
            d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
            c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
            b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
            a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
            d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
            c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
            b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
            a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
            d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
            c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
            b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
            d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
            b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

            a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
            d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
            c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
            b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
            a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
            d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
            c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
            b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
            a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
            d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
            c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
            b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
            a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
            d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
            c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
            b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

            a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
            d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
            c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
            b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
            d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
            c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
            b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
            d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
            c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
            b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
            a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
            d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
            b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

            a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
            d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
            c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
            b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
            a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
            d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
            c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
            b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
            a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
            d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
            b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
            a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
            d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
            b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
        }

        /*
         * These functions implement the four basic operations the algorithm uses.
         */
        function md5_cmn(q, a, b, x, s, t) {
            return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
        }

        function md5_ff(a, b, c, d, x, s, t) {
            return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
        }

        function md5_gg(a, b, c, d, x, s, t) {
            return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
        }

        function md5_hh(a, b, c, d, x, s, t) {
            return md5_cmn(b ^ c ^ d, a, b, x, s, t);
        }

        function md5_ii(a, b, c, d, x, s, t) {
            return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
        }

        function safe_add(x, y) {
            var lsw = (x & 0xFFFF) + (y & 0xFFFF);
            var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
            return (msw << 16) | (lsw & 0xFFFF);
        }

        function bit_rol(num, cnt) {
            return (num << cnt) | (num >>> (32 - cnt));
        }

        return Array(a, b, c, d);
    }

    function str2binl(str) {
        var bin = Array();
        var mask = (1 << chrsz) - 1;
        for (var i = 0; i < str.length * chrsz; i += chrsz)
            bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (i % 32);
        return bin;
    }

    var State31, Polynom31, State33, Polynom33,
        State64H, State64L, Polynom64, Butt;

    var Polynomials31 = new Array(
        0x40c6e78f, 0x44ea7b19, 0x45da25ce, 0x470c368e, 0x4920f4c1, 0x4a2fb865,
        0x4b641875, 0x4d474412, 0x4c175700, 0x4e880047, 0x50a5894c, 0x51ae3883,
        0x531df126, 0x563e62e8, 0x586801c2, 0x5bef4706, 0x5c14c48a, 0x5d06e2a7,
        0x5f2f8a72, 0x623311d9, 0x65616f52, 0x668043b4, 0x672161c9, 0x67f0a6a8,
        0x6814750f, 0x6c4920c3, 0x6dca541b, 0x6e97e1ed, 0x70963ac8, 0x72de5f24,
        0x7411688a, 0x7502196b, 0x76202331, 0x7887a9e1, 0x790621f4, 0x7e79deae,
        0x7faca450
    );


    function pn() {
        var MSB;

        do {
            MSB = State31 & 0x80000000;
            State31 &= 0x7fffffff;

            if (State31 & 1)
                State31 = (State31 >>> 1) ^ Polynom31;
            else
                State31 >>>= 1;

            if (State33 & 0x80000000) State31 |= 0x80000000;

            if (MSB)
                State33 = (State33 << 1) ^ Polynom33;
            else
                State33 <<= 1;

            MSB = (State64H & 1);
            State64H >>>= 1;
            State64H |= State64L & 0x80000000;

            if (MSB)
                State64L = (State64L << 1) ^ Polynom64;
            else
                State64L <<= 1;
        }
        while (State64L & Butt);

        return (State31 ^ State33);
    }


    function compress8to7(str) {
        var arr = Array(),
            val, tmp, j;

        for (var i = 0; i < str.length; i += 8) {
            val = str.charCodeAt(i) << 1 & 0xfe;
            for (j = 0; j < 7 && i + j < str.length + 1; j++) {
                tmp = str.charCodeAt(i + j + 1) << (j + 2);
                val |= tmp >> 8;
                arr[arr.length] = (val & 0xff);
                val = tmp & 0xff;
            }
        }
        return arr;
    }

    function expand7to8(array) {
        var str = "",
            tmp, out, j;

        for (var i = 0; i < array.length; i += 7) {
            tmp = array[i];
            out = tmp >> 1;
            str += String.fromCharCode(out & 0x7f);
            for (j = 1; j < 8; j++) {
                out = (tmp << (7 - j)) & 0x7f;
                tmp = array[i + j];
                str += String.fromCharCode(out |= (tmp & 0xff) >> (j + 1));
            }
        }
        str = str.split("\0")[0];
        return str;
    }

    function crypt(ina) {
        var ota = Array();
        for (var i = 0; i < ina.length; i++) {
            ota[i] = ina[i] ^ pn();
        }
        return ota;
    }


    var b64_tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


    function b64_decode_tab() {
        var decode = Array();
        for (var i = 0; i < b64_tab.length; i++) {
            decode[b64_tab.charCodeAt(i)] = i;
        }
        return decode;
    }

    var decode = b64_decode_tab();

    function b64_to_array(str) {
        var arr = Array();
        var lng = str.length;
        var b1, b2, b3, b4, triplet;

        for (var i = 0; i < str.length; i += 4) {
            b1 = str.charCodeAt(i);
            b2 = (i + 1 < lng) ? str.charCodeAt(i + 1) : 0;
            b3 = (i + 2 < lng) ? str.charCodeAt(i + 2) : 0;
            b4 = (i + 3 < lng) ? str.charCodeAt(i + 3) : 0;
            triplet = ((decode[b1] << 18) & 0xffffff) | ((decode[b2] << 12) & 0x3ffff) | ((decode[b3] << 6) & 0xfff) | ((decode[b4]) & 0x3f);
            arr[arr.length] = (triplet >> 16) & 0xff;
            if (b3) arr[arr.length] = (triplet >> 8) & 0xff;
            if (b4) arr[arr.length] = triplet & 0xff;
        }
        return arr;
    }

    SDA.prototype.array_to_form = function(arr) {
        var lng = arr.length;
        var str = "";
        var b2, b3, triplet;

        for (var i = 0; i < lng; i += 3) {
            b2 = (i + 1 < lng) ? arr[i + 1] : 0;
            b3 = (i + 2 < lng) ? arr[i + 2] : 0;
            triplet = ((arr[i] << 16) & 0xffffff) | ((b2 << 8) & 0xffff) | (b3 & 0xff);
            str += b64_tab.charAt((triplet >> 18) & 0x3f);
            str += b64_tab.charAt((triplet >> 12) & 0x3f);
            if (b2) str += b64_tab.charAt((triplet >> 6) & 0x3f);
            if (b3) str += b64_tab.charAt(triplet & 0x3f);
            if (i % 48 == 45) {
                this.wbuffer += str;
                if (i < lng - 3)
                    str = "\n";
            } else {
                if (i >= lng - 3) {
                    this.wbuffer += str;
                }
            }
        }
    };

    SDA.prototype.pnInit = function(passphr) {
        var pnState = core_md5(str2binl(passphr), passphr.length * chrsz);
        State31 = pnState[0];
        if (!(State31 & 0x7fffffff)) State31++;
        State33 = pnState[1];
        if (!State33) State33++;
        State64H = pnState[2];
        State64L = pnState[3];
        if (!State64H && !State64L) State64L++;

        var Polynom = core_md5(pnState, 0x80);
        Polynom ^= core_md5(str2binl(passphr), passphr.length * chrsz >> 1);
        Polynom31 = Polynomials31[(Polynom[0] >>> 1) % Polynomials31.length];
        Polynom33 = Polynom[1] | 1;
        Polynom64 = Polynom[2] | 1;
        Butt = 1 << (Polynom[3] & 0x1f);
        Butt |= 1 << ((Polynom[3] >> 8) & 0x1f);
    };

    SDA.prototype.encrypt = function(input, passphrase) {
        this.wbuffer = "";

        this.pnInit(passphrase);
        this.array_to_form(crypt(compress8to7(input)));

        return this.wbuffer;
    };

    SDA.prototype.decrypt = function(input, passphrase) {
        var wbuffer;

        this.pnInit(passphrase);
        wbuffer = expand7to8(crypt(b64_to_array(input)));

        return wbuffer;
    };

    return SDA;
}());
