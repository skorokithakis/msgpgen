//This is a subscript
(function(pref){
	function btoa(str){return content.btoa.apply(this, arguments)}
	//Hash from "Magic Password Generator"
	function mpwgen (master, domain, length) {
		var s=domain+master;
		var C='0123456789abcdefghijklmnopqrstuvwxyz.',h=7919,i,j='';
		for (i=0;i<s.length;i++) {h=((h<<5)+h)+C.indexOf(s.charAt(i))}
		while (h!=0) {j+=C.charAt(h % 16);h=h>>>4;}
		return j.slice(0,length);
	}

	function customHash (master, domain, length) {
		var algorithm = pref.get('customAlgorithm');
		var domainFirst = pref.get('domainFirst');
		var separator = pref.get('separator');
		var suffix = pref.get('hashSuffix');
		var prefix = pref.get('hashPrefix');
		var encoding = pref.get('encoding');
		var hashValue;

		if(pref.get('useHMAC')){
			var key = domainFirst ? domain : master
			var data = domainFirst ? master : domain
			hashValue = hashLib.HMAC(key, data, algorithm, encoding)
		} else{
			var toHash = domainFirst ?
					(domain + separator + master) :
					(master + separator + domain);
			hashValue = hashLib.digest(toHash, algorithm, encoding);
		}
		return prefix+hashValue.substring(0,length-(prefix.length+suffix.length))+suffix;
	}

	function sgp(master,domain,len) {
		function checkPasswd(Passwd) {
			var lowerStart=Passwd.search(/[a-z]/)===0;
			var hasDigits=Passwd.search(/[0-9]/)>0;
			var hasUpper=Passwd.search(/[A-Z]/)>0;
			return lowerStart&&hasDigits&&hasUpper;
		}
		var str=master+":"+domain;
		undefined==len ? len=10 : len;
		var i=0;
		while(i<10||!(checkPasswd(str.substring(0,len)))) {
			str=hashLib.digest(str, "md5", "b64").replace(/\//g,'8').replace(/\+/g,'9').replace("==","")+"AA";
			i++;
			if(i>1000){throw "Too many iterations"}
		}
		return str.substring(0,len);
	}

	function hpg(master,domain,len) {
		function checkPasswd(Passwd) {
			var lowerStart=Passwd.search(/[a-z]/)===0;
			var hasDigits=Passwd.search(/[0-9]/)>0;
			var hasUpper=Passwd.search(/[A-Z]/)>0;
			var noSymbols=Passwd.search(/[/+]/)==-1
			return lowerStart&&hasDigits&&hasUpper&&noSymbols;
		}
		undefined==len ? len=10 : len;
		var i=0;
		while (i<10 || !(checkPasswd (str.substring (0,len)))) {
			var newMaster = hashLib.HMAC(master, domain, "sha256", "hex");
			var newDomain = hashLib.HMAC(domain, master, "sha256", "hex");
			var str = hashLib.HMAC(domain + newMaster, master + newDomain, "sha1", "b64");
			domain = newDomain;
			master = newMaster;
			i++;
			if(i>1000){throw "Too many iterations"}
		}
		return str.substring (0, len);
	}

	var hashLib=(function(){
	/*
	* Configurable variables. You may need to tweak these to be compatible with
	* the server-side, but the defaults work in most cases.
	*/
	var hexcase=0;   /* hex output format. 0 - lowercase; 1 - uppercase        */
	var b64pad="";  /* base-64 pad character. "=" for strict RFC compliance   */

	function digest(string, algorithm, outputFormat) {
		var rawHash=rawDigest(hashes[algorithm.toLowerCase()], string);
		switch (outputFormat) {
			case "b64":	return rstr2b64(rawHash); break;
			case "hex":	return rstr2hex(rawHash); break;
			case "raw":	return rawHash; break;
			default:	return rstr2any(rawHash, outputFormat);
		}
	};

	function HMAC(key, data, algorithm, outputFormat) {
		algorithm=algorithm.toLowerCase();
		var hashLengths={sha1:160, sha256:256, sha224:224, md2:128,
				ripemd:160, md5:128, sha512:512, sha384:384};
		var blocksizes={sha512:1024,sha384:1024};	/*The algorithm defaults to a blocksize of 512 bits*/
		var rawHash=rawHMAC(hashes[algorithm], hashLengths[algorithm],
				key, data, blocksizes[algorithm]);
		switch (outputFormat.toLowerCase()) {
			case "b64":	return rstr2b64(rawHash); break;
			case "hex":	return rstr2hex(rawHash); break;
			case "raw":	return rawHash; break;
			default:	return rstr2any(rawHash,outputFormat);
		}
	};

	function rawDigest(hashFunction, s) {
		s=str2rstr_utf8(s);
		return binb2rstr(hashFunction(rstr2binb(s), s.length * 8));
	};

	function rawHMAC(hashFunction, hashLength, k, d, blockSize) {
		blockSize=blockSize?blockSize:512;
		var key=str2rstr_utf8(k);
		var data=str2rstr_utf8(d);
		var bkey = rstr2binb(key);
		if(bkey.length > blockSize>>5) bkey = hashFunction(bkey, key.length * 8);
		var ipad = Array(blockSize>>5), opad = Array(blockSize>>5);
		for(var i = 0; i < blockSize>>5; i++) {
			ipad[i] = bkey[i] ^ 0x36363636;
			opad[i] = bkey[i] ^ 0x5C5C5C5C;
		}
		var hash = hashFunction(ipad.concat(rstr2binb(data)), blockSize + data.length * 8);
		return binb2rstr(hashFunction(opad.concat(hash), blockSize + hashLength));
	};

	/* Convert a raw string to a hex string	*/
	function rstr2hex(input) {
		var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
		var output = "";
		var x;
		for(var i = 0; i < input.length; i++)
		{
			x = input.charCodeAt(i);
			output += hex_tab.charAt((x >>> 4) & 0x0F)
					+ hex_tab.charAt( x        & 0x0F);
		}
		return output;
	};

	/* Convert a raw string to a hex string	*/
	function rstr2hex2(str) {
		/*return the two-digit hexadecimal code for a byte*/
		function byteToHex(charCode) {
			return ("0" + charCode.toString(16)).slice(-2);
		}
		hex="";
		for(var i=0;i<str.length;i++) {
			hex+=byteToHex(str.charCodeAt(i))
		}
		if(hexcase==1) {
			hex=hex.toUpperCase();
		}
		return hex;
	};

	/* Convert a raw string to a base-64 string */
	function rstr2b64(input) {
		try{
			return btoa(input).replace(/=/g,b64pad?b64pad:"");
		} catch(e) {
		return rstr2b64_safe(input);
		}
	};

	/* Convert a raw string to a base-64 string without using the btoa function*/
	function rstr2b64_safe(input) {
		if (!("b64pad" in this)){ b64pad=""; }
		var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		var output = "";
		var len = input.length;
		for(var i = 0; i < len; i += 3) {
			var triplet = (input.charCodeAt(i) << 16)
						| (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
						| (i + 2 < len ? input.charCodeAt(i+2)      : 0);
			for(var j = 0; j < 4; j++)
			{
			if(i * 8 + j * 6 > input.length * 8) output += b64pad;
			else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
			}
		}
		return output;
	};

	/*Convert a raw string into an arbitary string encoding*/
	function rstr2any(input, charset) {
		var divisor = charset.length;
		var remainders = Array();
		var i, q, x, quotients;

		var dividends = Array(Math.ceil(input.length / 2));
		for(i = 0; i < dividends.length; i++) {
			dividends[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
		}
		while(dividends.length > 0) {
			quotients = Array();
			x = 0;
			for(i = 0; i < dividends.length; i++) {
				x = (x << 16) + dividends[i];
				q = Math.floor(x / divisor);
				x -= q * divisor;
				if(quotients.length > 0 || q > 0) {
					quotients[quotients.length] = q;
				}
			}
			remainders[remainders.length] = x;
			dividends = quotients;
		}
		var output = "";
		for(i = remainders.length - 1; i >= 0; i--) {
			output += charset.charAt(remainders[i]);
		}
		var full_length = Math.ceil(input.length * 8 /
		(Math.log(charset.length) / Math.log(2)));
		for(i = output.length; i < full_length; i++) {
			output = charset[0] + output;
		}
		return output;
	};

	/* Encode a string as utf-8.
	* For efficiency, this assumes the input is valid utf-16. */
	function str2rstr_utf8(input) {
		var output = "";
		var i = -1;
		var x, y;

		while(++i < input.length) {
			/* Decode utf-16 surrogate pairs */
			x = input.charCodeAt(i);
			y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
			if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
				x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
				i++;
			}

			/* Encode output as utf-8 */
			if(x <= 0x7F)
				output += String.fromCharCode(x);
			else if(x <= 0x7FF)
				output += String.fromCharCode(	0xC0 | ((x >>> 6 ) & 0x1F),
												0x80 | ( x         & 0x3F));
			else if(x <= 0xFFFF)
				output += String.fromCharCode(	0xE0 | ((x >>> 12) & 0x0F),
												0x80 | ((x >>> 6 ) & 0x3F),
												0x80 | ( x         & 0x3F));
			else if(x <= 0x1FFFFF)
				output += String.fromCharCode(	0xF0 | ((x >>> 18) & 0x07),
												0x80 | ((x >>> 12) & 0x3F),
												0x80 | ((x >>> 6 ) & 0x3F),
												0x80 | ( x         & 0x3F));
		}
		return output;
	};

	/*
	* Convert a raw string to an array of big-endian words
	* Characters >255 have their high-byte silently ignored.
	*/
	function rstr2binb(input) {
		var output = Array(input.length >> 2);
		for(var i = 0; i < output.length; i++) {
			output[i] = 0;
		}
		for(var i = 0; i < input.length * 8; i += 8) {
			output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i & 31);
		}
		return output;
	};

	/*
	* Convert an array of big-endian words to a string
	*/
	function binb2rstr(input) {
		var output = "";
		for(var i = 0; i < input.length * 32; i += 8) {
			output += String.fromCharCode((input[i>>5] >>> (24 - i & 31)) & 0xFF);
		}
		return output;
	};

	/* Add integers, wrapping at 2^32. */
	function add(x, y) {
		x ? 0 : x=0;
		y ? 0 : y=0;
		return (x+y)|0;
	};

	/* Bitwise rotate a 32-bit number to the left. */
	function bit_rol(num, cnt) {
		return (num << cnt) | (num >>> (32 - cnt));
	};
	var hashes={}

hashes.sha1=function(x, len) {
	/* Perform the appropriate triplet combination function for the current iteration */
	function ft(t, b, c, d) {
		if(t < 20) return (b & c) | ((~b) & d);
		if(t < 40) return b ^ c ^ d;
		if(t < 60) return (b & c) | (b & d) | (c & d);
		return b ^ c ^ d;
	};

	/* Determine the appropriate additivebit_rol constant for the current iteration	*/
	function kt(t) {
		return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
		(t < 60) ? -1894007588 : -899497514;
	}
	/* append padding */
	x[len >> 5] |= 0x80 << (24 - len & 31);
	x[((len + 64 >> 9) << 4) + 15] = len;

	var w = Array(80);
	var a =  1732584193;
	var b = -271733879;
	var c = -1732584194;
	var d =  271733878;
	var e = -1009589776;

	for(var i = 0; i < x.length; i += 16){
		var olda = a;
		var oldb = b;
		var oldc = c;
		var oldd = d;
		var olde = e;

		for(var j = 0; j < 80; j++) {
			if(j < 16) w[j] = x[i + j];
			else w[j] = bit_rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
			var t = add(add(bit_rol(a, 5), ft(j, b, c, d)),
				add(add(e, w[j]), kt(j)));
			e = d;
			d = c;
			c = bit_rol(b, 30);
			b = a;
			a = t;
		}

		a = add(a, olda);
		b = add(b, oldb);
		c = add(c, oldc);
		d = add(d, oldd);
		e = add(e, olde);
	}
	return [a, b, c, d, e];
}

hashes.sha224=function(m, l){
	var K=[	1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993,
			-1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
			1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
			264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
			-1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
			113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
			1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885,
			-1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
			430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
			1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872,
			-1866530822, -1538233109, -1090935817, -965641998
	]

	function S(X, n) {return ( X >>> n ) | (X << (32 - n));}
	function R(X, n) {return ( X >>> n );}
	function Ch(x, y, z) {return ((x & y) ^ ((~x) & z));}
	function Maj(x, y, z) {return ((x & y) ^ (x & z) ^ (y & z));}
	function Sigma0256(x) {return (S(x, 2) ^ S(x, 13) ^ S(x, 22));}
	function Sigma1256(x) {return (S(x, 6) ^ S(x, 11) ^ S(x, 25));}
	function Gamma0256(x) {return (S(x, 7) ^ S(x, 18) ^ R(x, 3));}
	function Gamma1256(x) {return (S(x, 17) ^ S(x, 19) ^ R(x, 10));}
	function Sigma0512(x) {return (S(x, 28) ^ S(x, 34) ^ S(x, 39));}
	function Sigma1512(x) {return (S(x, 14) ^ S(x, 18) ^ S(x, 41));}
	function Gamma0512(x) {return (S(x, 1)  ^ S(x, 8) ^ R(x, 7));}
	function Gamma1512(x) {return (S(x, 19) ^ S(x, 61) ^ R(x, 6));}

	var HASH = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
				0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	var W = new Array(64);
	var a, b, c, d, e, f, g, h;
	var i, j, T1, T2;

	/* append padding */
	m[l >> 5] |= 0x80 << (24 - l & 31);
	m[((l + 64 >> 9) << 4) + 15] = l;

	for(i = 0; i < m.length; i += 16)
	{
		a = HASH[0];
		b = HASH[1];
		c = HASH[2];
		d = HASH[3];
		e = HASH[4];
		f = HASH[5];
		g = HASH[6];
		h = HASH[7];

		for(j = 0; j < 64; j++)
		{
			if (j < 16) W[j] = m[j + i];
			else W[j] = add(add(add(Gamma1256(W[j - 2]), W[j - 7]),
				Gamma0256(W[j - 15])), W[j - 16]);

			T1 = add(add(add(add(h, Sigma1256(e)), Ch(e, f, g)),
											K[j]), W[j]);
			T2 = add(Sigma0256(a), Maj(a, b, c));
			h = g;
			g = f;
			f = e;
			e = add(d, T1);
			d = c;
			c = b;
			b = a;
			a = add(T1, T2);
		}

		HASH[0] = add(a, HASH[0]);
		HASH[1] = add(b, HASH[1]);
		HASH[2] = add(c, HASH[2]);
		HASH[3] = add(d, HASH[3]);
		HASH[4] = add(e, HASH[4]);
		HASH[5] = add(f, HASH[5]);
		HASH[6] = add(g, HASH[6]);
		HASH[7] = add(h, HASH[7]);
	}
	return HASH.splice(0,7);
};

hashes.sha256=function(m, l){
	var K=[	1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993,
				-1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
				1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
				264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
				-1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
				113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
				1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885,
				-1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
				430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
				1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872,
				-1866530822, -1538233109, -1090935817, -965641998
	]

	function S(X, n) {return ( X >>> n ) | (X << (32 - n));}
	function R(X, n) {return ( X >>> n );}
	function Ch(x, y, z) {return ((x & y) ^ ((~x) & z));}
	function Maj(x, y, z) {return ((x & y) ^ (x & z) ^ (y & z));}
	function Sigma0256(x) {return (S(x, 2) ^ S(x, 13) ^ S(x, 22));}
	function Sigma1256(x) {return (S(x, 6) ^ S(x, 11) ^ S(x, 25));}
	function Gamma0256(x) {return (S(x, 7) ^ S(x, 18) ^ R(x, 3));}
	function Gamma1256(x) {return (S(x, 17) ^ S(x, 19) ^ R(x, 10));}
	function Sigma0512(x) {return (S(x, 28) ^ S(x, 34) ^ S(x, 39));}
	function Sigma1512(x) {return (S(x, 14) ^ S(x, 18) ^ S(x, 41));}
	function Gamma0512(x) {return (S(x, 1)  ^ S(x, 8) ^ R(x, 7));}
	function Gamma1512(x) {return (S(x, 19) ^ S(x, 61) ^ R(x, 6));}

	var HASH = [1779033703, -1150833019, 1013904242, -1521486534,
				1359893119, -1694144372, 528734635, 1541459225];
	var W = new Array(64);
	var a, b, c, d, e, f, g, h;
	var i, j, T1, T2;

	/* append padding */
	m[l >> 5] |= 0x80 << (24 - l & 31);
	m[((l + 64 >> 9) << 4) + 15] = l;

	for(i = 0; i < m.length; i += 16)
	{
		a = HASH[0];
		b = HASH[1];
		c = HASH[2];
		d = HASH[3];
		e = HASH[4];
		f = HASH[5];
		g = HASH[6];
		h = HASH[7];

		for(j = 0; j < 64; j++)
		{
			if (j < 16) W[j] = m[j + i];
			else W[j] = add(add(add(Gamma1256(W[j - 2]), W[j - 7]),
				Gamma0256(W[j - 15])), W[j - 16]);

			T1 = add(add(add(add(h, Sigma1256(e)), Ch(e, f, g)),
											K[j]), W[j]);
			T2 = add(Sigma0256(a), Maj(a, b, c));
			h = g;
			g = f;
			f = e;
			e = add(d, T1);
			d = c;
			c = b;
			b = a;
			a = add(T1, T2);
		}

		HASH[0] = add(a, HASH[0]);
		HASH[1] = add(b, HASH[1]);
		HASH[2] = add(c, HASH[2]);
		HASH[3] = add(d, HASH[3]);
		HASH[4] = add(e, HASH[4]);
		HASH[5] = add(f, HASH[5]);
		HASH[6] = add(g, HASH[6]);
		HASH[7] = add(h, HASH[7]);
	}
	return HASH;
};

hashes.md5=function(x, len) {

	/* Make the function use big-endian */
	function binl2binb(l){
		var b=[];
		for(var i=0,num;num=l[i];i++){
			b.push(((num&0xff)<<24)+((num&0xff00)<<8)+((num&0xff0000)>>>8)+((num>>>24)&0xff));
		}
		return b;
	}

	/* These functions implement the four basic operations the algorithm uses. */
	function cmn(q, a, b, x, s, t)
	{return add(bit_rol(add(add(a, q), add(x, t)), s),b);}

	function ff(a, b, c, d, x, s, t)
	{return cmn((b & c) | ((~b) & d), a, b, x, s, t); }

	function gg(a, b, c, d, x, s, t)
	{return cmn((b & d) | (c & (~d)), a, b, x, s, t); }

	function hh(a, b, c, d, x, s, t)
	{return cmn(b ^ c ^ d, a, b, x, s, t);	}

	function ii(a, b, c, d, x, s, t)
	{return cmn(c ^ (b | (~d)), a, b, x, s, t); }

	/* convert endianess */
	x=binl2binb(x);

	/* append padding */
	x[len >> 5] |= 0x80 << ((len) & 31);
	x[(((len + 64) >>> 9) << 4) + 14] = len;

	var a =  1732584193;
	var b = -271733879;
	var c = -1732584194;
	var d =  271733878;

	for(var i = 0; i < x.length; i += 16)
	{
		var olda = a;
		var oldb = b;
		var oldc = c;
		var oldd = d;
		a = ff(a, b, c, d, x[i+ 0], 7 , -680876936);
		d = ff(d, a, b, c, x[i+ 1], 12, -389564586);
		c = ff(c, d, a, b, x[i+ 2], 17,  606105819);
		b = ff(b, c, d, a, x[i+ 3], 22, -1044525330);
		a = ff(a, b, c, d, x[i+ 4], 7 , -176418897);
		d = ff(d, a, b, c, x[i+ 5], 12,  1200080426);
		c = ff(c, d, a, b, x[i+ 6], 17, -1473231341);
		b = ff(b, c, d, a, x[i+ 7], 22, -45705983);
		a = ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
		d = ff(d, a, b, c, x[i+ 9], 12, -1958414417);
		c = ff(c, d, a, b, x[i+10], 17, -42063);
		b = ff(b, c, d, a, x[i+11], 22, -1990404162);
		a = ff(a, b, c, d, x[i+12], 7 ,  1804603682);
		d = ff(d, a, b, c, x[i+13], 12, -40341101);
		c = ff(c, d, a, b, x[i+14], 17, -1502002290);
		b = ff(b, c, d, a, x[i+15], 22,  1236535329);

		a = gg(a, b, c, d, x[i+ 1], 5 , -165796510);
		d = gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
		c = gg(c, d, a, b, x[i+11], 14,  643717713);
		b = gg(b, c, d, a, x[i+ 0], 20, -373897302);
		a = gg(a, b, c, d, x[i+ 5], 5 , -701558691);
		d = gg(d, a, b, c, x[i+10], 9 ,  38016083);
		c = gg(c, d, a, b, x[i+15], 14, -660478335);
		b = gg(b, c, d, a, x[i+ 4], 20, -405537848);
		a = gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
		d = gg(d, a, b, c, x[i+14], 9 , -1019803690);
		c = gg(c, d, a, b, x[i+ 3], 14, -187363961);
		b = gg(b, c, d, a, x[i+ 8], 20,  1163531501);
		a = gg(a, b, c, d, x[i+13], 5 , -1444681467);
		d = gg(d, a, b, c, x[i+ 2], 9 , -51403784);
		c = gg(c, d, a, b, x[i+ 7], 14,  1735328473);
		b = gg(b, c, d, a, x[i+12], 20, -1926607734);

		a = hh(a, b, c, d, x[i+ 5], 4 , -378558);
		d = hh(d, a, b, c, x[i+ 8], 11, -2022574463);
		c = hh(c, d, a, b, x[i+11], 16,  1839030562);
		b = hh(b, c, d, a, x[i+14], 23, -35309556);
		a = hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
		d = hh(d, a, b, c, x[i+ 4], 11,  1272893353);
		c = hh(c, d, a, b, x[i+ 7], 16, -155497632);
		b = hh(b, c, d, a, x[i+10], 23, -1094730640);
		a = hh(a, b, c, d, x[i+13], 4 ,  681279174);
		d = hh(d, a, b, c, x[i+ 0], 11, -358537222);
		c = hh(c, d, a, b, x[i+ 3], 16, -722521979);
		b = hh(b, c, d, a, x[i+ 6], 23,  76029189);
		a = hh(a, b, c, d, x[i+ 9], 4 , -640364487);
		d = hh(d, a, b, c, x[i+12], 11, -421815835);
		c = hh(c, d, a, b, x[i+15], 16,  530742520);
		b = hh(b, c, d, a, x[i+ 2], 23, -995338651);

		a = ii(a, b, c, d, x[i+ 0], 6 , -198630844);
		d = ii(d, a, b, c, x[i+ 7], 10,  1126891415);
		c = ii(c, d, a, b, x[i+14], 15, -1416354905);
		b = ii(b, c, d, a, x[i+ 5], 21, -57434055);
		a = ii(a, b, c, d, x[i+12], 6 ,  1700485571);
		d = ii(d, a, b, c, x[i+ 3], 10, -1894986606);
		c = ii(c, d, a, b, x[i+10], 15, -1051523);
		b = ii(b, c, d, a, x[i+ 1], 21, -2054922799);
		a = ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
		d = ii(d, a, b, c, x[i+15], 10, -30611744);
		c = ii(c, d, a, b, x[i+ 6], 15, -1560198380);
		b = ii(b, c, d, a, x[i+13], 21,  1309151649);
		a = ii(a, b, c, d, x[i+ 4], 6 , -145523070);
		d = ii(d, a, b, c, x[i+11], 10, -1120210379);
		c = ii(c, d, a, b, x[i+ 2], 15,  718787259);
		b = ii(b, c, d, a, x[i+ 9], 21, -343485551);

		a = add(a, olda);
		b = add(b, oldb);
		c = add(c, oldc);
		d = add(d, oldd);
	}
	/* convert endianess */
	return binl2binb([a, b, c, d]);;
};

hashes.sha512=function(x, len) {

	/*Copies src into dst, assuming both are 64-bit numbers*/
	function int64copy(dst, src) {
		dst.h = src.h;
		dst.l = src.l;
	}

	/*Right-rotates a 64-bit number by shift
	 *Won't handle cases of shift>=32
	 *The function revrrot() is for that */
	function int64rrot(dst, x, shift) {
		dst.l = (x.l >>> shift) | (x.h << (32-shift));
		dst.h = (x.h >>> shift) | (x.l << (32-shift));
	}

	/*Reverses the dwords of the source and then rotates right by shift.
	 *This is equivalent to rotation by 32+shift*/
	function int64revrrot(dst, x, shift) {
		dst.l = (x.h >>> shift) | (x.l << (32-shift));
		dst.h = (x.l >>> shift) | (x.h << (32-shift));
	}

	/*Bitwise-shifts right a 64-bit number by shift
	 *Won't handle shift>=32, but it's never needed in SHA512*/
	function int64shr(dst, x, shift) {
		dst.l = (x.l >>> shift) | (x.h << (32-shift));
		dst.h = (x.h >>> shift);
	}

	/*Adds two 64-bit numbers
	 *Like the original implementation, does not rely on 32-bit operations*/
	function int64add(dst, x, y) {
		var w0 = (x.l & 0xffff) + (y.l & 0xffff);
		var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
		var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
		var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
		dst.l = (w0 & 0xffff) | (w1 << 16);
		dst.h = (w2 & 0xffff) | (w3 << 16);
	}

	/*Same, except with 4 addends. Works faster than adding them one by one.*/
	function int64add4(dst, a, b, c, d) {
		var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
		var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
		var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
		var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
		dst.l = (w0 & 0xffff) | (w1 << 16);
		dst.h = (w2 & 0xffff) | (w3 << 16);
	}

	/*Same, except with 5 addends*/
	function int64add5(dst, a, b, c, d, e) {
		var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff);
		var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16);
		var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16);
		var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
		dst.l = (w0 & 0xffff) | (w1 << 16);
		dst.h = (w2 & 0xffff) | (w3 << 16);
	}

	/*A constructor for 64-bit numbers*/
	function int64(h, l) {
		this.h = h;
		this.l = l;
	}

	k=[
	new int64(0x428a2f98, -685199838), new int64(0x71374491, 0x23ef65cd),
	new int64(-1245643825, -330482897), new int64(-373957723, -2121671748),
	new int64(0x3956c25b, -213338824), new int64(0x59f111f1, -1241133031),
	new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736),
	new int64(-670586216, -1560083902), new int64(0x12835b01, 0x45706fbe),
	new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, -704662302),
	new int64(0x72be5d74, -226784913), new int64(-2132889090, 0x3b1696b1),
	new int64(-1680079193, 0x25c71235), new int64(-1046744716, -815192428),
	new int64(-459576895, -1628353838), new int64(-272742522, 0x384f25e3),
	new int64(0xfc19dc6, -1953704523), new int64(0x240ca1cc, 0x77ac9c65),
	new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
	new int64(0x5cb0a9dc, -1119749164), new int64(0x76f988da, -2096016459),
	new int64(-1740746414, -295247957), new int64(-1473132947, 0x2db43210),
	new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340),
	new int64(-958395405, 0x3da88fc2), new int64(-710438585, -1828018395),
	new int64(0x6ca6351, -536640913), new int64(0x14292967, 0xa0e6e70),
	new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
	new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, -1651133473),
	new int64(0x650a7354, -1951439906), new int64(0x766a0abb, 0x3c77b2a8),
	new int64(-2117940946, 0x47edaee6), new int64(-1838011259, 0x1482353b),
	new int64(-1564481375, 0x4cf10364), new int64(-1474664885, -1136513023),
	new int64(-1035236496, -789014639), new int64(-949202525, 0x654be30),
	new int64(-778901479, -688958952), new int64(-694614492, 0x5565a910),
	new int64(-200395387, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
	new int64(0x19a4c116, -1194143544), new int64(0x1e376c08, 0x5141ab53),
	new int64(0x2748774c, -544281703), new int64(0x34b0bcb5, -509917016),
	new int64(0x391c0cb3, -976659869), new int64(0x4ed8aa4a, -482243893),
	new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, -692930397),
	new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
	new int64(-2067236844, -1578062990), new int64(-1933114872, 0x1a6439ec),
	new int64(-1866530822, 0x23631e28), new int64(-1538233109, -561857047),
	new int64(-1090935817, -1295615723), new int64(-965641998, -479046869),
	new int64(-903397682, -366583396), new int64(-779700025, 0x21c0c207),
	new int64(-354779690, -840897762), new int64(-176337025, -294727304),
	new int64(0x6f067aa, 0x72176fba), new int64(0xa637dc5, -1563912026),
	new int64(0x113f9804, -1090974290), new int64(0x1b710b35, 0x131c471b),
	new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
	new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, -1676669620),
	new int64(0x4cc5d4be, -885112138), new int64(0x597f299c, -60457430),
	new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817)
	];
	/*Initial hash values*/
	var H = [
	new int64(0x6a09e667, -205731576),
	new int64(-1150833019, -2067093701),
	new int64(0x3c6ef372, -23791573),
	new int64(-1521486534, 0x5f1d36f1),
	new int64(0x510e527f, -1377402159),
	new int64(-1694144372, 0x2b3e6c1f),
	new int64(0x1f83d9ab, -79577749),
	new int64(0x5be0cd19, 0x137e2179)];

	var T1 = new int64(0, 0),
	T2 = new int64(0, 0),
	a = new int64(0,0),
	b = new int64(0,0),
	c = new int64(0,0),
	d = new int64(0,0),
	e = new int64(0,0),
	f = new int64(0,0),
	g = new int64(0,0),
	h = new int64(0,0),
	/*Temporary variables not specified by the document*/
	s0 = new int64(0, 0),
	s1 = new int64(0, 0),
	Ch = new int64(0, 0),
	Maj = new int64(0, 0),
	r1 = new int64(0, 0),
	r2 = new int64(0, 0),
	r3 = new int64(0, 0);
	var j, i;
	var W = new Array(80);
	for(i=0; i<80; i++)
		W[i] = new int64(0, 0);

	/* append padding to the source string. The format is described in the FIPS.*/
	x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
	x[((len + 128 >> 10)<< 5) + 31] = len;

	for(i = 0; i<x.length; i+=32) {
		int64copy(a, H[0]);
		int64copy(b, H[1]);
		int64copy(c, H[2]);
		int64copy(d, H[3]);
		int64copy(e, H[4]);
		int64copy(f, H[5]);
		int64copy(g, H[6]);
		int64copy(h, H[7]);

		for(j=0; j<16; j++) {
			W[j].h = x[i + 2*j];
			W[j].l = x[i + 2*j + 1];
		}

		for(j=16; j<80; j++) {
			/*sigma1*/
			int64rrot(r1, W[j-2], 19);
			int64revrrot(r2, W[j-2], 29);
			int64shr(r3, W[j-2], 6);
			s1.l = r1.l ^ r2.l ^ r3.l;
			s1.h = r1.h ^ r2.h ^ r3.h;
			/*sigma0*/
			int64rrot(r1, W[j-15], 1);
			int64rrot(r2, W[j-15], 8);
			int64shr(r3, W[j-15], 7);
			s0.l = r1.l ^ r2.l ^ r3.l;
			s0.h = r1.h ^ r2.h ^ r3.h;

			int64add4(W[j], s1, W[j-7], s0, W[j-16]);
		}

		for(j = 0; j < 80; j++) {
			/*Ch*/
			Ch.l = (e.l & f.l) ^ (~e.l & g.l);
			Ch.h = (e.h & f.h) ^ (~e.h & g.h);

			/*Sigma1*/
			int64rrot(r1, e, 14);
			int64rrot(r2, e, 18);
			int64revrrot(r3, e, 9);
			s1.l = r1.l ^ r2.l ^ r3.l;
			s1.h = r1.h ^ r2.h ^ r3.h;

			/*Sigma0*/
			int64rrot(r1, a, 28);
			int64revrrot(r2, a, 2);
			int64revrrot(r3, a, 7);
			s0.l = r1.l ^ r2.l ^ r3.l;
			s0.h = r1.h ^ r2.h ^ r3.h;

			/*Maj*/
			Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
			Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

			int64add5(T1, h, s1, Ch, k[j], W[j]);
			int64add(T2, s0, Maj);

			int64copy(h, g);
			int64copy(g, f);
			int64copy(f, e);
			int64add(e, d, T1);
			int64copy(d, c);
			int64copy(c, b);
			int64copy(b, a);
			int64add(a, T1, T2);
		}
		int64add(H[0], H[0], a);
		int64add(H[1], H[1], b);
		int64add(H[2], H[2], c);
		int64add(H[3], H[3], d);
		int64add(H[4], H[4], e);
		int64add(H[5], H[5], f);
		int64add(H[6], H[6], g);
		int64add(H[7], H[7], h);
	}

	/*represent the hash as an array of 32-bit dwords*/
	var hash = new Array(16);
	for(i=0; i<8; i++)
	{
		hash[2*i] = H[i].h;
		hash[2*i + 1] = H[i].l;
	}
	return hash;
}

		return {digest:digest, HMAC:HMAC}
	})()

	//Begin PwdHash
	/*
	Copyright 2005 Collin Jackson

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
	* Neither the name of Stanford University nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	*/

	function pwdHash(password, realm, length) {
		const PasswordPrefix="@@"
		const len=2 	//Length of password prefix

		/**
		* Fiddle with the password a bit after hashing it so that it will get through
		* most website filters. We require one upper and lower case, one digit, and
		* we look at the user's password to determine if there should be at least one
		* symbol or not.
		*/

		function applyConstraints (hash, size, nonalphanumeric) {
			var startingSize = size - 4;  // Leave room for some extra characters
			var result = hash.substring(0, startingSize);
			var extras = hash.substring(startingSize).split('');

			// Some utility functions to keep things tidy
			function nextExtra() { return extras.length ? extras.shift().charCodeAt(0) : 0; }
			function nextExtraChar() { return String.fromCharCode(nextExtra()); }
			function rotate(arr, amount) { while(amount--) arr.push(arr.shift()) }
			function between(min, interval, offset) { return min + offset % interval; }
			function nextBetween(base, interval) {
				return String.fromCharCode(between(base.charCodeAt(0), interval, nextExtra()));
			}
			function contains(regex) { return result.match(regex); }

			// Add the extra characters
			result += (contains(/[A-Z]/) ? nextExtraChar() : nextBetween('A', 26));
			result += (contains(/[a-z]/) ? nextExtraChar() : nextBetween('a', 26));
			result += (contains(/[0-9]/) ? nextExtraChar() : nextBetween('0', 10));
			result += (contains(/\W/) && nonalphanumeric ? nextExtraChar() : '+');
			while (contains(/\W/) && !nonalphanumeric) {
				result = result.replace(/\W/, nextBetween('A', 26));
			}

			// Rotate the result to make it harder to guess the inserted locations
			result = result.split('');
			rotate(result, nextExtra());
			return result.join('');
		}

		password.substring(0,len) == PasswordPrefix ? password = password.substring(len) : false
		var hash = hashLib.HMAC (password, realm, "md5", "b64");
		var size = password.length + len;
		var nonalphanumeric = password.match(/\W/) != null;
		var result = applyConstraints(hash, size, nonalphanumeric);
		return result;
	}
	//End PwdHash

	function safeEval(code,master,domain,length,fullLocation) {
		var s = Components.utils.Sandbox("http://invalid./");
		s.master=master;
		s.domain=domain;
		s.length=length;
		//Map fullLocation to a normal object to prevent permission denial
		var fullLocation2={};
		for (i in fullLocation){
			//We don't want the location methods mapped, only the properties
			if (typeof(fullLocation[i])=="function"){continue}
			fullLocation2[i]=fullLocation[i];
		}
		fullLocation2.toString=function(){return this.href};
		s.fullLocation=fullLocation2;
		s.importFunction(hashLib.digest,"digest");
		s.importFunction(hashLib.HMAC,"HMAC");
		s.importFunction(pref.getAny,"getPref");
		return Components.utils.evalInSandbox(code, s, "1.8", "hashPasswordGenerator://customFunction.js",1);
	}

	function customAlgorithm(master,domain,length,fullLocation) {
		try{
			var code=pref.get('algorithmFunction')
			return safeEval(code,master,domain,length,fullLocation);
		} catch(e){
			//Components.utils.dumpError(e);
			return "";
		}
	}
	return {
		mpwgen:mpwgen,
		hpg:hpg,
		sgp:sgp,
		pwdHash:pwdHash,
		custom:customHash,
		customAlgorithm:customAlgorithm,
		safeEval:safeEval,
		hashLib:hashLib
	}
})
