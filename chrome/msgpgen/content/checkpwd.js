var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].
		getService(Components.interfaces.mozIJSSubScriptLoader);var hashLib=loader.loadSubScript("chrome://msgpgen/content/hashes.js")(pref).hashLib

var pref=loader.loadSubScript("chrome://msgpgen/content/pref.js");
var hashLib=loader.loadSubScript("chrome://msgpgen/content/hashes.js")(pref).hashLib
var colorHash=loader.loadSubScript("chrome://msgpgen/content/colorhash.js")(pref, hashLib);

function dgEBI(id){
	return document.getElementById(id)
}

function checkPwd (textbox){
	return colorHash.colorize(textbox);
}

function promptLoad (event) {
	dgEBI('remember').checked=window.arguments[0].remember;
	dgEBI('master-pw').focus();
}

function promptAccept (event) {
	window.arguments[0].masterPw=dgEBI('master-pw').value;
	window.arguments[0].remember=dgEBI('remember').checked;
	return true;
}
