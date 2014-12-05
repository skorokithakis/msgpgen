try{
(function () {
var masterPw = null;
var pwLength = 0;
var pwAlgorithm;
//Load supplimentary files.
var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].
			 getService(Components.interfaces.mozIJSSubScriptLoader);
var pref=loader.loadSubScript('chrome://msgpgen/content/pref.js');
var errorLog=loader.loadSubScript('chrome://msgpgen/content/errorLog.js');
var hashes=loader.loadSubScript('chrome://msgpgen/content/hashes.js')(pref);
var getFieldTypes=loader.loadSubScript('chrome://msgpgen/content/getFieldTypes.js');

var dumpErr=errorLog.dumpErr;
var dumpMsg=errorLog.dumpMsg;

//Begin function declarations
function dgEBI(id,doc){
	if(!doc){doc=content.document;}
	return doc.getElementById(id);
}
function onMessage(m){
	dumpMsg("Message recieved")
	if(m.name=="msgpgen-manual"){
		var master = m.json.master;
		var algorithm = m.json.algorithm;
		var length = m.json.length;
		fillDocument(master, content.document, true, length, algorithm);
		for (var i=0; i<win.frames.length; i++) {
			fillDocument(master, content.frames[i].document, true, length, algorithm);
		}
	}
	if(m.name=="msgpgen-pw-update"){
		dumpMsg("password update received")
		pwAlgorithm = m.json.algorithm;
		pwLength = m.json.length;
		masterPw = m.json.master;
		dumpMsg("Master is now: "+masterPw);
	}
	
}
addMessageListener("msgpgen-manual", onMessage);
addMessageListener("msgpgen-pw-update", onMessage);

function autoRun(event){
	dumpMsg("Trying to fill document: master: "+masterPw)
	if(masterPw&&pref.get('fillOnLoad')){
		fillDocument(masterPw,event.target,false)
	}
}


function makePass (master,domain,fullLocation,length,algorithm) {
	length=length?length:pref.get('passwordLength');
	algorithm=algorithm?algorithm:pref.get('algorithm');
	return hashes[algorithm](master,domain,length,fullLocation)
}

function getDomain (doc) {
	var docHost;
	try{docHost=doc.location.host}
	catch(e){
		dumpMsg('Host not found');
		return "";
	}
	var host='', tmpHost;
	// First try a very simple pattern to find the domain name.
	tmpHost=String(doc.location.host).match(/(.*\.)?(.+\..{2,7})/);
	if (tmpHost && tmpHost[2]) host=tmpHost[2];
	// Then try to find a more specific "reasonable" name inside a
	// third-level domain.  If there is none, this does nothing.
	tmpHost=String(doc.location.host)
			.match(/(.*\.)?(.*\.((ac|biz|co|com|edu|gov|info|int|mil|name|net|org)\.[a-z]{2}))/);
	if (tmpHost && tmpHost[2]) host=tmpHost[2];
	dumpMsg('Picked host: '+host);
	return host;
}

function fillDocument (master,doc,runManually,length,algorithm){
	try{
		dumpMsg("Filling document: master="+master+"doc.location="+doc.location);
	var host=getDomain(doc);
	dumpMsg("host is: "+host);
	try{
	var user=pref.get('username');
	var email=pref.get('email');
	}catch(e){dumpErr(e)}
	dumpMsg("user: "+user+", email: "+email);
	// substitute wildcard address
	if ('@'==email.charAt(0)) email=host.match(/[^.]*/)+email;
	// substitute plus address
	email=email.replace('+@', '+'+host.match(/[^.]*/)+'@');
	var fieldNum;
	var forms=doc.forms;
	if(!forms.length){return}
	var pass=makePass(master,host,doc.location,length,algorithm);
	dumpMsg("Generated: "+pass)
	for (var i=0; forms[i];i++){
		var form = forms[i];
		var formType=getFieldTypes(form)
		if(formType.passFields){
			if (pref.get('autoCompOff')) {
				form.setAttribute('autocomplete', 'off');
			}
			fillPassFields(formType.passFields,pass);
			for (var j=0,el; el=formType.emailFields[j];j++){
				if((runManually || el.value=='') && email){
					el.value=email
				}
			}
			for (var j=0,el; el=formType.userFields[j];j++){
				if((runManually || el.value=='') && user){
					el.value=user;
				}
			}
			if(formType.submitElement&&runManually){
				formType.submitElement.focus();
			}
		}
	}
	} catch(e){dumpErr(e)}
}

function fillPassFields (passFields,pass){
	//If there are 3 password fields in a form,
	//it is probably a change password form,
	//so leave the first field blank
	var onlyFill2Fields=pref.get('onlyFill2Fields')
	if(3==passFields.length&&onlyFill2Fields){
		passFields[1].value=pass;
		passFields[2].value=pass;
	}
	else {
		for (var j=0; passFields[j];j++){
			passFields[j].value=pass;
		}
	}
}

//Begin event handlers
function start() {
	//var el=dgEBI("contentAreaContextMenu");
	//if (el) el.addEventListener("popupshowing", popupshowing, false);
	addEventListener("DOMContentLoaded", autoRun, true);
	//Load pwdHash style password prefix from preferences
	prefix=pref.get('interceptPrefix');
	
	if(prefix){
		//Add PwdHash style password interceptor
		addEventListener('keypress', keypressHandler, true);
		addEventListener('keydown', keyUpDown, true);
		addEventListener('keyup', keyUpDown, true);
	}
	dumpMsg("Tab now ready to receive");
	sendAsyncMessage("msgpgen-tab-ready", {});
	dumpMsg("Tab sent ready message")
}

function popupshowing (event) {
	var hide=('password'!=gContextMenu.target.type);
	dgEBI("msgpgen-context").setAttribute('hidden', hide);
}
//End event handlers

//Begin PwdHash style password interceptors
var passFieldValue="";
var intercepting=false;
var prefix="!@";

function fireKeyPress (target, charCode, keyCode) {
	dumpMsg("Trying to create fake keypress")
	var evt = content.document.createEvent("KeyEvents");
	evt.initKeyEvent("keypress", true, true, content, false, false,
			false, false, keyCode, charCode);
	evt.msgpgenIntercepted = true;
	target.dispatchEvent(evt);
	dumpMsg("Fake keypress dispatched")
}

//Given a key code will return whether or not pressing
//this key may produce a printable character
function keyCodePrintable(code){
	var normalPrintable=KeyEvent.DOM_VK_0<=code&&code<=KeyEvent.DOM_VK_DIVIDE;
	var morePrintable=KeyEvent.DOM_VK_COMMA<=code&&code<=KeyEvent.DOM_VK_QUOTE;
	return normalPrintable||morePrintable;
}

function keypressHandler(event) {
	function getNextFiller(){
		return passFieldValue.length+32
	}
	//In these cases, we don't want the keypress to be intercepted
	if(event.msgpgenIntercepted||event.ctrlKey||
			event.target.tagName.toLowerCase()!="input"){
		return;
	}
	if(event.keyCode&&event.type=="keypress"){
		//If enter was pressed, hash the field and then simulate an enter keypress
		if(event.keyCode==13){
			event.preventDefault();
			passwdFieldBlur(event);
			fireKeyPress(event.target, 0, 13)
		}
		return;
	}
	event.target.addEventListener('blur', passwdFieldBlur, false);
	intercepting=intercepting||(event.charCode==prefix.charCodeAt(0)&&
			event.target.value=="")
	//If the user selected everything, we won't have an empty field
	//so we need to allow for this case
	if(event.charCode==prefix.charCodeAt(1)&&
			event.target.value==prefix[0]){
		passFieldValue=prefix[0]+passFieldValue;
		intercepting=true
	}
	if(intercepting&&event.type=="keypress"&&event.charCode){
		event.preventDefault();
		event.stopPropagation();
		passFieldValue+=String.fromCharCode(event.charCode);
		fireKeyPress(event.target, getNextFiller(), 0);
	}
}

function keyUpDown(event){
	//For non-keypress events, blocking them entirely is the easiest option
	if(intercepting&&keyCodePrintable(event.keyCode)){
		event.preventDefault();
		event.stopPropagation();
	}
}

function getPassForField(field){
	var fieldVal=field.value;
	var passwd=""
	for(i in fieldVal){
		passwd+=String.fromCharCode(passFieldValue.charCodeAt(fieldVal.charCodeAt(i)-33))
	}
	//If the first part doesn't match the prefix, just unmask the password
	if(passwd.slice(0,prefix.length)!=prefix){
		return passwd;
	} else {
		if(field.value.length<5){
			alert('Your password is too short.\n'+
			'Something may be trying to steal your password')
		}
		field.addEventListener('focus', hashedFieldFocus, false);
		var domain=getDomain(field.ownerDocument);
		return makePass(passwd.slice(prefix.length),domain,field.ownerDocument.location);
	}
}

//We don't want the user mixing hashed passwords and unhashed passwords
function hashedFieldFocus(event){
	event.target.value='';
	this.removeEventListener('focus', hashedFieldFocus, false);
}

function passwdFieldBlur(event){
	if(intercepting){
		event.target.value=getPassForField(event.target);
		intercepting=false;
		passFieldValue="";
	}
	this.removeEventListener('blur', passwdFieldBlur, false);
}
//End PwdHash style password interceptors
start();

})()
}catch(e){dump(e);alert(e)}