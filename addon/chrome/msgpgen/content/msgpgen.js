dump("Initializing msgpgen");
(function () {

var masterPw = null;

//Load supplimentary files.
var loader = Components.classes["@mozilla.org/moz/jssubscript-loader;1"].
			 getService(Components.interfaces.mozIJSSubScriptLoader);
var pref=loader.loadSubScript('chrome://msgpgen/content/pref.js');
var errorLog=loader.loadSubScript('chrome://msgpgen/content/errorLog.js');
var hashes=loader.loadSubScript('chrome://msgpgen/content/hashes.js')(pref);
var getFieldTypes=loader.loadSubScript('chrome://msgpgen/content/getFieldTypes.js');
var colorHash=loader.loadSubScript("chrome://msgpgen/content/colorhash.js")(pref, hashes.hashLib);

var dumpErr=errorLog.dumpErr;
var dumpMsg=errorLog.dumpMsg;

//Begin function declarations
function dgEBI(id,doc){
	if(!doc){doc=document;}
	return doc.getElementById(id);
}

function fillForms(promptValue) {
	try {
		if(promptValue&&promptValue.masterPw){
			dumpMsg("Master password received, filling forms");
			var currentTab=getBrowser()
			var win=currentTab.contentWindow;
			fillDocument(promptValue.masterPw, win.document,true,
					promptValue.length,promptValue.algorithm);
			for (var i=0; i<win.frames.length; i++) {
				fillDocument(promptValue.masterPw, win.frames[i].document,true,
						promptValue.length,promptValue.algorithm);
			}
		}
		if(promptValue && promptValue.remember){
			masterPw=promptValue.masterPw;
		}
	} catch (e) { dumpErr(e) }
}

function run(event) {
	var runWithPrompt=(event.target.getAttribute("name").indexOf("prompt")>-1);
	if(event.target.getAttribute("name").indexOf("forget")>-1){
		masterPw=null;
	} else if(runWithPrompt||!masterPw){
		fillForms(getMaster(runWithPrompt))
	} else {
		fillForms({masterPw:masterPw});
	}
	/*
	 * If we click the custom prompt menu item, it would bubble up to the toolbar button
	 * We need to prevent this else there will be 2 prompts.
	 */
	event.stopPropagation();
}

function autoRun(event){
	if(masterPw&&pref.get('fillOnLoad')){
		fillDocument(masterPw,event.target,false)
	}
}

function getMaster(runWithPrompt){
	var remember=false;
	if(!runWithPrompt){
		remember=pref.get('rememberDefault');
	}
	var returnValue={remember:remember};
	if(!runWithPrompt){
		window.openDialog(
				'chrome://msgpgen/content/masterPrompt.xul',
				'_blank', 'modal, centerscreen', returnValue);
	} else{
		window.openDialog(
				'chrome://msgpgen/content/extendedInput.xul',
				'_blank', 'modal, centerscreen', returnValue);
	}
	if(returnValue.masterPw){
		return returnValue;
	} else{
		return null;
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
	var host=getDomain(doc);
	var user=pref.get('username');
	var email=pref.get('email');
	// substitute wildcard address
	if ('@'==email.charAt(0)) email=host.match(/[^.]*/)+email;
	// substitute plus address
	email=email.replace('+@', '+'+host.match(/[^.]*/)+'@');
	var fieldNum;
	var forms=doc.forms;
	dumpMsg("Filling document: forms="+forms+", forms.length="+forms.length);
	if(!forms||!forms.length){return}
	var pass=makePass(master,host,doc.location,length,algorithm);
	for (var i=0; forms[i];i++){
		dumpMsg("Found form");
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
function onload (event) {
	if(pref.get('firstRun')){
		addToolbarButton();
		pref.set('bool','firstRun',false);
	}
	window.removeEventListener('load', onload, false);
	var el=dgEBI("contentAreaContextMenu");
	if (el) el.addEventListener("popupshowing", popupshowing, false);
	var els=document.getElementsByClassName('msgpgen')
	for(var i=0; els[i]; i++){
		els[i].addEventListener('command',run,false);
	}
	getBrowser().addEventListener("DOMContentLoaded", autoRun, true);
	//Load pwdHash style password prefix from preferences
	prefix=pref.get('interceptPrefix');
	if(prefix){
		//Add PwdHash style password interceptor
		window.addEventListener('keypress', keypressHandler, true);
		window.addEventListener('keydown', keyUpDown, true);
		window.addEventListener('keyup', keyUpDown, true);
	}
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
	var evt = document.createEvent("KeyEvents");
	evt.initKeyEvent("keypress", true, true, window, false, false,
			false, false, keyCode, charCode);
	evt.msgpgenIntercepted = true;
	target.dispatchEvent(evt);
}

//Given a key code will return whether or not pressing
//this key may produce a printable character
function keyCodePrintable(code){
	var normalPrintable=KeyEvent.DOM_VK_0<=code&&code<=KeyEvent.DOM_VK_DIVIDE;
	var morePrintable=KeyEvent.DOM_VK_COMMA<=code&&code<=KeyEvent.DOM_VK_QUOTE;
	return normalPrintable||morePrintable;
}

var originalBackground, originalColor;

function startIntercepting(event){
	intercepting=true;
	originalBackground=event.target.style.backgroundImage;
	originalColor=event.target.style.color;
	var button=dgEBI('tb-msgpgen');
	button&&(button.style.MozAppearance="none");
}
function stopIntercepting(event){
	dumpMsg("Stopping intercepting. The textbox should return to normal now.");
	intercepting=false;
	event.target.style.backgroundImage=originalBackground;
	event.target.style.color=originalColor;
	var button=dgEBI('tb-msgpgen');
	button&&(button.style.backgroundColor="");
	button&&(button.style.MozAppearance="");
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
			fireKeyPress(event.target, 0, 13);
			return;
		}
		if(event.keyCode==9){
			dumpMsg("Tab Pressed");
			return;
		}
	}
	event.target.addEventListener('blur', passwdFieldBlur, false);
	/*
	 * TODO: This needs to be secured. I need to add protection against a form that 
	 * modifies the value of the field such that after entering the prefix, it's not
	 * actually in the field.
	 * Done: When you enter the master password, the icon background changes color.
	 * This cannot be faked. As long as you make sure that the icon background changes,
	 * you should be secure.
	 */
	if(event.target.value==prefix&&!intercepting){startIntercepting(event);}
	if(event.target.value==''&&intercepting){stopIntercepting(event);}
	
	if(intercepting&&event.type=="keypress"&&event.charCode){
		event.preventDefault();
		event.stopPropagation();
		passFieldValue+=String.fromCharCode(event.charCode);
		fireKeyPress(event.target, getNextFiller(), 0);
	}
	if(intercepting){
		//Wait until the keypress has taken effect to display background. Backspace won't work properly otherwise.
		setTimeout(function(){
			var unmasked=unmaskPassword(event.target);
			/*
			 * Make the textbox have the same background color as in the main dialog.
			 * Note: This can be faked on the website's side. You should check the icon background.
			 * TODO: Check if this is secure. The webpage might be able to read the 
			 * background color and reverse the hash. I'm not sure how -moz-element works.
			 */
			colorHash.colorize(event.target, unmasked);
			var button=dgEBI('tb-msgpgen');
			button&&(button.style.backgroundColor=colorHash.getBackgroundColor(unmasked));
		}, 0);
	}
}

function keyUpDown(event){
	//For non-keypress events, blocking them entirely is the easiest option
	if(intercepting&&keyCodePrintable(event.keyCode)){
		event.stopPropagation();
	}
}
function unmaskPassword(field){
	var fieldVal=field.value;
	var passwd=""
	for(var i = prefix.length; i<fieldVal.length; ++i){
		passwd+=String.fromCharCode(passFieldValue.charCodeAt(fieldVal.charCodeAt(i)-33))
	}
	return passwd;
}
function getPassForField(field){
	var passwd=unmaskPassword(field);
	if(field.value.length<8){
		alert('Your password is too short.\n'+
		'Something may be trying to steal your password');
	}
	field.addEventListener('focus', hashedFieldFocus, false);
	var domain=getDomain(field.ownerDocument);
	return makePass(passwd,domain,field.ownerDocument.location);
}

/*
 * We don't want the user mixing hashed passwords and unhashed passwords
 * We clear the hashed password before the user types into the field
 */
function hashedFieldFocus(event){
	event.target.value='';
	this.removeEventListener('focus', hashedFieldFocus, false);
}

function passwdFieldBlur(event){
	if(intercepting){
		event.target.value=getPassForField(event.target);
		stopIntercepting(event);
		passFieldValue="";
	}
	event.target.removeEventListener('blur', passwdFieldBlur, false);
}
//End PwdHash style password interceptors

function addToolbarButton () {
	try{
		var bar
		var addonBar=dgEBI("addon-bar");
		var navBar=dgEBI("nav-bar");
		if(addonBar){bar=addonBar} else {bar=navBar;}
		bar.insertItem("tb-msgpgen");
		bar.setAttribute("currentset", bar.currentSet);
		if(addonBar){document.persist("addon-bar", "currentset");} 
		else{document.persist("nav-bar", "currentset");}
	} catch(e){}
}

function browserIsFennec(){
	const fennecId="{a23983c0-fd0e-11dc-95ff-0800200c9a66}"
	var appInfo = Components.classes["@mozilla.org/xre/app-info;1"]
		.getService(Components.interfaces.nsIXULAppInfo);
	if(appInfo.ID==fennecId){
		return true;
	}
	else{
		return false
	}
}
//End function declarations

//Redefine some functions if the browser is Fennec
if(browserIsFennec()){
	getMaster=function(runWithPrompt){
		var remember=false;
		if(!runWithPrompt){
			remember=pref.get('rememberDefault');
		}
		var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
				.getService(Components.interfaces.nsIPromptService);
		var password={};
		remember={value:remember};
		var promptValue=prompts.promptPassword(window, "Hash Password Generator",
				"Please enter your master password",
				password, "Remember for this session", remember)
		if(promptValue){
			return {masterPw:password.value, remember:remember.value};
		} else {
			return null;
		}
	}
}

//Start everything off
window.addEventListener('load', onload, false);

})()
