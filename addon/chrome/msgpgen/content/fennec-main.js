(function(){
var masterPw = null;
var pwLength;
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


function attachScript(browser){
	dumpMsg("Attaching script");
	var messageManager=browser.messageManager;
	messageManager.loadFrameScript("chrome://msgpgen/content/contentScript.js", true);
	dumpMsg("Done attaching script");
}
function onTabOpen(e){
	var tab=e.originalTarget;
	var browser=tab.linkedBrowser;
	attachScript(browser);
	dumpMsg("Tab opened")
	function updateThisTab(){
		updateTab(browser, masterPw, pwLength, pwAlgorithm);
		delete this.msgpgenUpdate;
	}
	browser.msgpgenUpdate=updateThisTab;
	//browser.messageManager.addMessageListener("msgpgen-tab-ready", onTabReady)
}
function onTabReady(m){
	m.target.msgpgenUpdate();
}
function fillTab(browser, master, pwLength, algorithm, remember){
	var messageContents={master:master, length:pwLength, algorithm:algorithm};
	browser.messageManager.sendAsyncMessage("msgpgen-manual", messageContents);
}
function updateTab(browser, master, pwLength, algorithm){
	var messageContents={master:master, length:pwLength, algorithm:algorithm};
	browser.messageManager.sendAsyncMessage("msgpgen-pw-update", messageContents);
}
function updateTabs(master, pwLength, algorithm){
	var tabs=Browser.tabs;
	for(var i=0;i<tabs.length;i++){
		updateTab(tabs[i].browser, master, pwLength, algorithm);
	}
}
function fillForms(promptValue) {
	try {
		dumpMsg("fillForms run");
		if(promptValue&&promptValue.masterPw){
			dumpMsg("Master password received, filling forms");
			var currentTab=getBrowser();
			dumpMsg("About to call fillTab");
			fillTab(currentTab, promptValue.masterPw, promptValue.length, 
					promptValue.algorithm, promptValue.remember);
			dumpMsg("Called fillTab")
		}
		if(promptValue.remember){
			masterPw=promptValue.masterPw;
			pwLength=promptValue.length;
			pwAlgorithm=promptValue.algorithm;
			updateTabs(masterPw, pwLength, pwAlgorithm);
		}
	} catch (e) { dumpErr(e) }
}

function run(event) {
	try{
		dumpMsg("Running now")
		var runWithPrompt=(event.target.getAttribute("name")=="msgpgen-prompt-shortcut");

		if(event.target.getAttribute("name")=="msgpgen-forget-shortcut"){
			masterPw=null;
		} else if(runWithPrompt||!masterPw){
			fillForms(getMaster(runWithPrompt))
		} else {
			fillForms({masterPw:masterPw});
		}
	}catch(e){dumpErr(e)}
}

function getMaster(runWithPrompt){
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
		dumpMsg("Password has been typed")
		return {masterPw:password.value, remember:remember.value};
	} else {
		dumpMsg("No password")
		return null;
	}
}

function onLoad(event) {
	dumpMsg("Browser loaded");
	window.removeEventListener('load', onload, false);
	var els=document.getElementsByClassName('msgpgen')
	for(var i=0; els[i]; i++){
		els[i].addEventListener('command',run,false);
	}
	var tabs=document.getElementById("tabs");
	tabs.addEventListener("TabOpen", onTabOpen, true);
	var browsers=Browser.browsers
	for(var i=0;i<browsers.length;i++){
		attachScript(browsers[i]);
	}
	messageManager.addMessageListener("msgpgen-tab-ready", onTabReady)
}

window.addEventListener('load', onLoad, false);

})()
