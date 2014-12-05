//This is a subscript
(function(){
	var debugMode=false;
	var debugErrors=false;
	var consoleService = Components.classes["@mozilla.org/consoleservice;1"].
						 getService(Components.interfaces.nsIConsoleService);
	function dumpErr(e) {
		if(debugErrors){
			dumpMsg("ERROR: "+e)
			var scriptError = Components.classes["@mozilla.org/scripterror;1"]
			                  .createInstance(Components.interfaces.nsIScriptError);
			var message="Error in Hash Password Generator:\n"+
			            e.name+": "+e.message;
			scriptError.init(message, e.fileName, null, e.lineNumber, null, null, null);
			consoleService.logMessage(scriptError);
		}
	}

	function dumpMsg(msg) {
		if(debugMode){
			consoleService.logStringMessage('Hash Password Generator:\n '+msg);
		}
	}
	return {dumpErr:dumpErr,dumpMsg:dumpMsg}
})()
