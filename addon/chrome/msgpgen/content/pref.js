//This is a subscript
(function(){
	var prefService = Components.classes['@mozilla.org/preferences-service;1']
			.getService(Components.interfaces.nsIPrefService)
	var allBranch=prefService.getBranch(null);
	var msgpgenBranch = prefService.getBranch('msgpgen.');

	function get(name) {
		var type=msgpgenBranch.getPrefType(name);
		switch(type) {
			case msgpgenBranch.PREF_BOOL:   return msgpgenBranch.getBoolPref(name);
			case msgpgenBranch.PREF_INT:    return msgpgenBranch.getIntPref(name);
			case msgpgenBranch.PREF_STRING:	return msgpgenBranch.getCharPref(name);
		}
		return null;
	}

	function set(type, name, value) {
		switch (type) {
			case 'bool':   msgpgenBranch.setBoolPref(name, value); break;
			case 'int':    msgpgenBranch.setIntPref(name, value); break;
			case 'string':
			default:       msgpgenBranch.setCharPref(name, value); break;
		}
	}

	function getAny(name) {
		var type=allBranch.getPrefType(name)
		switch(type) {
			case allBranch.PREF_BOOL:   return allBranch.getBoolPref(name);
			case allBranch.PREF_INT:    return allBranch.getIntPref(name);
			case allBranch.PREF_STRING:	return allBranch.getCharPref(name);
		}
		return null;
	}

	function setAny(type, name, value) {
		switch (type) {
			case 'bool':   allBranch.setBoolPref(name, value); break;
			case 'int':    allBranch.setIntPref(name, value); break;
			case 'string':
			default:       allBranch.setCharPref(name, value); break;
		}
	}
	return {set:set, get:get, setAny:setAny, getAny:getAny};
})()