//Fast hash used for real time verification of master password
function fastHash (string) {
	if(string){
		var val=7,i;
		for(i=0; i < 999 + 2 * string.length; i++){
			val+=(val<<1)+string.charCodeAt(i % string.length)
		}
		return ((val < 0 ? -val : val).toString(16)+"0000000").substring(0,8);
	} else {
		return "ffffffff"		//return something if the empty string is passed
	}
}