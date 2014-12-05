(function(pref, hashLib){
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
function getBackgroundColor(str){
	var passHash = pref.get('verifyHash');
	var hashed = fastHash(str);
	if(passHash){
		return (hashed == passHash ? '#00ff00' : '#ff0000');
	}
	return ('#'+(hashed+'00').substring(0,6));
}

var imageWidth=42;
var can1, can2, ctx1, ctx2;

var currentBlobURL=null;
var currentTextbox=null;

function colorize(textbox, text){
	if(textbox!==currentTextbox){
		var document=textbox.ownerDocument;
		can1=document.createElementNS("http://www.w3.org/1999/xhtml", "html:canvas");
		can1.width = 7;
		can1.height = 3;
		can2=document.createElementNS("http://www.w3.org/1999/xhtml", "html:canvas");
		ctx1=can1.getContext("2d");
		ctx2=can2.getContext("2d");
		currentTextbox=textbox;
	}
	if(arguments.length<2){text=textbox.value};
	var hashed2 = hashLib.digest(text,"SHA512","raw");
	var textColour = '';
	var bgColour = getBackgroundColor(text);
	var R=parseInt(bgColour.substring(1,3),16);
	var G=parseInt(bgColour.substring(3,5),16);
	var B=parseInt(bgColour.substring(5,7),16);
	var textColour = (0.3*R + 0.59*G + 0.11*B) < 96 ? "White" : "Black";
	
	var hashcodes=[]; 
	for(var i=0;i<hashed2.length;i++){
		hashcodes.push(hashed2.charCodeAt(i))
	}
	var iDat=ctx1.createImageData(7,3);
	for(var i=0;i<21;i++){
		iDat.data[4*i]=hashcodes[3*i];
		iDat.data[4*i+1]=hashcodes[3*i+1];
		iDat.data[4*i+2]=hashcodes[3*i+2];
		iDat.data[4*i+3]=255; 
	}
	ctx1.putImageData(iDat,0,0);
	var style=getComputedStyle(textbox,null);
	can2.height=parseInt(style.height)+parseInt(style.paddingTop)+parseInt(style.paddingBottom);
	can2.width=parseInt(style.width)+parseInt(style.paddingLeft)+parseInt(style.paddingRight);
	ctx2.fillStyle=bgColour;
	ctx2.fillRect(0,0,can2.width, can2.height);
	ctx2.drawImage(can1, can2.width-imageWidth, 0, imageWidth, can2.height);
	/*can2.toBlob(function(blob){
		URL.revokeObjectURL(currentBlobURL);
		currentBlobURL=URL.createObjectURL(blob);
		textbox.style.backgroundImage = "url("+currentBlobURL+")";
	});*/
	textbox.ownerDocument.mozSetImageElement("msgpgen-canvas", can2);
	textbox.style.backgroundImage = '-moz-element(#msgpgen-canvas)';
	textbox.style.color = textColour;
}
return {
	colorize: colorize,
	getBackgroundColor: getBackgroundColor
}
})