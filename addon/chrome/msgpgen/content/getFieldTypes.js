//This is a subscript
(function getFieldTypes(form){
	function findFieldType(el) {
		try {
			function oneElXpath(doc, exp) {
				var result=doc.evaluate(
					exp, doc, null, doc.defaultView.XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, null
				);
				return result.snapshotItem(0);
			}
			
			var doc=el.ownerDocument;
			// In these cases, we *know* it's not a field we want to deal with.
			if (el.type in {
				'checkbox':1, 'hidden':1, 'radio':1, 'reset':1
			}) {
				return null;
			}
			if (el.tagName.toLowerCase()!="input"){
				return null;
			}

			// Fields with exact name or type 'password' are clear.
			if ( 'password'==String(el.type)
				|| 'password'==String(el.name).toLowerCase()
			) {
				return 'password';
			}

			// Submit and image type fields are clear.
			if ('submit'==el.type || 'image'==el.type) {
				return 'submit';
			}

			var userScore=0;
			var emailScore=0;
			var label=null;

			// Find label text.
			if (''!=el.id) {
				// If we have an id, try to find the label for it.
				try{
					label=oneElXpath(doc, '//label[@for="'+el.id+'"]');
				} catch(e){dump(e)}
			}
			// Try to find the label this el is _in_.
			label=el;
			while (label && 'LABEL'!=label.tagName) {
				label=label.parentNode;
			}
			
			var txt='';
			if (label) {
				// If we have a label, use its text.
				txt=label.textContent;
			}
			else {
				// If we don't, try to find some surrounding text.

				try {
					var tmpid='msgpgen'+String(Math.random()).substr(2);
					var tmptxt=doc.createTextNode(tmpid);

					// Put in our temp text to look for.
					el.appendChild(tmptxt);

					// Look for 20 (non whitespace) chars before that marker.
					var txt=doc.body.textContent.replace(/\s+/g, ' ');
					var pos=txt.indexOf(tmpid);
					txt=txt.substring(pos-20, pos);

					// Remove our marker.
					el.removeChild(tmptxt);
				}
				catch (e) {
					dumpErr(e);
					txt='';
				}

			}
			if (txt.match(/\b(e-?mail)\b/i)
				|| el.name.match(/^e$|e-?mail/i)
			) {
				return 'email';
			}

			if (txt.match(/\b((user|member) ?name|log ?in|id)\b/i)
				|| el.name.match(/user|username|login|id/i)
			)  {
				return 'user';
			}

			// If I didn't match something above, I don't know!
// 			dump([
// 				'unknown field!',
// 				'type: '+el.type,
// 				'name: '+el.name,
// 				'id: '+el.id,
// 				'label: '+label,
// 				'text: '+txt,
// 			''].join('\n'));
		} catch(e){
			dump(e);
			return null;
		}
		return null;
	}

	var passFields=[], emailFields=[], userFields=[], submitElement;
	if(form.elements){
		for (var j=0, el; el=form.elements[j]; j++) {
			var type=findFieldType(el);
			if (!type) {
				continue;
			} else if ('password'==type) {
				passFields.push(el)
			}
			// Skip any element that isn't visible.
			if (0==el.offsetWidth) continue;
			if ('user'==type) {
				userFields.push(el);
			} else if ('email'==type) {
				emailFields.push(el);
			} else 	if ('submit'==type) {
				submitElement=el;
			}
		}
		return {
			passFields: passFields,
			emailFields: emailFields,
			userFields: userFields,
			submitElement: submitElement
		}
	} else return {passFields: null}
})