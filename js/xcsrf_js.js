(function(module,undefined) {
	/** 
	 * use try/catch to determine if a string is valid Json string.
	 * This function will return `false` for any valid json primitive, e.g.
	 *     'true' -> false
	 *     '123' -> false
	 *     'null' -> false
	 *     '"I'm a string"' -> false
	 * @param: string str - JSON string
	 * @return: bool	
	 */
	function isValidJson(str) {
		try { 
			JSON.parse(str) 
		} 
		catch { 
			return false; 
		}	
		return true;
	}

	/**
	 * Convert the header string into an array of individual headers
	 * Used to process getAllResponseHeaders() result
	 * @param: headers - A string representing all of the response's headers
	 * @return: an array of individual headers
	 * usage: var contentType = headerMap["content-type"];
	 */
	function httpHeaderMap(headers) {
		var arr = headers.trim().split(/[\r\n]+/);
		var len = arr.length;
		// Create a map of header names to values
		var items, header, value, headerMap = {};
		for (var i = 0; i < len; i++) {
			items = arr[i].split(': ');
			header = items.shift();
			value = items.join(': ');
			headerMap[header] = value;
		}
		return headerMap;
	}
	
	//override Fetch() to automatically send CSRF token with it.
	//Testing env: Google Chrome Version 100.0.4896.88 (Official Build) (64-bit)
	function overrideFetchRequest() {
		const originalFetch = window.fetch;
		window.fetch = function() {
			//NOTE: fetch will convert HTTP header names to lower case!!!
			if (arguments[1]!==undefined) {
				if (arguments[1].headers===undefined) { 
					var hdr = new Headers(); 
					//set token in header
					hdr.append(module.config.CSRF_XHR_HEADER_NAME, getCSRFToken(module.config.CSRF_TOKEN_NAME));
					hdr.append(module.config.CSRF_FETCH_FLAG_HEADER_NAME, true);
					arguments[1].headers = hdr;
				} else {
					arguments[1].headers.append(module.config.CSRF_XHR_HEADER_NAME, getCSRFToken(module.config.CSRF_TOKEN_NAME));	
					arguments[1].headers.append(module.config.CSRF_FETCH_FLAG_HEADER_NAME, true);
				}
				//set ajax calling method id
				arguments[1].headers.append('Ajax-Call-Method', 'fetch');
			} else { 
				if (arguments[0]["method"]==="POST") {
					//append headers ONLY IF it is a POST method
					arguments[0].headers.append(module.config.CSRF_XHR_HEADER_NAME, getCSRFToken(module.config.CSRF_TOKEN_NAME));	
					arguments[0].headers.append(module.config.CSRF_FETCH_FLAG_HEADER_NAME, true);
					arguments[0].headers.append('Ajax-Call-Method', 'fetch');
				}
			}
			var response = originalFetch.apply(this, arguments);
			response.then(function(origResponse) {
				var resp = origResponse.clone();
				if (resp.status == 403 && resp.statusText === 'Forbidden') {
					if (resp.headers.has('csrf-auth-status')) return resp.json();
					else return false;
				}
				else return false;
			})
			.then(function(respJson){	
				if (!respJson) return;
				var popup = document.createElement("div");
				popup.innerHTML = respJson.popup!==undefined?respJson.popup:'';
				document.body.appendChild(popup);
			});
			/* the original response can be resolved unmodified: */
			return response;			
		 }	
	}//overrideFetchRequest()

	//override the XMLHttpRequest.prototype.send to intercept all requests and add a csrf token in a customer header. 
	//This would globally insert a CSRF token to ALL instances of XMLHttpRequest (XHR), in POST data body/header, 
	//and then encapsulate the native send.
	//A CSRF Token is always carried by a request header in case of AJAX POST request(both xhr and fetch). 
	//This is done in the XMLHttpRequest Send method wrapper by calling setRequestHeader() method of XMLHttpRequest class, 
	//or in the Fetch case, append the token to a request Header.
	function OverrideXHRSend() {
		// ORIGINAL SEND - THIS IS ALWAYS UNDEFINED
		//Keep the reference to the native send method
		var originalSend = XMLHttpRequest.prototype.send,
			originalOpen = XMLHttpRequest.prototype.open;

		// OVERRIDDEN METHOD 
		XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
			this.method = method; //interceopt and export XHR request method to send() method.
			this.addEventListener('readystatechange', function(){
				//interact with the response text
				// readyState 2 - HEADERS_RECEIVED: headers and status are available.
				if (this.readyState == this.HEADERS_RECEIVED) {
					// Get the raw header string
					//var headers = this.getAllResponseHeaders();
				}
			});
			this.addEventListener('load',function() {// called when the response is received
				if (this.status == 403 && this.statusText === 'Forbidden') {
					var hdr = httpHeaderMap(this.getAllResponseHeaders());
					if (hdr['csrf-auth-status'] !== undefined) {
						var resp, popup = document.createElement("div");
						try {
							resp=JSON.parse(this.responseText);
						} catch (e) {
							console.log("JSON.parse reponse failed.");
							return;
						}
						popup.innerHTML = resp.popup!==undefined?resp.popup:'';
						document.body.appendChild(popup);
					}
				}
			});
			
			var om = originalOpen.apply(this, arguments);
			//Overriding Defaults to Set Custom Header
			//this.setRequestHeader(module.config.CSRF_XHR_HEADER_NAME, token);
			return om;
		}
		XMLHttpRequest.prototype.send = function(data) {
			//will only insert tokens to post method
			if (this.method.toLowerCase() === 'post') {
				//NOTE: custom headers will not work with HTTPS requests
				//custom header that triggers a preflight request to ask for 
				//the server¡¯s permission to send further CORS requests.
				//If the server won¡¯t send the correct preflight response, 
				//the actual request will never be sent. 
				var token = getCSRFToken(module.config.CSRF_TOKEN_NAME);				
				this.setRequestHeader(module.config.CSRF_XHR_HEADER_NAME, token);
				//set ajax calling method id
				this.setRequestHeader('Ajax-Call-Method', 'xhr');
				//wrap the csrf token and payload in the request into a new json string
				/*
				//while this strategy works, it also create overheads when forwarding the request
				//to the web application. As a transparent standalone server, xcsrf-proxy does not
				//understand the protocol betweend web app server and client. It needs to restore 
				//payload in the original request. Pass token with custom header instead.
				data = JSON.stringify({
					[module.config.CSRF_TOKEN_NAME] : token,
					payload: data
				});
				*/
			}
			//invoke original real method with arguments passed into the call
			return originalSend.apply(this, arguments);
		}
	}

	/** 
	 * Override HTMLMFormElement to intercept form submit and insert the csrf token a HTML request. This
	 * will handle all current and later dynamically created forms.
	 * @param: N/A - except module.config.CSRF_TOKEN_NAME as a global variable.
	 * @return: N/A->undefined
	 */	
	function overrrideHTMLFormElement() {
		/********************
		The following code handles HTMLFormElement.submit() method) with JavaScript. 
		--VERY IMPORTANT--
		to intercept JavaScript submit, this code block should be added in the top 
		of body element before any form rendered and submitted.
		*********************/
		//store the original method, it will be called when both JavaScript submit and HTML submit invoked!
		var original = HTMLFormElement.prototype.submit;
		//create an intercept and override the submit() method 
		HTMLFormElement.prototype.submit = function (data) {
			var token = getCSRFToken(module.config.CSRF_TOKEN_NAME);
			insertTokenHiddenInput(module.config.CSRF_TOKEN_NAME, token, this);
			//optional - submit type identifier	
			insertTokenHiddenInput('csrfFormElementTrigger', 'javascript_method', this);
			//invoke the old method
			original.call(this, data);
		};

		/********************
		HTML submit
		The following code overrides the onsubmit event (HTMLFormElement::submit event). 
		It works as long as the form is submitted either via Submit button (or ENTER).
		It's totally IGNORED if you call the form.submit programmaticaly like this:
		document.getElementById('myform').submit();
		Have to override the submit method. See above code.
		*********************/
		//Wrapper for HTMLFormElements addEventListener (html form submit) to insert
		//CSRF token form all HTML form submit
		//listen for form submit with event delegation to document root, while prevent 
		//the default action of submitting the form. This way will handle all current 
		//forms and any dynamically creted forms effectively.
		document.body.addEventListener('submit', function (e) {
			e.preventDefault();
			var form = e.target,
				token = getCSRFToken(module.config.CSRF_TOKEN_NAME);
			//insert token as a hidden input value
			insertTokenHiddenInput(module.config.CSRF_TOKEN_NAME, token, form);
			//optional - submit type identifier - should be ripped off before handover to web app.
			insertTokenHiddenInput('csrfFormElementTrigger', 'onsubmit_event', form);
			//invoke the native submit method for form by passing event object with apply();		
			original.apply(form);		
			return;
		}, false);	
	}

	/** 
	 * Retrieve csrf token from the meta tag in the html file
	 * @param: string tagName -  name of the meta tag holding csrf token
	 * @return: string token - anti-csrf token provided by server (in a meta tag)
	 * NOTE: this function uses template literals as introduce in ECMAScript 2015 (ES6);
	 *      may need Babel/Webpack to transpile your code into ES5 to ensure its compatibility.
	 * usage: var token = getCSRFToken('csrf-token');
	 */
	function getCSRFToken(tagName) {
		return document.querySelector(`meta[name=${tagName}]`).getAttribute("content").trim();
	}

	/** 
	 * Copy csrf token to a new created hidden input field, and insert as the 1st child into a given form
	 * @param: string name -  name of the hidden input
	 * @param: string token - anti-csrf token provided by server (in a meta tag)
	 * @param: string frm - name of the form element
	 * @return: N/A->undefined
	 */
	function insertTokenHiddenInput(name, token, frm){
		var existingIp;
		//remove hidden input matched the predefined name, if exists! 
		existingIp = frm.querySelectorAll('input[name="'+name+'"]');
		existingIp.forEach(function(item){
			//remove curren existing csrf token input field despite the value of the token 
			if (item!=="undefined") { 
				frm.removeChild(item);
			}
		});
		//start inserting a hidden input
		var el = document.createElement("input");
		el.name = name;
		el.type = 'hidden';
		el.value = token;
		// Insert the new element before the first child
		//var firstChild = frm.firstChild
		frm.insertBefore(el, frm.firstChild);
	}
	
	/*   helper functions */

	/**
	 * save all forms  data in a page to localStorage
	 * @Param: string key - key to use in localStorage
	 * @return: N/A;
	 */
	function saveAllFormDataInBrowser(key='_formData_csrf_') {
		var formElms = document.forms;
		var frm = [];
		localStorage[key+'_path'] = location.pathname;
		for (var i=0;i<formElms.length;i++) { 
			frm[i] = JSON.stringify(Array.from(formElms[i].querySelectorAll('input')).map((el) => el.value));
		} 
		localStorage[key] = JSON.stringify(frm);
	}

	/**
	 * restore all forms in a page from localStorage
	 * @Param: string key - key to use in localStorage
	 * @Param: bool samepage - flag to bind the form data to a specific page rather than origin.
	 * @return: N/A;
	 *
	 */
	function restoreAllFormDataInBrowser(key='_formData_csrf_', samepage=true) {
		if (samepage) {
			if (!localStorage[key+'_path']||localStorage[key+'_path']!==location.pathname) {
				console.log('form data restore aborted.');
				return;
			}
		}
		var formElms = document.forms;
		var frmSaved,_formData_ = JSON.parse(localStorage._formData_csrf_) || [];
		for (var i=0;i<formElms.length;i++) { 
			frmSaved = JSON.parse(_formData_[i]) || [];
			Array.from(formElms[i].querySelectorAll('input')).forEach((input, id) => {
			  input.value = frmSaved[id];
			  var event = document.createEvent("HTMLEvents");
			  event.initEvent("input", true, true);
			  input.dispatchEvent(event);
			});
		}
		//remove the localStorage item once restored.
		localStorage.removeItem(key+'_path');
		localStorage.removeItem(key);
	}
	
	/**
	 * delegate event listener using event bubble
	 * usage: 
	 * bindDynamicEventListener('click', document, '.alert-button', callback);
	 */
	function bindDynamicEventListener(eventType, parentElement, selector, callback)	{
		parentElement.addEventListener(eventType, function(e) {
			if (e.target && e.target.matches && e.target.matches(selector)) {
				 e.delegatedTarget = e.target;
				 callback.apply(this, arguments);
			}
		});
	}

	//Invoke XCSRF interceptors
	OverrideXHRSend();
	overrrideHTMLFormElement();	
	overrideFetchRequest();
	window.addEventListener('load', (e) => {		
		restoreAllFormDataInBrowser();
	});
		
	//public methods
	module.backForms = saveAllFormDataInBrowser;
})(HI5_XCSRF_NAMESPACE_CLONE);