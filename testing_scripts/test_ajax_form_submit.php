<?php
	/** enable xcsrf authentication block **/
	include_once "../xcsrf_proxy.php";
	//Initialise CSRFGuard library
	$xcsrf = new XCSRF();
	$auth = $xcsrf->init();
	/** end enable xcsrf authentication **/

	if (isset($_SERVER['HTTP_AJAX_CALL_METHOD'])) {
		if (strtolower($_SERVER['HTTP_AJAX_CALL_METHOD']) === 'fetch') {
			$ajax_method = array(
				'HTTP_AJAX_CALL_METHOD' => 'fetch'
			);
		}
		//this a ajax xhr request
		//if ($xcsrf->getAuthResults()['calling_method']==='ajax_xhr') {} //also works.
		if (strtolower($_SERVER['HTTP_AJAX_CALL_METHOD']) === 'xhr') {
			$ajax_method = array(
				'HTTP_AJAX_CALL_METHOD' => 'xhr'
			);
		}
		if (isset($ajax_method)) {
			$ajax_method = json_encode(array_merge($ajax_method, $xcsrf->getAuthResults()));
			echo $ajax_method;
			$errorlog = "../log/csrf_error.log";
			file_put_contents($errorlog, "\n\r public xcsrd results: ".print_r($ajax_method, true), FILE_APPEND | LOCK_EX);		
			exit;
		}
	}
?>
<!DOCTYPE html>
<html>
<head>
	<meta content="text/html; charset=utf-8" http-equiv="Content-Type">
</head>
<body>
	<!-- 
	***************
	XHR/Fetch form sumbit testing 
	**************
	-->
	<div style="margin-top: 30px;">
	<fieldset>
        <button type="button" id="csrf-fetch-request" class="btn-fetch-request" style="visibility: hidden;">Send Fetch request</button>
		<button type="button" id="csrf-xhr-request" class="btn-xhr-request" style="visibility: hidden;">Send XHR request</button>
		<button type="button" id="cheating-csrf-xhr-request" class="btn-cheating-xhr-request" style="visibility: hidden;">Cheating XHR request</button>
        <hr class="half-rule"/>
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Requests history</h3>
				<span id="xhr-panel"><span>
            </div>
            <div class="panel-body" id="renderingZone"></div>
        </div>
	</fieldset>
	</div>

	<script>
		var CSRF_TOKENS = {}, 
			endpoint = window.location.href;;

		//*******************************
		//xhr/fetch testing script
		//*******************************

		function fetchTesting(uri) {
			const myHeaders = new Headers();
			myHeaders.append('x-csrf-auth-token-1st', '7726fd8eed7fa9a22493d4');
			const myInit = {
			  method: 'POST',
			  //headers: myHeaders,
			  headers: new Headers({
				'testing-csrf-auth-2nd': '222222221efe975d7d'
			  }),
			  mode: 'cors',
			  cache: 'default',
			};
			const myRequest = new Request(uri);
			myRequest.headers = myHeaders;

			fetch(myRequest, myInit)
			  .then((response) => {
				// console.log("fetch response...");
				return response.json();
			  })
			  .then(data => {
				/* process data further */
				console.log(JSON.stringify(data));
				console.log(data['msg']);
				//display xcsrf auth messages in request history
				if (document.querySelector("#xhr-panel"))
				document.querySelector("#xhr-panel").innerHTML += "<br>response text csrf status: " + JSON.stringify(data);			
			  })
			  .catch(error => console.error(error));
		}

		//usage: xhrTesting(endpoint);
		function xhrTesting(endpoint, method = "POST") {
			/* helper functions */
			var showReqStatus = function(msg) {
				//display xcsrf auth messages in request history
				if (document.querySelector("#xhr-panel"))
				document.querySelector("#xhr-panel").innerHTML += msg;	
			}
			
			/**
			 * Obtain the raw header string with getAllResponseHeaders(), convert it into 
			 * an array of individual headers; and then create a mapping of header names 
			 * to their values.
			 * Used to process getAllResponseHeaders() result
			 * @param: headers - A string representing all of the response's headers
			 * @return: an array of individual headers
			 * use: var contentType = headerMap["content-type"];
			 */
			 var httpHeaderMap = function(headers) {
				//convert the raw header string into an array
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
			
			xhr = new XMLHttpRequest();

			//retrieve headers with an event handler; or with addEventListener('readystatechange',func)
			//we send csrf anthentication failure status in header.
			xhr.onreadystatechange = function() {
				if (this.readyState == this.HEADERS_RECEIVED) {
					// Get the raw header string
					var headers = xhr.getAllResponseHeaders();
				}
			}
			
			//status - HTTP status code (a number): 200, 404, 403 and so on, can be 0 in case of a non-HTTP failure.
			//statusText - HTTP status message (a string): usually OK for 200, Not Found for 404, Forbidden for 403 and so on.
			//response - the server response body.
			xhr.onload = function() {
				var resp = {};
				resp.status = xhr.status;
				resp.statusText = xhr.statusText;
				if (resp.status == 403) {}
				//most likely we only consider JSON object.
				try {
					resp.response = JSON.parse(xhr.response);
				} catch (e) {
					console.error("Fatal error exit - response is not a JSON object");
					console.warn("JSON.parse() failed. Ref: " + e);
					console.log("response status: "+xhr.status+": "+xhr.statusText);
					return false;
				}
				if (resp.response !== undefined) { 
					var msg = JSON.stringify(resp.response);
					console.log("response text csrf status: " + msg);
					msg = "<br>response text csrf status: " + msg;
					showReqStatus(msg);
				} else {
					console.log("response text *-* status: " + JSON.stringify(resp));
				}
				//option 2 header
				var hdr = httpHeaderMap(xhr.getAllResponseHeaders());
				if (hdr['csrf-auth-status'] !== undefined) {
					console.log("header csrf status: " + hdr['csrf-auth-status']);
					showReqStatus("<br>header csrf status: " + hdr['csrf-auth-status']);
				}
			};//xhr.onload
			xhr.open(method, endpoint);

			xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');	
			//send request a random json string
			var json = JSON.stringify({
				name: "who",
				surname: "matter"
			});
			xhr.send(json);
		} //END xhrTesting()

		document.body.addEventListener("click", function(e) {
			e.preventDefault();
			if (e.target.matches("#fakebtn")) {
				//replace content in meta tag with a random gen string
				document.querySelector("meta[name=csrf_auth_token]").setAttribute("content",(Math.random() + 1).toString(36).substring(7));
				document.querySelector("#evilfrm").submit();
			}
			if (e.target.matches("#csrf-fetch-request")) {
				fetchTesting(endpoint);
			}
			if (e.target.matches("#csrf-xhr-request")) {
				xhrTesting(endpoint);
			}
			if (e.target.matches("#cheating-csrf-xhr-request")) {
				console.log("invoking xhrTesting(endpoint)");
				//hide 'Send XHR request' button, cause we will replace the token which leading to a failed csrf check.
				document.querySelector("#csrf-xhr-request").style.visibility='hidden';
				document.querySelector("#csrf-fetch-request").style.visibility='hidden';
				//insert a fake csrf token before firing a cheating request.
				document.querySelector('meta[name="csrf_auth_token"]').setAttribute('content','aadfds');
				xhrTesting(endpoint);
			}

		  },false);

		window.addEventListener("load", function(){
			//show xhr testing button int the testing page
			document.getElementById("csrf-fetch-request").style.visibility = "visible";
			document.getElementById("csrf-xhr-request").style.visibility = "visible";
			document.getElementById("cheating-csrf-xhr-request").style.visibility = "visible";
		});
	</script>
</body>
</html>
