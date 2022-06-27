<?php
	/** enable xcsrf authentication block **/
	//load xcsrf lib
	include_once "../xcsrf_proxy.php";
	//initialize xcsrf lib
	$xcsrf = new XCSRF();
	$auth = $xcsrf->init();
	/** end enable xcsrf authentication **/

	if ($_SERVER['REQUEST_METHOD'] === 'POST') {
		if ($_POST['csrfFormElementTrigger']==='onsubmit_event' 
			|| $_POST['csrfFormElementTrigger']==='javascript_method') {
			$delay = 5; // delay in seconds
			//header("Refresh: $delay;"); 
			echo("<meta http-equiv='refresh' content='$delay'>"); //Refresh by HTTP 'meta'
			echo $_POST['csrfFormElementTrigger']. " - form successfully received! Page will be refresh in $delay seconds.<br><br>";
		}
		var_dump($_POST);
		exit;
	}
?>

<!DOCTYPE html>
<head>
	<title>CSRF Proof Of Concept Testing</title>
	<style>
		.errorbox {
			padding: 10px;
			margin: 5px 0px;
			border: 1px solid green;
			background-color: greenyellow;
			
			opacity: 1;
			transition: opacity 3s;
		}
		.errorbox-bgrn {
			padding: 10px;
			margin: 5px 0px;
			border: 1px solid green;
			background-color: greenyellow;
		}
		.errorbox-red {
			padding: 10px;
			margin: 5px 0px;
			border: 1px solid green;
			background-color: red;
		}
		.errorbox-base {
			opacity: 0;
			transition: opacity 3s;
		}
		.fake-token-warning {
			visibility: hidden;
			color: red;
			background-color: yellow;
		}
	</style>
</head>
<body>
	<h3> Hi5_CSRF Testing </h3>
	<div>
		<span class="fake-token-warning">CSRF token replaced with a fake token.</span>
		<div>
		<button id="gen-fake-token">Cheating with fake token</button>
		<button id="restore-token">Restore CSRF token</button>
		</div>
	
	</div>
	<fieldset>
		<legend>cheating form - will be failed</legend>
		<span class="fake-token-warning">replace token before form submit with HTMLFormElement onsubmit event (html form submit with Enter/button)</span>
		<form id="cheating-form" method="POST">
			<input type="text" name="frm-data" value="frm-value" />
			<input type="submit" id="frm3btn" value="submit" />
			<div id="cheating-form-error" class="errorbox-base"></div>
		</form>
		<hr>
		<label>Testing javascript HTMLFormElement.submit() method: </label>
		<button id="js-submit">Try JavaScript Submit</button>
	</fieldset>
	
	<h3>Dynamic form testing</h3>
	<fieldset id="fieldset">
		<legend id="legend">Click "Add new form" button to create/csrf test forms on the fly</legend>
		<div id="placeholder">
			<form id="template" method="post" action="">
				<fieldset>
				<legend>static form example</legend>
				<p>Item <input type ="text" size="25" name="prof_item" /><br /></p>
				<p>Description <input type ="text" size="25" name="prof_description" /><br /></p>
				<!--p>Enlargement <label for="enlargement"></label></p>
				<p><textarea name="prof_enlargement" cols="71" rows="5" id=""></textarea></p-->
				<input type="submit" value="submit" name="xxsubmit">
				</fieldset>
			</form> <!-- template -->
		</div> <!-- placeholder -->
		<p><button type="button" name="Submit" onclick="addForm();">Add new form</button></p>
	</fieldset>
	<script>
		var _counter = 0;
		function addForm() {
			_counter++;
			var frmClone = document.getElementById("template").cloneNode(true);
			frmClone.id += (_counter + "");
			document.getElementById("placeholder").appendChild(frmClone);
		}
	</script>


	<!-- try again button to fresh this page -->
	<script type="template" data-role="try-again-button">
		<form method="GET" action="" />
		  <input type="submit" value="Try again" />
		</form>
	</script>

	<script >
		var config = window.config || {};
		//replace the csrf token with a random fake token.
		function cheatingWithFakeToken() {
			var fake_token = (Math.random() + 1).toString(36).substring(2);
			document.querySelector('meta[name=csrf_auth_token]').setAttribute('content', fake_token);
			document.querySelectorAll('.fake-token-warning').forEach(function(el){el.style.visibility='visible';});
		}
		window.addEventListener('load', function(){
			//set csrf toke in js variable
			config.originalToken = document.querySelector('meta[name=csrf_auth_token]').getAttribute('content');		
		});
		(function () {
		  document.body.addEventListener('click', function(e){
			if (e.target.id==="js-submit") {			
				cheatingForm();
			}
			if (e.target.id==="gen-fake-token") {			
				cheatingWithFakeToken();
			}
			if (e.target.id==="restore-token") {	
				document.querySelector('meta[name=csrf_auth_token]').setAttribute('content', config.originalToken);
				document.querySelectorAll('.fake-token-warning').forEach(function(el){el.style.visibility='hidden';});
			}
		  });
		  function cheatingForm() {
				// Returns a random integer from 0 to 9:
				var delay=5000; //5s
				var n = Math.floor(Math.random() * 10);
				if (n % 2 == 0) { // if it is even then cheating form
					//replace the csrf token with a random fake token.
					var fake_token = (Math.random() + 1).toString(36).substring(2);
					document.querySelector('meta[name=csrf_auth_token]').setAttribute('content', fake_token);	
					document.querySelector("#cheating-form-error").innerHTML = 
					'<div class="errorbox-red"><b>cheated and overrode the CSRF token later in the form, with fake token <'
					+fake_token+'>, This form fails CSRF validation.</b></div>';
					setTimeout(() => {
						document.querySelector("#cheating-form").submit();
					}, delay)
				} else {
					setTimeout(() => {//delay 5s
						document.querySelector("#cheating-form").submit();
					}, delay)
					document.querySelector("#cheating-form-error").innerHTML = '<div class="errorbox-bgrn"><b>This form will pass CSRF validation with the real token. This page will be refreshed in '+delay/1000+'s.</b></div>';
				}
				document.querySelector("#cheating-form-error").style.opacity=1;
				
				//insert "try again" button
				var btn = document.createElement("div");
				btn.innerHTML = document.querySelector('script[type="template"][data-role="try-again-button"]').innerText;
				document.querySelector("#cheating-form-error").appendChild(btn);
		  }
		})();
	</script>
</body>
</html>
