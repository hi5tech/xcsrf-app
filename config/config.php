<?php
/**
 * Configuration file for Hi5 XCSRF Proxy
 */
return array(
	//define variable name used to bind csrf token
	"CSRF_SESSION_VARIABLE_NAME" => "anti_csrf", 
	//define csrf token name used in user browser (DOM), e.g. meta tag, javascript var, or hidden input
	"CSRF_TOKEN_NAME" => "csrf_auth_token",
	//define a JavaScript namespace in DOM for xcsrf client to be excuted.
	"CSRF_JAVASCRIPT_NAMESPACE" => "hi5embAgent",

	//it should be the under the xcsrf folder (xcsrf app root)
	//e.g. "/var/your/path/hi5_csrf/js/xcsrf_js.js" where "/hi5_csrf" as the app root.
	"csrfJsClient" => "/js/xcsrf_js.js",
	//define xcsrf error log file. Should give apache write permission. 
	"xcsrfErrorLog" => "/log/csrf_error.log",
	
	//define a spefic target origin for same-origin check. Default as empty with $_SERVER['SERVER_NAME'] would be assigned;
	//"it could reflect the hostname supplied by the client, which can be spoofed." 
	//ref: https://www.php.net/manual/en/reserved.variables.server.php
	//the name (with no PROTOCOL prefix like https://) of the server host example: 
	//"CSRF_TARGET_ORIGIN" => "webapp.example.com",
	"CSRF_TARGET_ORIGIN" => "",
	//custom error page to be displayed when csrf authentication failed.
	//file should use absolute path, e.g.
	//"errorRedirectionPage" => "/your/path/403-forbidden.html",
	"errorRedirectionPage" => "",
	"customErrorMessage" => ""
);
