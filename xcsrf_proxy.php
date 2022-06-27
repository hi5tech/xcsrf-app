<?php
/**
 * Validating check workflow - Hi5 intercepting proxy (xcsrf_proxy) and Hi5 browser client (xcsrf_js).
 * Features: 
  Synchronization Token as Anti-CSRF Mechanism;  
  default per-session token instead of per-request token; 
  xcsrf_proxy authenticates POST requests only.
  This approach relies on JavaScript logic for injecting CSRF tokens into HTML elements or XHR requests. 
  CSRF won't protect a web application from the user, but it can help protect both web application and user from a third party 
 (as in the case of CSRF/session-hijacking) when combined with HTTPS. 
 */

define("_DEBUG_", true);
define("DEFAULT_CSRF_TOKEN_NAME", "csrf_auth_token");
define("DEFAULT_CSRF_SESSION_VARIABLE_NAME", "anti_csrf");
define("DEFAULT_CSRF_JAVASCRIPT_NAMESPACE", "hi5embAgent");
define("DEFAULT_CSRF_FETCH_FLAG_HEADER_NAME", "csrf_fetch_http2_flag");
define("DEFAULT_CSRF_XHR_HEADER_NAME", "x_csrf_auth_token"); 

class XCSRF
{
	/**
	 * Flag for Same Origin Check
	 * This will work with $_SERVER['SERVER_NAME'] as default targin origin.
	 */		
	private $sameOriginCheck = false;
	
	/**
	 * Varaible to store CSRF auth error messages
	 * ValidationError
	 * @var string
	 */	
	protected $authError = '';

	/**
	 * config file for XCSRF
	 * @xcsrfErrorLog (string) => csrf error log file
	 * @customErrorMessage (string) => custom error message for failed authentication
	 * @csrfJsClient (string) => location of the XCSRF js file
	 */
	private $config = array();
	private $validationResult = array();

	/**
	 * function to be called when CSRF authentication failed. This will usually 
	 * output an error message about the failure.
	 * performs logging and take appropriate action
	 * @param: String $file - custom page of error message by web app.
	 * @return: void
	 */
	private function csrfAuthFailedCallback($file)	{
		header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden');
		//If $file not available, fall back to the default error handle page
		if (!file_exists($file)) $file = __DIR__ ."/tpl/csrf-403-forbidden-refresh.html";
		echo file_get_contents($file);
	}

	/**
	 * function to set auth cookie 
	 * @param: void
	 * @return void
	 */
	public function reGenerateToken() {
		$token = $this->generateAuthToken();
		//set token to session for server side validation
		$_SESSION[$this->config['CSRF_TOKEN_NAME']] = $token;
		//set token to cookie for client side processing
		setcookie($this->config['CSRF_TOKEN_NAME'], 
			$token, 
			time() + $this->cookieExpiryTime);
	}
	
	/**
	 * Utility function to determine if it is the 1st request from a visitor.
	 * Since only POST requests are permitted from authorized pages, the very
	 * first request from a user it a GET request. And current implement binds
	 * a token to a session. So the first request will have not $_SESSION data
	 * attached.
	 * This function is not used directly. It is called by other public methods.
	 * @see 
	 * @param: n/a
	 * @return n/a
	 */		
	protected function isFirstGetRequest() {
		if (session_id()==='') session_start();
		return $_SERVER['REQUEST_METHOD'] === "GET" 
			&& !isset($_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['token']);
	}
	
	/**
	 * Utility function to refresh current page, after regenerate a new token
	 * This function is not used directly. It is called by other public methods.
	 * @see 
	 * @param: n/a
	 * @return n/a
	 */	
	protected function refreshThisPage() {
		header('Location: '.$_SERVER['REQUEST_URI']);
		exit;
	}
	
	/**
	 * Utility function to create random chars string of a given length (default as 10)
	 * Used to create random id for dynamically generated dom element (html id should not start with a number).
	 * @param: int $len length of the random string that should be returned in bytes.
	 * @return string
	 */
	protected function generateRandomCharString($len=10) {
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
		return substr(str_shuffle($chars), 0, $len);
	}
	
	/**
	 * Utility function for cryptographic pseudo-random key generation of a given length (default as 8)
	 * This function is not used directly. It is called by other public methods.
	 * @see generateAuthToken()
	 * @param: int $len length of the random string that should be returned in bytes.
	 * @return string
	 */
	protected function generateSecureRandomKey($len=8) {
		// PHP_VERSION_ID is defined as a number, e.g. ver 5.2.7 => 50207.
		// PHP_VERSION_ID is available as of PHP 5.2.7, if PHP version is
		// lower than that, then emulate it
		if (!defined('PHP_VERSION_ID')) {
			$version = explode('.', PHP_VERSION);
			define('PHP_VERSION_ID', ($version[0] * 10000 + $version[1] * 100 + $version[2]));
		}
		//generates a given length string of cryptographic pseudo-random bytes 
		//for cryptographic use as salts/keys, or initialization vectors.
		//if php ver<7
		if (PHP_VERSION_ID < 70000) {
			$key = bin2hex(openssl_random_pseudo_bytes($len));
		} else {
		//if php ver > 7, returns a string containing the give number of cryptographically 
		//secure random bytes then convert binary data into hexadecimal representation.
			$key = bin2hex(random_bytes($len));
		}
		return $key;
	}
	
	/**
	 * Utility function for HMAC hash generation of a given length against session_id()
	 * This function is not used directly. It is called by other public methods.
	 * This function resets any data in the $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']].
	 * @see reGenerateToken()
	 * @param: string $algo name of selected hashing algorithm supported with hash_hmac().
	 * @return string
	 */
	protected function generateAuthToken($algo='md5') {
		//generates a given length string of cryptographic pseudo-random bytes 
		//for cryptographic use as salts/keys, or initialization vectors.
		$key = $this->generateSecureRandomKey();
        // Create or overwrite the csrf entry in the seesion
        $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']] = array();
        $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['time'] = time();
        $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['secret'] = $key;
		$_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['algo'] = $algo;
        $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['sessid'] = session_id();
        $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['ip'] = $_SERVER['REMOTE_ADDR'];
		
		//create csrf token with HMAC(session_id, secret)
		//$token = hash_hmac($algo, session_id(), $key);
		$token = $this->calculateHash();
        $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['token'] = $token;
		return $token;
	}

    /**
     *  Calculates the HMAC hash of session id, with a cryptographic pseudo-random key (secret).
     *  This function is not used directly. It is called by other public CsrfToken method.
     *  @see generateAuthToken()
     *  @visibility protected
     *  @return string or NULL
     */
    protected function calculateHash() {
        if (isset($_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]))
		return hash_hmac($_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['algo'], 
						session_id(), 
						$_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['secret']);
		else return NULL;
    }

	/** 
	 * insert CSRF token with DOMDocument()
     * @see obCallback()
     * @visibility private
     * @param string $html html file/fragment as DOM input
	 * @param string $csrfName csrf toke tag name
	 * @param string $token csrf auth token
	 * @param boolean $fragment flag for html fragment, default to false as a htlm root element; if true, then 
	 *                return as fragment of a html file, by removing <doctype>, <html> and <body> tags
     * @return boolean
	 *
	 * TO-DO: before insert meta tag, check if <head> tag is available. Create one if there isn't one yet.
	 */
	private function insertTokenMetaTag($html, $csrfName, $token, $fragment=false) {
		$doc = new DOMDocument();
		$doc->loadHTML($html);
		$elements = $doc->getElementsByTagName('meta');
		//check if any csrf tokens, with same names, already exists. 
		//If so, remove all.
		$i = $elements->length-1;
		while ($i > -1) {
			//remove tags with give attribute and value
			if (trim($elements->item($i)->getAttribute('name')) === $csrfName) {
				$elements->item($i)->parentNode->removeChild($elements->item($i));
			}
			$i--;
		}
		//now create a new meta tag with token, and append it to the head tag, 
		//which is the first element of the returned DOMNodeList
		$meta = $doc->createElement('meta');
		$meta->setAttribute('name', $csrfName);
		$meta->setAttribute('content', $token);
		//get head node and append the new node
		$head = $doc->getElementsByTagName('head')->item(0);
		$head->appendChild($meta);
		if (!$fragment) {//leave <doctype> tags
			return $doc->saveHTML();
		}
		else {//remove all the 3 tags.
			return preg_replace('/^<!DOCTYPE.+?>/', '', 
					str_replace( array('<html>', '</html>', '<body>', '</body>'), 
					array('', '', '', ''), 
					$doc->saveHTML()));
		}
	}

	
	/**
	 * Rewrites <form> on the fly to add CSRF tokens to them. This will also inject JavaScript 
	 * library loader and a configuration object as well.
	 * @param: $buffer, output buffer to which all output are stored
	 * @return string, complete output buffer
	 */
	private function obCallback($buffer) {
		$token = $this->getAuthToken();
		//return as a valid html file
		$buffer = $this->insertTokenMetaTag(
					$buffer, 
					$this->config['CSRF_TOKEN_NAME'], 
					$token, 
					false);
		//seperate front/back end business logic with tpl/snippet 
		$script = file_get_contents(__DIR__ ."/js/tpl_csrf_loader_snippet.js");
		
		$search = array("{{csrf_client_file}}", 
						"{{CSRF_TOKEN_NAME}}", 
						"{{CSRF_JAVASCRIPT_NAMESPACE}}", 
						"{{CSRF_XHR_HEADER_NAME}}",
						"{{CSRF_FETCH_FLAG_HEADER_NAME}}");
		$replace = array($this->config['csrfJsClient'], 
						$this->config['CSRF_TOKEN_NAME'], 
						$this->config['CSRF_JAVASCRIPT_NAMESPACE'], 
						$this->config['CSRF_XHR_HEADER_NAME'],
						$this->config['CSRF_FETCH_FLAG_HEADER_NAME']); 
		$script = str_replace($search, $replace, $script);
		
		//load xcsrf client and add it next to the body element. We need to initialize 
		//the HTMLMFormElement interceptor before any form rendered and submitted.
		$xcsrf_client = '<script>'.file_get_contents(__DIR__ .$this->config['csrfJsClient']).'</script>';
			
	    //insert xcsrf JavaScript client loader the html file
	    $buffer = str_ireplace('<body>', '<body>' . $script . $xcsrf_client, $buffer, $count);
	    if (!$count) {
	        $buffer .= $script;
	    }
	    return $buffer;
	}

    /**
     *  Calculates the HMAC hash of session id, with a cryptographic pseudo-random key (secret).
     *  This function is not used directly. It is called by other public CsrfToken method.
     *
     *  @see generateAuthToken()
     *  @visibility protected
     *  @return string or NULL
     */
    protected function getAuthToken() {
		//start session if not yet available
		if (!session_id()) {
		    session_start();
		}
		//if this is the very first GET request from a visitor, 
		//generate a csrf token and bind it with session data.
		//In this implementation, only generate one token per session.
		if ($this->isFirstGetRequest()) { 
			$this->generateAuthToken();
		} else { 
			if (!isset($_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']])) $this->generateAuthToken();
		}
		return $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['token'];
    }
	
	/**
	 * initialize the CSRF work flow
	 *
	 * @param 
	 * @return void
	 *
	 */
	public function init() {
		//initialize app configuration
		try {
			if (!file_exists("config/config.php")) {
				throw new exception("configuration file not found for XCSRF!");	
			}
		} catch (exception $e) {
			//TO-DO
			//do-nothing now. Simply avoid showing sye error messages to end users.
		}	
		//load configuration file and properties
		$this->config = require("config/config.php");
		
		if ($this->config['CSRF_TOKEN_NAME'] == '')
			$this->config['CSRF_TOKEN_NAME'] = DEFAULT_CSRF_TOKEN_NAME;	
		if ($this->config['CSRF_SESSION_VARIABLE_NAME'] == '')
			$this->config['CSRF_SESSION_VARIABLE_NAME'] = DEFAULT_CSRF_SESSION_VARIABLE_NAME;	
		if ($this->config['CSRF_JAVASCRIPT_NAMESPACE'] == '')
			$this->config['CSRF_JAVASCRIPT_NAMESPACE'] = DEFAULT_CSRF_JAVASCRIPT_NAMESPACE;	
		if ($this->config['CSRF_TARGET_ORIGIN'] == '')
			$this->config['CSRF_TARGET_ORIGIN'] = $_SERVER['SERVER_NAME'];
		//System preset values
		$this->config['CSRF_XHR_HEADER_NAME'] = DEFAULT_CSRF_XHR_HEADER_NAME;
		$this->config['CSRF_FETCH_FLAG_HEADER_NAME'] = DEFAULT_CSRF_FETCH_FLAG_HEADER_NAME;

		//start session if not yet available
		if (session_id() == '') {
		    session_start();
		}

		//if this is the very first GET request from a visitor, 
		//generate a csrf token and bind it with session data.
		//In this implementation, only generate one token per session.
		if ($this->isFirstGetRequest()) { 
			$this->generateAuthToken();
		}
		
		//validate the incoming request
		$auth = $this->validateCsrfToken();
		//xcsrf_proxy will only intercept if: 1. this is a get request; 2. it is a post request and csrf validation failed.
		if ($_SERVER['REQUEST_METHOD'] === 'GET' || !$auth)
			ob_start(array($this, "obCallback"));
	} //init()	

	/**
	 * validateCsrfToken() validate HTTP requests against headers and CSRF token.
	 *
	 * @param N/A
	 * @return boolean - true on success
	 */
	private function validateCsrfToken() {
		//we validate POST request here!
		if ($_SERVER['REQUEST_METHOD'] === 'GET') return true;
		$auth = false;
		//flag for ajax call (fetch & xhr)
		$isAjaxCall = false; 
		/* STEP 1: Verifying Same Origin with Standard Headers, as recommended by OWASP. */
		//In production, web applications should check customer header instead.!!!
		/***NOTE: It is not safe to rely on both values in security-dependent contexts.***/
		/*should avoid partern as "origin.com.attacker.com"!!*/
		$originCheck = false;
	
		//Try to get the source from the "Origin" header
		if (isset($_SERVER['HTTP_ORIGIN'])) {
			//If empty then fallback on "Referer" header
			if (isset($_SERVER['HTTP_REFERER'])) {
				$incomingOrigin = $_SERVER['HTTP_ORIGIN'];
				$targetOrigin = $this->config['CSRF_TARGET_ORIGIN'];

				$this->validationResult['Origin_incoming'] = $incomingOrigin;
				$this->validationResult['Origin_target'] = $targetOrigin;
				$this->validationResult['Referer'] = $_SERVER['HTTP_REFERER'];
				$this->validationResult['SERVER_NAME'] = $_SERVER['SERVER_NAME'];		
				$isSameOrigin = function_exists('str_ends_with') ? 
								str_ends_with($incomingOrigin, $targetOrigin) : 
								substr($incomingOrigin, -strlen($targetOrigin))===$targetOrigin;
				if ($isSameOrigin) { 
					$originCheck = true;
				} else {//NOT FOUND!
					//return false;
					$this->validationResult['origin_check_error'] 
						= "CSRF detected invalid Origin header: incoming-origin = $incomingOrigin agaist target-origin = $targetOrigin";
				}		
			} else {
				//return false;
				$this->validationResult['origin_check_error']
					= "validateCsrfToken(): REFERER request header is absent/empty.";
			}
		} else {
				//ORIGIN request header is empty then we trace the event and we block the request
				//return false;
				$this->validationResult['origin_check_error']
					= "validateCsrfToken(): ORIGIN request header is absent/empty.";
		}
		
		/* STEP 2: Verifying CSRF token */
		
		// If it's a POST, check the token matches: if (!empty($_POST))
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			$isFetchCall = $this->getApacheHeaderValue($this->config['CSRF_FETCH_FLAG_HEADER_NAME'], true);
			$token = $this->getHttpHeaderValue($this->config['CSRF_XHR_HEADER_NAME'], $isFetchCall);
			if ($token===null) { //form submit
				$token = $_POST[$this->config['CSRF_TOKEN_NAME']];
				$this->validationResult['calling_method'] = 'form-submit(HTMLFormElement)';
				$this->validationResult['form_submit_trigger'] = isset($_POST['csrfFormElementTrigger'])?$_POST['csrfFormElementTrigger']:"javascript_method";
			} else { //ajax call with Fetch API or XHR
				$isAjaxCall = true;
				if ($isFetchCall)
					$this->validationResult['calling_method'] = 'ajax_fetch';
				else 
					$this->validationResult['calling_method'] = 'ajax_xhr';
			}
			//check if the CSRF token is present in the requeest.
			if (isset($token)) {	
				//check if csrf information is present in the session
				if (isset($_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']])) {
					//log csrf session data
					$this->validationResult['sess-data'] = $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']];
					//verify that token in request and the one with session data are the same
					if ($token
						=== $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['token']) {
						//check client ip, optional.
						if ($_SERVER['REMOTE_ADDR']=== $_SESSION[$this->config['CSRF_SESSION_VARIABLE_NAME']]['ip']) {
							//request authenticated! Strip off the token in request and in session data ONLY IF 
							//it is NOT a xmlHttpRequest, get back to web app.

							$auth = true;
						} else { $this->authError = 'Client IP Did Not Match.';}
					} else { $this->authError = 'Tokens Did Not Match.';}
				} else { $this->authError = 'No CSRF Token Bound with Session Data.';}
			} else { $this->authError = 'No CSRF Token included in Request.';}
		} else { $this->authError = 'Not a POST Request.';}
		
		//if (!$auth) delete cookies
		//delete token from $_POST and $_REQUEST arrays
		unset($_POST[$this->config['CSRF_TOKEN_NAME']]);
		unset($_REQUEST[$this->config['CSRF_TOKEN_NAME']]);
			
		$this->validationResult['error_message'] = $this->authError;
		$this->validationResult['result'] = $auth?'authenticated':'failed';
		$this->validationResult['request_method'] = $_SERVER['REQUEST_METHOD'];
		$this->validationResult['target-script'] = debug_backtrace()[1]['file'];
		if (isset($token)) 
			$this->validationResult['token_in_request'] = $token;
		$this->validationResult['User-Agent'] = $_SERVER['HTTP_USER_AGENT'];

		if (_DEBUG_) {
			if (defined('APP_DOCUMENT_ROOT')) {
				$errorlog = APP_DOCUMENT_ROOT."/log/csrf_error.log";			
			}//else defined('APP_DOCUMENT_ROOT') or define('APP_DOCUMENT_ROOT', 'defaultValue');
			else $errorlog = __DIR__.$this->config['xcsrfErrorLog'];
			file_put_contents($errorlog, "\n\r dump headers: ".print_r(apache_request_headers(),true), FILE_APPEND | LOCK_EX);	
			file_put_contents($errorlog, "\n\r authResult: ".print_r($this->validationResult,true), FILE_APPEND | LOCK_EX);
		}

		//output an error message about the csrf authentication failure.
		if (!$auth) {
			if ($isAjaxCall) {
				//return header/json msg
				//we send csrf anthentication failure status in header.
				header($_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden');
				header('csrf-auth-status: Failed');
				//retrieve standalone popup window snippet
				$popup = file_get_contents(__DIR__."/tpl/tpl_csrf_auth_failed_popup_snippet.html");
				$popup = str_replace('{{csrf-auth-failed-popup}}','thisisatesting',$popup);
				$arr = array (
							"csrf-auth-status"  => "Failed",
							"action" => "Try again",
							"popup" => trim($popup),
							"error_code"   => "403 Forbidden"
						);
				echo json_encode($arr);
			} else {
				$this->csrfAuthFailedCallback($this->config['errorRedirectionPage']);
			}
			exit;
		}
		return $auth;
	} //validateCsrfToken()

    /**
     *  This method returns CSRF token authentication errors. Null as default value.
     *
     *  @see 
     *  @visibility public
     *  @return string
     */
    public function getAuthError() {
        return $this->authError;
    }	

    /**
     *  This public method returns CSRF authentication results. 
     *
     *  @see 
     *  @visibility public
     *  @return string
     */
    public function getAuthResults() {
        $results = array();
		$results['calling_method'] = $this->validationResult['calling_method'];
		$results['request_method'] = $this->validationResult['request_method'];
		$results['error_message'] = $this->validationResult['error_message'];
		$results['csrf-auth-status'] = $this->validationResult['result'];
		return $results;
    }	

	/**
	 * This function handles custom headers, e.g. X-Requested-With mainly used to identify Ajax requests.
	 * Headers will not always be present in $_SERVER, should always have the header prefixed with "X-".
	 * Note that 'X-Requested_With' or 'X_Requested_With' will be likely ignored in $_SERVER.
	 * Alternatively, use apache_request_headers() will be more safe, and header name will be same as that
	 * in the request rather than "has HTTP_ prepended to give the meta-variable name", as a web server
	 * may comply with RFC3875(see@4.1.18).  -- "The HTTP header field name is converted to upper case,
	 * has all occurrences of - replaced with _ and has HTTP_ prepended to give the meta-variable name."
	 *      E.x $headers = apache_request_headers(); echo $headers['X_Requested_With'];
	 *
	 * @param string $key
	 * @return mixed; if not found, return null.
	 * use: $header_x_requested_with = getHeaderInSever('X-Requested-With');
	 */
	protected function getHeaderInSever($key) {
		// Expanded for clarity.
		$key = str_replace('-', '_', $key);
		$key = 'HTTP_'.strtoupper($key);
		return $_SERVER[$key] ?? null;
	}
	
	/**
	 * Retrieve a custom header value of a given header name, via apache_request_header()
	 * see details @ getHeaderInSever($key)
	 * @param string $key
	 * @param bool $http2 - flag to use lower case header name search for modern 
	 *                      browsers complying with HTTP/2(see RFC 7540#section-8.1.2)
	 * @return mixed; if not found, return null.
	 * NOTE: $http2 flag should be used strictly with Fetch(), NOT xmlHttpRequest.
	 */
	protected function getApacheHeaderValue($key, $http2=false) {
		$headers = apache_request_headers(); 
		//for modern browsers complying with HTTP/2, testing with Fetch() in 
		//Google Chrome Version 100.0.4896.88 (Official Build) (64-bit)
		//When HTTP2 flag is true, make a second attemp with lowercased 
		//key search, if only if the original key failed!!
		if ($http2 && !array_key_exists($key, $headers)) {
			$key = strtolower($key);
		}
		return $headers[$key] ?? null;
	}
	
	/**
	 * NOTE: Fetch API will convert header names to lower-case, but xmlHttpRequest does not. 
	 * This will confuse apache_request_headers() on the server side.
	 * Due to the fact that HTTP/2 actually enforce lowercase header (see @RFC 7540#section-8.1.2)
	 * The specifical purpose of getHttpHeaderValue($key) is to avoid implementing the 
	 * DEFAULT_CSRF_XHR_HEADER_NAME field in lowercase. See@Doc above!
	 *
	 * NOTE2: The reason that we prefer testing apache_request_headers() first is because this method
	 * will not ignore a header without prefixed "X-" in the name, while $_SERVER does ignore such headers!
	 *
	 * @param string $key - request header name
	 * @return mixed; if not found, return NULL.
	 * TODO - test if $key='';
	 */
	protected function getHttpHeaderValue($key, $http2=false) {
		$val = $this->getApacheHeaderValue($key, $http2);
		if ($val===null) $val = $this->getHeaderInSever($key);
		return $val;
	}

} //END class XCSRF
