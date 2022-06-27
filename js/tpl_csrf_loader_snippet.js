<script type="application/json" data-role="setting-args" data-module-name="Shared/cofig.mod">
	{"CSRF_JAVASCRIPT_NAMESPACE":"{{CSRF_JAVASCRIPT_NAMESPACE}}","CSRF_TOKEN_NAME":"{{CSRF_TOKEN_NAME}}","CSRF_XHR_HEADER_NAME":"{{CSRF_XHR_HEADER_NAME}}","CSRF_FETCH_FLAG_HEADER_NAME":"{{CSRF_FETCH_FLAG_HEADER_NAME}}"}
</script>
<script>
	/**
	 *  Hi5 xcsrf client (xcsrf_js) loader (snippet)
	 *  This snippet will be loaded into DOM and self-invoke to load xcsrf_js client
	 *  @see xcsrf_proxy@server
	 */
	 
	//check to evaluate if variable/namespace exists in the global namespace. If already 
	//defined, use that instance, otherwise assign a new object literal to variable/namespace.
	var HI5_XCSRF_NAMESPACE_CLONE = window.HI5_XCSRF_NAMESPACE_CLONE || {},
	    {{CSRF_JAVASCRIPT_NAMESPACE}} = window.{{CSRF_JAVASCRIPT_NAMESPACE}} || {};
	HI5_XCSRF_NAMESPACE_CLONE = {{CSRF_JAVASCRIPT_NAMESPACE}};
	(function(module,undefined) {
		//private properties / methods
		
		//get system config object.
		function getConfigObj() {
			const sel = 'script[type="application/json"][data-role="setting-args"][data-module-name="Shared/cofig.mod"]';
			var jstr = document.querySelector(sel).innerText;
			return JSON.parse(jstr);
		}
		//public methods and properties 
		module.config = getConfigObj();
	})(HI5_XCSRF_NAMESPACE_CLONE);
</script>

