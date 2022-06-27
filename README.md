A simple, zero-management CSRF authentication PHP framework that can be integrated with any web application. 
It features cookieless solution to achieve GDPR compliance, and provides CSRF authentication out of the box.

This tiny project was implemented and adapted from a research paper "A server- and browser-transparent CSRF defense 
for web 2.0 applications" by Riccardo Pelizzi and R. Sekar (http://seclab.cs.sunysb.edu/seclab/pubs/acsac11.pdf). 
Other reference also includes "Securing Frame Communication in Browsers" by A. Barth, C. Jackson, and J.C. Mitchell
(https://seclab.stanford.edu/websec/csrf/csrf.pdf).

CSRF protection secures web applications for:

	* HTML forms with POST
	* Dynamically generated forms
	* JavaScript submit with HTMLFormElement.submit() method or HTML submit with HTMLFormElement onsubmit event
	* Ajax Requests with both XHR and Fetch

***************
Usage example:
***************

On the top of your php file, include the library and call the initiating function:
	<?php
		/** enable xcsrf authentication block **/
		include_once "../xcsrf_proxy.php";
		//Initialise CSRFGuard library
		$xcsrf = new XCSRF();
		$auth = $xcsrf->init();
		/** end enable xcsrf authentication **/
	?>
	
More details see testing scripts in /testing_scripts folder.
