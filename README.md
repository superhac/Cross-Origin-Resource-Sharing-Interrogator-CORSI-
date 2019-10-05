# Cross-Origin-Resource-Sharing-Interrogator-CORSI-
A pentesting tool that detects improper Cross-Orgin Resource Sharing (CORS) settings that are ripe for exploitation.
### Help
<pre>
Cross-Origin Resource Sharing Interrogator (CORSI) v1.0 by Superhac
Usage: cori [OPTION]... [url]
  -acrh string
    	The access_control_request_headers header values (default "x-requested-with")
  -acrm string
    	The access_control_request_method values (default "GET")
  -insecureSSL
    	Ignore SSL errors.  E.g. certificate signed by unknown authority
  -outAllHeaders
    	Will output all headers from response
  -postDomainTackOn string
    	value tacked on to end of "Origin".  "bad.com" would be www.example.com.bad.com (default "realevil.com")
  -preDomainPad string
    	Prepended to domain name in "Origin".  "realevil" would be www.realevilexample.com (default "realevil")
  -subdomain string
    	Arbitrary subdomain use in "Origin" header.  "test" would be test.example.com (default "test")
  -useragent string
    	User agent string (default "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36")
      </pre>
### Example Output
<pre>
Cross-Origin Resource Sharing Interrogator (CORSI) v1.0 by Superhac

Testing URL: https://www.examplesite.com
* Testing HTTP Origin (Fail)
  Trigger: Access-Control-Allow-Origin:  http://www.examplesite.com
  Returned CORS Headers
    Access-Control-Allow-Methods:  GET
    Access-Control-Allow-Origin: http://www.examplesite.com
    Access-Control-Allow-Headers:  x-requested-with
    Access-Control-Allow-Credentials:  true 
* Testing HTTPS Origin (Pass)
  Returned CORS Headers
    Access-Control-Allow-Methods:  GET
    Access-Control-Allow-Origin: https://www.examplesite.com
    Access-Control-Allow-Headers:  x-requested-with
    Access-Control-Allow-Credentials:  true 
* Testing HTTPS Arbitrary Subdomain [https://test.www.examplesite.com] (Fail)
  Trigger: Access-Control-Allow-Origin:  https://test.www.examplesite.com
  Returned CORS Headers
    Access-Control-Allow-Methods:  GET
    Access-Control-Allow-Origin: https://test.www.examplesite.com
    Access-Control-Allow-Headers:  x-requested-with
    Access-Control-Allow-Credentials:  true 
* Testing HTTPS Post-Domain TackOn Bypass [https://www.examplesite.com.realevil.com] (Pass)
  Returned CORS Headers
* Testing HTTPS Pre-Domain Bypass [https://www.realevilexamplesite.com] (Pass)
  Returned CORS Headers
* Testing Null Origin [null] (Pass)
  Returned CORS Headers
</pre>
