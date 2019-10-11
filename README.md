# Cross-Origin-Resource-Sharing-Interrogator-CORSI-
A pentesting tool that detects improper Cross-Orgin Resource Sharing (CORS) settings that are ripe for exploitation.

### Preflight Requests

Conditions that activate a preflight request:
1. The requested method is **not** a [Simple Method.](https://www.w3.org/TR/cors/#simple-method) 

      If the request is not GET, HEAD or POST it will trigger a preflight request from the browser.
 
2. The requested headers are **not** [Simple  Headers.](https://www.w3.org/TR/cors/#simple-header) 

      Simple headers include : _Cache-Control_, _Content-Language_, _Content-Type_, _Expires_, _Last-Modified_ and _Pragma_.  For example if the request contains, _Access-Control-Request-Headers: authorization_ its not simple and this would trigger a preflight request.

3. The request includes a "content-type" with values **other than** _text/plain_, _application/x-www-form-urlencoded_, or _multipart/form-data_ 

      If you request a "_content-type_" of "_application/json_" for example, the browser will issue a preflight request. 

The OPTION method.


You might be asking why you need to do a preflight request when the Same Origin Policy (SOP) would protect you from cross domain requests.  Thats a good question, and personally I still don't understand why, but there is a lengthy writeup on this exact subject over at [StackOverflow](https://stackoverflow.com/questions/15381105/cors-what-is-the-motivation-behind-introducing-preflight-requests) if your interested. 


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
  -useragentrandom
    	Use random useragent string for requests

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

### References
[W3C Cross-Origin Resource Sharing Specification](https://www.w3.org/TR/cors/)
[CORS - What is the motivation behind introducing preflight requests?](https://stackoverflow.com/questions/15381105/cors-what-is-the-motivation-behind-introducing-preflight-requests)

