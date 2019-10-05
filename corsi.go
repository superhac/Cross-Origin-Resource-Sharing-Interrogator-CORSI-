package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var version = "1.0"

//flags
var userAgent = flag.String("useragent", `Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36`, "User agent string")
var access_control_request_headers = flag.String("acrh", "x-requested-with", "The access_control_request_headers header values")
var arbitrarySubdomain = flag.String("subdomain", "test", `Arbitrary subdomain use in "Origin" header.  "test" would be test.example.com`)
var postDomainTackOn = flag.String("postDomainTackOn", "realevil.com", `value tacked on to end of "Origin".  "bad.com" would be www.example.com.bad.com`)
var preDomainPad = flag.String("preDomainPad", "realevil", `Prepended to domain name in "Origin".  "realevil" would be www.realevilexample.com`)
var access_control_request_method = flag.String("acrm", "GET", "The access_control_request_method values")
var outAllHeaders = flag.Bool("outAllHeaders", false, "Will output all headers from response")
var insecureSSL = flag.Bool("insecureSSL", false, "Ignore SSL errors.  E.g. certificate signed by unknown authority")

//terminal escape codes
const (
	ESC_clearToEndOfLine = "\033[K"
	ESC_blinkRed         = "\033[31m\033[5m"
	ESC_red              = "\033[31m"
	ESC_blinkRedClear    = "\033[25m\033[0m"
	ESC_yellow           = "\033[0;33m"
	ESC_clear            = "\033[0m"
	ESC_green            = "\033[0;32m"
	ESC_blueUnderline    = "\033[4;34m"
)

type ReqHeaders struct {
	name  string
	value string
}

func checkCORS(reqUrl string, method string, reqHeaders map[string]string, redirects *[]string) (http.Header, error) {
	var client *http.Client
	url, err := url.Parse(reqUrl)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
		return nil, err
	}

	if *insecureSSL { // Ignore invvalid certs... aka self-signed.
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
	} else { // dont ignore SSL errors
		client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}}
	}

	req, err := http.NewRequest(method, url.Scheme+"://"+url.Host+url.Path, nil)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	// set alll the request headers
	for name, value := range reqHeaders {
		req.Header.Set(name, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 200 {
		return resp.Header, nil
		//printRedirects(redirects)
	} else if resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 {
		*redirects = append(*redirects, resp.Header.Get("Location"))
		respHeader, err := checkCORS(resp.Header.Get("Location"), method, reqHeaders, redirects)
		return respHeader, err
	}
	// if it hits here something with http status code went wrong
	return nil, errors.New("Respone Code: " + strconv.Itoa(resp.StatusCode))
}

func printRedirects(redirects *[]string) {
	fmt.Print("INFO: Detected Redirect ")
	for _, value := range *redirects {
		fmt.Print(" -> " + value)
	}
	fmt.Println("")
}

func printCorsResponseHeaders(headers http.Header) {
	fmt.Println("  Returned CORS Headers")
	// CORS Response Headers
	if val, found := headers["Access-Control-Allow-Methods"]; found {
		fmt.Println("    Access-Control-Allow-Methods: ", val[0])
	}
	if val, found := headers["Access-Control-Allow-Origin"]; found {
		fmt.Println("    Access-Control-Allow-Origin:", val[0])
	}
	if val, found := headers["Access-Control-Allow-Headers"]; found {
		fmt.Println("    Access-Control-Allow-Headers: ", val[0])
	}
	if val, found := headers["Access-Control-Allow-Credentials"]; found {
		if val[0] == "true" {
			fmt.Println(ESC_yellow+"    Access-Control-Allow-Credentials: ", val[0], ESC_clear)
		} else {
			fmt.Println("    Access-Control-Allow-Credentials: ", val[0])
		}
	}
	if val, found := headers["Access-Control-Expose-Headers"]; found {
		fmt.Println("    Access-Control-Expose-Headers: ", val[0])
	}
	if val, found := headers["Access-Control-Max-Age"]; found {
		fmt.Println("    Access-Control-Max-Age: ", val[0])
	}
	if *outAllHeaders {
		fmt.Println("  All Returned Headers")
		for k, v := range headers {
			fmt.Printf("    %s -> %s\n", k, v)
		}
	}
}

// uses the same url as origin but sets the protocol to http.   Downgrade attack
func corsHttpOrigin(reqUrl string, redirects *[]string) {
	origin, err := url.Parse(reqUrl)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
		return
	}

	reqHeaders := map[string]string{
		"Origin":                         "http://" + origin.Host,
		"User-Agent":                     *userAgent,
		"Access-Control-Request-Headers": *access_control_request_headers,
		"Access-Control-Request-Method":  *access_control_request_method,
	}

	fmt.Print("* Testing HTTP Origin (Testing...)")

	headers, err := checkCORS(reqUrl, "OPTIONS", reqHeaders, redirects)
	if err != nil {
		fmt.Println("\033[11D" + ESC_red + err.Error() + ESC_clear + ")" + ESC_clearToEndOfLine)
		return
	}

	if val, found := headers["Access-Control-Allow-Origin"]; found {
		if val[0] == "http://"+origin.Host || val[0] == "*" {
			fmt.Println("\033[11D" + ESC_blinkRed + "Fail" + ESC_blinkRedClear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		} else {
			fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
		}
	} else { // NO ACAO header
		fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
	}
	printCorsResponseHeaders(headers)
}

func corsHttpsOrigin(reqUrl string, redirects *[]string) {
	origin, err := url.Parse(reqUrl)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
		return
	}

	reqHeaders := map[string]string{
		"Origin":                         "https://" + origin.Host,
		"User-Agent":                     *userAgent,
		"Access-Control-Request-Headers": *access_control_request_headers,
		"Access-Control-Request-Method":  *access_control_request_method,
	}

	fmt.Print("* Testing HTTPS Origin (Testing...)")

	headers, err := checkCORS(reqUrl, "OPTIONS", reqHeaders, redirects)
	if err != nil {
		fmt.Println("\033[11D" + ESC_red + err.Error() + ESC_clear + ")" + ESC_clearToEndOfLine)
		return
	}

	if val, found := headers["Access-Control-Allow-Origin"]; found {
		if val[0] == "*" {
			fmt.Println("\033[11D" + ESC_blinkRed + "Fail" + ESC_blinkRedClear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		} else {
			fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
		}
	} else { // NO ACAO header
		fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
	}
	printCorsResponseHeaders(headers)
}

func corsHttpsArbitrarySubDomain(reqUrl string, redirects *[]string) {
	origin, err := url.Parse(reqUrl)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
		return
	}

	reqHeaders := map[string]string{
		"Origin":                         "https://" + *arbitrarySubdomain + "." + origin.Host,
		"User-Agent":                     *userAgent,
		"Access-Control-Request-Headers": *access_control_request_headers,
		"Access-Control-Request-Method":  *access_control_request_method,
	}

	fmt.Print("* Testing HTTPS Arbitrary Subdomain [" + "https://" + *arbitrarySubdomain + "." + origin.Host + "] (Testing...)")

	headers, err := checkCORS(reqUrl, "OPTIONS", reqHeaders, redirects)
	if err != nil {
		fmt.Println("\033[11D" + ESC_red + err.Error() + ESC_clear + ")" + ESC_clearToEndOfLine)
		return
	}

	if val, found := headers["Access-Control-Allow-Origin"]; found {
		if val[0] == "https://"+*arbitrarySubdomain+"."+origin.Host || val[0] == "*" {
			fmt.Println("\033[11D" + ESC_blinkRed + "Fail" + ESC_blinkRedClear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		} else {
			fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		}
	} else { // NO ACAO header
		fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
	}
	printCorsResponseHeaders(headers)
}

func corsHttpsPostDomainTackOnBypass(reqUrl string, redirects *[]string) {
	origin, err := url.Parse(reqUrl)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
		return
	}

	reqHeaders := map[string]string{
		"Origin":                         "https://" + origin.Host + "." + *postDomainTackOn,
		"User-Agent":                     *userAgent,
		"Access-Control-Request-Headers": *access_control_request_headers,
		"Access-Control-Request-Method":  *access_control_request_method,
	}

	fmt.Print("* Testing HTTPS Post-Domain TackOn Bypass [" + "https://" + origin.Host + "." + *postDomainTackOn + "] (Testing...)")

	headers, err := checkCORS(reqUrl, "OPTIONS", reqHeaders, redirects)
	if err != nil {
		fmt.Println("\033[11D" + ESC_red + err.Error() + ESC_clear + ")" + ESC_clearToEndOfLine)
		return
	}

	if val, found := headers["Access-Control-Allow-Origin"]; found {

		if val[0] == "https://"+origin.Host+"."+*postDomainTackOn || val[0] == "*" {
			fmt.Println("\033[11D" + ESC_blinkRed + "Fail" + ESC_blinkRedClear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		} else {
			fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		}
	} else {
		fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
	}
	printCorsResponseHeaders(headers)
}

func corsHttpspreDomainPadBypass(reqUrl string, redirects *[]string) {
	origin, err := url.Parse(reqUrl)
	if err != nil {
		log.Fatal(err)
		fmt.Println(err)
		return
	}

	urlparts := strings.Split(origin.Host, ".")
	domain := urlparts[len(urlparts)-2] + "." + urlparts[len(urlparts)-1]
	domain = *preDomainPad + domain

	if len(urlparts) > 2 { // this is hack to tack on the www or whatever is in front of the domain. FIX
		domain = urlparts[0] + "." + domain
	}

	reqHeaders := map[string]string{
		"Origin":                         "https://" + domain,
		"User-Agent":                     *userAgent,
		"Access-Control-Request-Headers": *access_control_request_headers,
		"Access-Control-Request-Method":  *access_control_request_method,
	}

	fmt.Print("* Testing HTTPS Pre-Domain Bypass [" + "https://" + domain + "] (Testing...)")

	headers, err := checkCORS(reqUrl, "OPTIONS", reqHeaders, redirects)
	if err != nil {
		fmt.Println("\033[11D" + ESC_red + err.Error() + ESC_clear + ")" + ESC_clearToEndOfLine)
		return
	}

	if val, found := headers["Access-Control-Allow-Origin"]; found {
		if val[0] == "https://"+*preDomainPad+origin.Host || val[0] == "*" {
			fmt.Println("\033[11D" + ESC_blinkRed + "Fail" + ESC_blinkRedClear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		} else {
			fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		}
	} else {
		fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
	}
	printCorsResponseHeaders(headers)
}

func corsNullOrigin(reqUrl string, redirects *[]string) {
	reqHeaders := map[string]string{
		"Origin":                         "null",
		"User-Agent":                     *userAgent,
		"Access-Control-Request-Headers": *access_control_request_headers,
		"Access-Control-Request-Method":  *access_control_request_method,
	}

	fmt.Print("* Testing Null Origin [null] (Testing...)")

	headers, err := checkCORS(reqUrl, "OPTIONS", reqHeaders, redirects)
	if err != nil {
		fmt.Println("\033[11D" + ESC_red + err.Error() + ESC_clear + ")" + ESC_clearToEndOfLine)
		return
	}

	if val, found := headers["Access-Control-Allow-Origin"]; found {
		if val[0] == "null" || val[0] == "*" {
			fmt.Println("\033[11D" + ESC_blinkRed + "Fail" + ESC_blinkRedClear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		} else {
			fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
			fmt.Println("  Trigger: Access-Control-Allow-Origin: ", val[0])
		}
	} else {
		fmt.Println("\033[11D" + ESC_green + "Pass" + ESC_clear + ")" + ESC_clearToEndOfLine)
	}
	printCorsResponseHeaders(headers)
}

// override fefault flag usage text
func overrideFlagUsageText(f *flag.FlagSet) {

	f.Usage = func() {
		fmt.Println("\nCross-Origin Resource Sharing Interrogator (CORSI) v" + version + " by Superhac")
		fmt.Println("Usage: cori [OPTION]... [url]")
		flag.PrintDefaults()
	}
}

func main() {
	var redirects []string

	overrideFlagUsageText(flag.CommandLine) // override usage text

	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Printf("No url specified....")
		os.Exit(1)
	}

	//get url from cmdline
	var reqUrl = flag.Args()[0]

	fmt.Println("\nCross-Origin Resource Sharing Interrogator (CORSI) v" + version + " by Superhac\n")
	fmt.Println("Testing URL: " + reqUrl)

	//start running tests
	corsHttpOrigin(reqUrl, &redirects)

	//check if there were redirects and set to final url for efficiency
	if len(redirects) > 0 {
		printRedirects(&redirects)
		reqUrl := redirects[len(redirects)-1] // set url to last redirect
		fmt.Println("INFO: Setting URL to last redirect -> " + reqUrl)
	}
	// continue running tests
	corsHttpsOrigin(reqUrl, &redirects)
	corsHttpsArbitrarySubDomain(reqUrl, &redirects)
	corsHttpsPostDomainTackOnBypass(reqUrl, &redirects)
	corsHttpspreDomainPadBypass(reqUrl, &redirects)
	corsNullOrigin(reqUrl, &redirects)

}
