package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
)

/*-----------------------------------JSON FORMAT CONVERSION--------------------------------------------*/

func convertToJSON(inputFile, outputFile string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", inputFile, err)
	}

	jsonData := map[string]string{"output": string(data)}
	output, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to convert data to JSON: %v", err)
	}

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		return fmt.Errorf("failed to write JSON to file %s: %v", outputFile, err)
	}

	return nil
}

/* -------------------------------COMMAND EXECUTER AND FILE HANDLER------------------------------------- */

func runCommand(command string, args []string, outputFile string) error {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute command %s: %v\nOutput: %s", command, err, string(output))
	}

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		return fmt.Errorf("failed to write output to file %s: %v", outputFile, err)
	}

	return nil
}

/* -------------------------------BASIC INFORMATION GATHERING-------------------------------------------- */

func basicInfoGathering(domain string) {
	fmt.Println("Starting Basic Information Gathering...")
	os.MkdirAll("output/basic_info", 0755)

	// WHOIS
	fmt.Println("Whois scan running...")
	whoisFile := "output/basic_info/whois.txt"
	whoisCmd := "sh"
	whoisArgs := []string{"-c", fmt.Sprintf("whois %s | grep -iE \"^(Domain Name|Registrar|Updated Date|Creation Date|Registrar Registration Expiration Date|Registrar:|Domain Status|Name Server|DNSSEC|Registrant Name|Registrant Organization|Registrant Street|Registrant City|Registrant State|Registrant Postal Code|Registrant Country|Registrant Phone|Registrant Email|Tech Name|Tech Organization|Tech Street|Tech City|Tech State|Tech Postal Code|Tech Country|Tech Phone|Tech Email|Registrar URL|Registrar Abuse Contact Email|Registrar Abuse Contact Phone):\"", domain)}
	if err := runCommand(whoisCmd, whoisArgs, whoisFile); err != nil {
		fmt.Printf("Error running whois: %v\n", err)
	}

	whoisJSONFile := "output/basic_info/whois.json"
	if err := convertToJSON(whoisFile, whoisJSONFile); err != nil {
		fmt.Printf("Error converting whois output to JSON: %v\n", err)
	}

	// WHATWEB
	fmt.Println("Whatweb scan running...")
	whatwebFile := "output/basic_info/whatweb.json"
	whatwebCmd := "whatweb"
	whatwebArgs := []string{"-q", "--log-json", whatwebFile, "https://" + domain}
	if err := runCommand(whatwebCmd, whatwebArgs, whatwebFile); err != nil {
		fmt.Printf("Error running WhatWeb: %v\n", err)
	}

	// SHODAN
	fmt.Println("Shodan scan running...")
	shodanFile := "output/basic_info/shodan.txt"
	shodanCmd := "shodan"
	shodanArgs := []string{"domain", domain}
	if err := runCommand(shodanCmd, shodanArgs, shodanFile); err != nil {
		fmt.Printf("Error running Shodan: %v\n", err)
	}

	shodanJSONFile := "output/basic_info/shodan.json"
	if err := convertToJSON(shodanFile, shodanJSONFile); err != nil {
		fmt.Printf("Error converting Shodan output to JSON: %v\n", err)
	}
}

/* -------------------------------GOOGLE DORKING------------------------------------- */

func googleDorking(domain string) {
	fmt.Println("Starting Google Dorking...")
	os.MkdirAll("output/google_dorking", 0755)

	scriptPath := "/root/tools/Fast-Google-Dorks-Scan/FGDS.sh"
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		fmt.Printf("Dorking script not found at %s\n", scriptPath)
		return
	}

	if err := runCommand("bash", []string{scriptPath, domain}, "output/google_dorking/dorking_output.txt"); err != nil {
		fmt.Printf("Error running Google Dorking script: %v\n", err)
	}
}

/* -------------------------------SUBDOMAIN ENUMERATION------------------------------------- */

func subdomainEnumeration(domain string) {
	fmt.Println("Starting Subdomain Enumeration...")
	os.MkdirAll("output/subdomains", 0755)

	// PASSIVE SUBDOMAIN ENUMERATION
	// ASSSETFINDER
	fmt.Println("Assetfinder is running...")
	assetfinderFile := "output/subdomains/assetfinder.txt"
	assetfinderCmd := "assetfinder"
	assetfinderArgs := []string{"--subs-only", domain}
	if err := runCommand(assetfinderCmd, assetfinderArgs, assetfinderFile); err != nil {
		fmt.Printf("Error running Assetfinder: %v\n", err)
	}

	// SUBFINDER
	fmt.Println("Subfinder is running...")
	subfinderFile := "output/subdomains/subfinder.txt"
	subfinderCmd := "subfinder"
	subfinderArgs := []string{"-d", domain, "-o", subfinderFile, "-silent"}
	if err := runCommand(subfinderCmd, subfinderArgs, subfinderFile); err != nil {
		fmt.Printf("Error running Subfinder: %v\n", err)
	}

	// ACTIVE SUBDOMAIN ENUMERATION
	// FFUF
	fmt.Println("FFUF is running...")
	ffufOutputJSON := "output/subdomains/ffuf_output.json"
	ffufExtractedSubdomains := "output/subdomains/ffuf_subdomains.txt"
	ffufCmd := "ffuf"
	ffufArgs := []string{
		"-u", fmt.Sprintf("https://FUZZ.%s", domain),
		"-w", "/home/taukir/WebGuardian/Subdomain_Enumeration/.wordlists/subdomains_list.txt",
		"-H", fmt.Sprintf("Host: FUZZ.%s", domain),
		"-o", ffufOutputJSON,
		"-of", "json",
	}
	if err := runCommand(ffufCmd, ffufArgs, ""); err != nil {
		fmt.Printf("Error running ffuf: %v\n", err)
	} else {
		jqCmd := "jq"
		jqArgs := []string{"-r", ".results[].host", ffufOutputJSON}
		if err := runCommand(jqCmd, jqArgs, ffufExtractedSubdomains); err != nil {
			fmt.Printf("Error extracting subdomains with jq: %v\n", err)
		}
	}

	// GOBUSTER
	fmt.Println("GOBUSTER is running...")
	gobusterFile := "output/subdomains/gobuster_output.txt"
	gobusterExtracted := "output/subdomains/gobuster_subdomains.txt"
	gobusterCmd := "gobuster"
	gobusterArgs := []string{"dns", "--wildcard", "-d", domain, "-w", "/home/taukir/WebGuardian/Subdomain_Enumeration/.wordlists/subdomains_list.txt", "-o", gobusterFile}
	if err := runCommand(gobusterCmd, gobusterArgs, gobusterFile); err != nil {
		fmt.Printf("Error running Gobuster: %v\n", err)
	} else {
		bashCmd := "bash"
		bashArgs := []string{"-c", fmt.Sprintf("grep 'Found:' %s | awk '{print $2}' > %s", gobusterFile, gobusterExtracted)}
		if err := runCommand(bashCmd, bashArgs, gobusterExtracted); err != nil {
			fmt.Printf("Error processing output with grep and awk: %v\n", err)
		}
	}

	// COMBINING SUBDOMAINS
	combinedFile := "output/subdomains/combined_subdomains.txt"
	combineCmd := "cat"
	combineArgs := []string{assetfinderFile, subfinderFile, ffufExtractedSubdomains, gobusterExtracted}
	if err := runCommand(combineCmd, combineArgs, combinedFile); err != nil {
		fmt.Printf("Error combining subdomain lists: %v\n", err)
	}

	// SORTING SUBDOMAINS
	uniqueFile := "output/subdomains/unique_subdomains.txt"
	uniqCmd := "sort"
	uniqArgs := []string{"-u", combinedFile}
	if err := runCommand(uniqCmd, uniqArgs, uniqueFile); err != nil {
		fmt.Printf("Error removing duplicates: %v\n", err)
	}

	// FILTERING OUT SUBDOMAINS BASED ON STATUS CODE
	// ALIVE SUBDOMAINS
	fmt.Println("HTTPX is running...")
	httpxCmd1 := "httpx"
	httpxArgs1 := []string{"-l", uniqueFile, "-mc", "200,300,301,302", "-o", "output/subdomains/alive.txt", "-silent"}
	if err := runCommand(httpxCmd1, httpxArgs1, "output/subdomains/alive.txt"); err != nil {
		fmt.Printf("Error running httpx for alive subdomains: %v\n", err)
	}

	// 403 BYPASS POTENTIAL SUBDOMAINS
	httpxCmd2 := "httpx"
	httpxArgs2 := []string{"-l", uniqueFile, "-mc", "403", "-o", "output/subdomains/403bypass.txt", "-silent"}
	if err := runCommand(httpxCmd2, httpxArgs2, "output/subdomains/403bypass.txt"); err != nil {
		fmt.Printf("Error running httpx for 403 subdomains: %v\n", err)
	}

	// SUBDOMAIN TAKEOVER POTENTIAL SUBDOMAINS
	httpxCmd3 := "httpx"
	httpxArgs3 := []string{"-l", uniqueFile, "-mc", "404", "-o", "output/subdomains/subdomainTakeover.txt", "-silent"}
	if err := runCommand(httpxCmd3, httpxArgs3, "output/subdomains/subdomainTakeover.txt"); err != nil {
		fmt.Printf("Error running httpx for 404 subdomains: %v\n", err)
	}
}

/* -------------------------------WEB CRAWLING------------------------------------- */

func webCrawling() {
	fmt.Println("Crawling URLs from Alive Subdomains...")
	webCrawlingDir := "output/webcrawling"
	parameterDir := "output/parameters"
	os.MkdirAll(webCrawlingDir, 0755)
	katanaFile := webCrawlingDir + "/katana_urls.txt"
	waybackFile := webCrawlingDir + "/waybackurls.txt"
	gauFile := webCrawlingDir + "/gau_urls.txt"
	combinedUrlsFile := webCrawlingDir + "/combined_urls.txt"
	uniqueUrlsFile := webCrawlingDir + "/unique_urls.txt"
	xssFile := parameterDir + "/xss.txt"
	sqliFile := parameterDir + "/sqli.txt"
	lfiFile := parameterDir + "/lfi.txt"
	ssrfFile := parameterDir + "/ssrf.txt"
	rceFile := parameterDir + "/rce.txt"
	idorFile := parameterDir + "/idor.txt"

	// KATANA
	fmt.Println("Katana is running...")
	katanaCmd := "katana"
	katanaArgs := []string{"-u", "output/subdomains/alive.txt", "-o", katanaFile, "-silent"}
	if err := runCommand(katanaCmd, katanaArgs, katanaFile); err != nil {
		fmt.Printf("Error running Katana: %v\n", err)
	}

	// WAYBACKURLS
	fmt.Println("Waybackurls is running...")
	waybackCmd := "sh"
	waybackArgs := []string{"-c", "cat output/subdomains/alive.txt | waybackurls >> " + waybackFile}
	if err := runCommand(waybackCmd, waybackArgs, waybackFile); err != nil {
		fmt.Printf("Error running WaybackURLs: %v\n", err)
	}

	// GAU
	fmt.Println("Gau is running...")
	gauCmd := "sh"
	gauArgs := []string{"-c", "cat output/subdomains/alive.txt | gau >> " + gauFile}
	if err := runCommand(gauCmd, gauArgs, gauFile); err != nil {
		fmt.Printf("Error running GAU: %v\n", err)
	}

	// COMBINING URLS
	combineCmd := "cat"
	combineArgs := []string{katanaFile, waybackFile, gauFile}
	if err := runCommand(combineCmd, combineArgs, combinedUrlsFile); err != nil {
		fmt.Printf("Error combining URL lists: %v\n", err)
	}

	// SORTING URLS
	urldedupeCmd := "sh"
	urldedupeArgs := []string{"-c", fmt.Sprintf("cat %s | urldedupe -s >> %s", combinedUrlsFile, uniqueUrlsFile)}
	if err := runCommand(urldedupeCmd, urldedupeArgs, uniqueUrlsFile); err != nil {
		fmt.Printf("Error running urldedupe for URL deduplication: %v\n", err)
	}

	/* -------------------------------FINDING PARAMETER------------------------------------- */
	fmt.Println("Parameters Finding is running...")
	// XSS
	gfxssCmd := "gf"
	gfxssArgs := []string{"xss", uniqueUrlsFile, ">>", xssFile}
	if err := runCommand(gfxssCmd, gfxssArgs, xssFile); err != nil {
		fmt.Printf("Error running GF for XSS vulnerability testing: %v\n", err)
	}
	// SQLi
	gfsqliCmd := "gf"
	gfsqliArgs := []string{"sqli", uniqueUrlsFile, ">>", sqliFile}
	if err := runCommand(gfsqliCmd, gfsqliArgs, sqliFile); err != nil {
		fmt.Printf("Error running GF for XSS vulnerability testing: %v\n", err)
	}
	// SSRF
	gfssrfCmd := "gf"
	gfssrfArgs := []string{"ssrf", uniqueUrlsFile, ">>", ssrfFile}
	if err := runCommand(gfssrfCmd, gfssrfArgs, ssrfFile); err != nil {
		fmt.Printf("Error running GF for XSS vulnerability testing: %v\n", err)
	}
	// LFI
	gflfiCmd := "gf"
	gflfiArgs := []string{"lfi", uniqueUrlsFile, ">>", lfiFile}
	if err := runCommand(gflfiCmd, gflfiArgs, lfiFile); err != nil {
		fmt.Printf("Error running GF for XSS vulnerability testing: %v\n", err)
	}
	// RCE
	gfrceCmd := "gf"
	gfrceArgs := []string{"lfi", uniqueUrlsFile, ">>", rceFile}
	if err := runCommand(gfrceCmd, gfrceArgs, rceFile); err != nil {
		fmt.Printf("Error running GF for XSS vulnerability testing: %v\n", err)
	}
	// IDOR
	gfidorCmd := "gf"
	gfidorArgs := []string{"lfi", uniqueUrlsFile, ">>", idorFile}
	if err := runCommand(gfidorCmd, gfidorArgs, idorFile); err != nil {
		fmt.Printf("Error running GF for XSS vulnerability testing: %v\n", err)
	}
}

/* -------------------------------VULNERABILITY ASSESSMENT------------------------------------- */
func vulnerabilityDiscovery(domain string) {
	fmt.Println("Starting Vulnerability Discovery...")
	os.MkdirAll("output/vulnerabilities", 0755)

	// Nuclei
	fmt.Println("Nuclie is running...")
	uniqueFile := "output/subdomains/unique_subdomains.txt"
	nucleiFile := "output/vulnerabilities/nuclei.txt"
	nucleiCmd := "nuclei"
	nucleiArgs := []string{"-list", uniqueFile, "-o", nucleiFile}

	if err := runCommand(nucleiCmd, nucleiArgs, nucleiFile); err != nil {
		fmt.Printf("Error running Nuclei: %v\n", err)
	}

	// Dalfox
	fmt.Println("Dalfox is running...")
	xssFile := "output/parameters/xss.txt"
	dalfoxFile := "output/vulnerabilities/dalfox.txt"
	dalfoxCmd := "dalfox"
	dalfoxArgs := []string{"file", xssFile, "-o", dalfoxFile}

	if err := runCommand(dalfoxCmd, dalfoxArgs, dalfoxFile); err != nil {
		fmt.Printf("Error running Dalfox: %v\n", err)
	}

	// SQLMAP
	sqliFile := "output/parameters/sqli.txt"
	sqlmapFile := "output/vulnerabilities/sqlmap.txt"
	sqlmapCmd := "sqlmap"
	sqlmapArgs := []string{"-m", sqliFile, "--batch", ">>", sqlmapFile}

	if err := runCommand(sqlmapCmd, sqlmapArgs, sqlmapFile); err != nil {
		fmt.Printf("Error running Sqlmap: %v\n", err)
	}
}

/* -------------------------------COMPLETE SCAN------------------------------------- */
func fullScan(domain string) {
	fmt.Println("Starting Full Scan...")
	basicInfoGathering(domain)
	googleDorking(domain)
	subdomainEnumeration(domain)
	webCrawling()
	vulnerabilityDiscovery(domain)
}

/* -------------------------------MAIN FUNCTION------------------------------------- */
func main() {
	domain := flag.String("domain", "", "Specify the target domain (required)")
	basicInfo := flag.Bool("basic", false, "Run Basic Information Gathering")
	googleDork := flag.Bool("dorking", false, "Run Google Dorking")
	subdomainEnum := flag.Bool("subdomains", false, "Run Subdomain Enumeration")
	webCrawl := flag.Bool("crawling", false, "Run Web Crawling on Alive Subdomain ")
	vulnDiscovery := flag.Bool("vuln", false, "Run Vulnerability Discovery")
	fullScanFlag := flag.Bool("full", false, "Run Full Scan (basic info, dorking, subdomain enumeration, vulnerability discovery)")
	help := flag.Bool("h", false, "Print this help manual")

	flag.Parse()

	if *help || *domain == "" {
		fmt.Println(`
   ██╗    ██╗███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
   ██║    ██║██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
   ██║ █╗ ██║█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
   ██║███╗██║██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
   ╚███╔███╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
    ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  
                          Automated Web Security Sentinel Suite

    Contributer:
    Singh Divya Madan:        https://github.com/Divya-03s
    Yuvraj Singh Gohil:       https://github.com/yuvrajgohil24
    Kanishk Malav:            https://github.com/Kanishk-Malav
    Taukir Ahmed:             https://github.com/Technoob09
    Divyansh Jha:             https://github.com/Divyanshjha
   
    Flags:
    -domain       Specify the target domain (required)
    -basic        Run Basic Information Gathering
    -dorking      Run Google Dorking
    -subdomains   Run Subdomain Enumeration
    -crawling     Run Web Crawling on Alive Subdomain
    -vuln         Run Vulnerability Discovery
    -full         Run Full Scan (basic info, dorking, subdomain enumeration, vulnerability discovery)
    -h            Print this help manual

    Example Usage:
    webguardian -basic -domain example.com
    webguardian -dorking -domain example.com
    webguardian -subdomains -domain example.com
    webguardian -crawling -domain example.com
    webguardian -vuln -domain example.com
    webguardian -full -domain example.com
    webguardian -h`)
		return
	}

	if *basicInfo {
		basicInfoGathering(*domain)
	}

	if *googleDork {
		googleDorking(*domain)
	}

	if *subdomainEnum {
		subdomainEnumeration(*domain)
	}

	if *webCrawl {
		webCrawling()
	}

	if *vulnDiscovery {
		vulnerabilityDiscovery(*domain)
	}

	if *fullScanFlag {
		fullScan(*domain)
	}
}
