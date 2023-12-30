package src

import (
	"fmt"
	. "github.com/k4s/phantomgo"
	"github.com/microcosm-cc/bluemonday"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

type Whois struct {
	DomainName 			string
	RegistrationDate 	string
	UpdateDate 			string
	ExpireDate 			string
	Registrar 			string
	Registrant 			string
	RegistrantCountry 	string
	IP 					[]string
	MXRecord 			[]string

}


// GetWhois makes request to viewdns.info/whois/ service
// and parses response to extract current whois information.
func GetWhois(target string, output string) {
	var whois *Whois
	baseURL := "https://viewdns.info/whois/?domain="
	targetURL := baseURL + target

	splitStr := strings.Split(target, ".")
	toplevelDomain := splitStr[len(splitStr)-1]

	// Set up http client and make request.
	httpClient := &http.Client{}
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("Content-Type", "text/html; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	html, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}


	switch toplevelDomain {
	case "ru":
		whois = RuTemplate(html, target)
	case "ua":
		whois = UaTemplate(html, target)
	case "com":
		whois = ComTemplate(html, target)
	case "eu":
		whois = EuTemplate(html, target)
	case "by":
		whois = ByTemplate(html, target)
	default:
		whois = CommonTemplate(html, target)
	}

	switch output {
	case "cmd":
		CmdFull(whois)
	case "raw":
		CmdRaw(whois)
	case "doc":
		Docx(whois)

	}

}


// GetWhoisHistoryFree makes request to osint.sh/whoishistory/ free service
// and parses response to extract whois history information.
func GetWhoisHistoryFree (target string, position int) (string, error) {

	baseURL := "https://osint.sh/whoishistory/"
	postBody := "domain=" + target

	// osint.sh requires JS so here we use PhantomJS web browser to make request.
	p := &Param{
		Method:       "POST",
		Url:          baseURL,
		Header:       http.Header{"User-Agent": []string{`Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0`}},
		UsePhantomJS: true,
		PostBody:     postBody,
	}
	browser := NewPhantom()
	resp, err := browser.Download(p)
	if err != nil {
		return "", err
	}

	html, err := ioutil.ReadAll(resp.Body)
	if err !=nil {
		return "", err
	}

	re := regexp.MustCompile(`<div class="col-lg-8">[\s\S]*</div>`)
	submatchall := re.FindAllStringSubmatch(string(html), -1)

	// We use StripTagsPolicy to cut off all HTML tags.
	stripPolicy := bluemonday.StripTagsPolicy()

	// Here we beautify what we've got from whois history
	// and place it into one slice.
	// The replace with # symbol is for cases when there are empty lines in required data
	// so in next working with replaced strings it will not be messed up.
	replacer := strings.NewReplacer("Update Date", "#", "Expiry Date", "#", "Create Date", "",
		"Owner", "#", "Address", "#", "Email", "#", "Phone", "#", "Name Server", "#",
	)
	for n, element := range submatchall {
		s := strings.Split(element[n], "</div>")
		for _, r := range s[:1] {
			counter := 0
			sanitizedStrings := stripPolicy.Sanitize(r)
			cs := replacer.Replace(sanitizedStrings)
			cs = strings.TrimSpace(cs)
			ss := strings.Split(cs, "\n")
			for _, str := range ss {
				str = strings.TrimSpace(str)
				if (str == "") || (strings.Contains(str, "Crafted")) {
					continue
				} else {
					if strings.Contains(str, "#") {
						str = strings.Trim(str, "#")
					}
					switch counter {
					case 0:		// Returns RECORD DATING FROM
						if counter == position {
							return str, nil
						}
					case 1: 	// Returns Update Date
						if counter == position {
							return str, nil
						}
					case 2:		// Returns Create Date
						if counter == position {
							return str, nil
						}
					case 3:		// Returns Expire Date
						if counter == position {
							return str, nil
						}
					case 4:		// Returns Registrant
						if counter == position {
							return str, nil
						}
					case 5:		// Returns Registrant Address
						if counter == position {
							return str, nil
						}
					case 6:		// Returns Registrant Email
						if counter == position {
							return str, nil
						}
					case 7:		// Returns Registrant Phone
						if counter == position {
							return str, nil
						}
					case 8:		// Return Name Server
						if counter == position {
							return str, nil
						}
					}
					counter++
				}
			}
		}
	}

	return "", nil

}