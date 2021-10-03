package cmd

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/biter777/countries"
	. "github.com/k4s/phantomgo"
	"github.com/microcosm-cc/bluemonday"
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

var(

	dn = []string{"Domain Name:", "domain:"}
	cr = []string{"Creation Date:", "created:"}
	ud = []string{"Updated Date:", "updated:"}
	ed = []string{"Registry Expiry Date:", "Registrar Registration Expiration Date:"}
	rr = []string{"Registrar:", "registrar:", "Registrar Name:" }
	rt = []string{"Registrant Name:", "registrant:", "owner:"}
	rtc = []string{"Registrant Country:" }

)

// GetWhois makes request to viewdns.info/whois/ service
// and parses response to extract current whois information.
func GetWhois(target string, output string) {


	var wasThereAlready bool
	var wi = new(Whois)
	baseURL := "https://viewdns.info/whois/?domain="
	targetURL := baseURL + target

	// Set up http client and make request.
	httpClient := &http.Client{}
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("Content-Type", "text/html; charset=UTF-8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	re := regexp.MustCompile(`<br.*?>(.*)<br>`)
	submatchall := re.FindAllStringSubmatch(string(body), -1)

	for _, element := range submatchall {
		s := strings.Split(element[1], "<br>")
		for _, str := range s[8:] {
			if strings.Contains(str, "For more information on Whois") {
				break
			}
			//if strings.Contains(str, dn[0]) || strings.Contains(str, dn[1]) {
			//	value := trimmer(str, dn)
			//	wi.DomainName = strings.ToLower(value)
			//}
			if strings.Contains(str, cr[0]) || strings.Contains(str, cr[1]){
				value := trimmer(str, cr)
				value = parseDate(value)
				wi.RegistrationDate = value

			}
			if strings.Contains(str, ud[0]) || strings.Contains(str, ud[1]){
				value := trimmer(str, ud)
				value = parseDate(value)
				wi.UpdateDate = value
			}
			if strings.Contains(str, ed[0]) || strings.Contains(str, ed[1]) {
				value := trimmer(str, ed)
				value = strings.Replace(value, ".0Z", " (UTC)", 1)
				value = strings.Replace(value, "T", " ", 1)
				wi.ExpireDate = value
			}
			if strings.Contains(str, rr[0]) || strings.Contains(str, rr[1]) || strings.Contains(str, rr[2]) {
				value := trimmer(str, rr)
				value = strings.TrimPrefix(value, " ")
				wi.Registrar = value
			}
			if strings.Contains(str, rt[0]) || strings.Contains(str, rt[1]) || strings.Contains(str, rt[2]) {
				value := trimmer(str, rt)
				// If the current information about registrant is hidden
				// then check whois history to see if there is some additional information
				if strings.Contains(value,"Privacy") {
					value, err = getWhoisHistoryFree(target, 4)
					if err != nil {
						fmt.Println(err)
					}
					wi.Registrant = value
				}
				wi.Registrant = value
			}
			if strings.Contains(str, rtc[0]) {
				value := strings.Replace(str, rtc[0],"", 1)
				value = strings.TrimSpace(value)
				country := countries.ByName(value)
				wi.RegistrantCountry = country.StringRus()
			}
			// If there is no strings in current whois information like "Registrant Name:", "registrant:", "owner:"
			// then we need to check whois history information.
			if !wasThereAlready {
				if !strings.Contains(string(body), rt[0]) || !strings.Contains(string(body), rt[1]) || !strings.Contains(string(body), rt[2]) {
					value, err := getWhoisHistoryFree(target, 4)
					if err != nil {
						fmt.Println(err)
					}
					wi.Registrant = value
					wasThereAlready = true
				}
			}
		}
	}

	wi.DomainName = target

	// If even in whois history information about registrant is hidden
	// then set the string that tells about it.
	if wi.Registrant == "" {
		wi.Registrant = "Информация скрыта"
	}

	var ipSlice []string
	ips, err := net.LookupIP(target)
	if err != nil {
		fmt.Println(err)
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipSlice = append(ipSlice, ipv4.String())
		}
	}
	wi.IP = ipSlice


	var mxRecords []string
	mxs, err := net.LookupMX(target)
	if err != nil {
		fmt.Println(err)
	}
	for _, mx := range mxs {
		if mxRecord := mx.Host; mxRecord != "" {
			value := strings.TrimSuffix(mxRecord, ".")
			mxRecords = append(mxRecords, value)
		}
	}
	// If there is no information about mx
	// then we just set "-" for more visibility.
	if mxRecords == nil {
		mxRecords = append(mxRecords, "-")
	}
	wi.MXRecord = mxRecords


	// Create required output
	switch output {
	case "cmd":
		fmt.Printf("Доменное имя \t\t\t\t\t\t\t%s\n", wi.DomainName)
		fmt.Printf("Дата регистрации \t\t\t\t\t\t%s\n", wi.RegistrationDate)
		fmt.Printf("Дата обновления \t\t\t\t\t\t%s\n", wi.UpdateDate )
		fmt.Printf("Дата истечения срока действия \t\t\t\t\t%s\n", wi.ExpireDate)
		fmt.Printf("Регистратор доменного имени \t\t\t\t\t%s\n", wi.Registrar)
		fmt.Printf("Регистрант доменного имени \t\t\t\t\t%s\n", wi.Registrant)
		fmt.Printf("Страна регистранта \t\t\t\t\t\t%s\n", wi.RegistrantCountry)
		fmt.Printf("IP-адрес \t\t\t\t\t\t\t%s\n", strings.Join(wi.IP, ", "))
		fmt.Printf("MX-запись \t\t\t\t\t\t\t%s\n", strings.Join(wi.MXRecord, ", "))
	case "doc":
		dat, err := os.ReadFile("config.txt")
		if err != nil {
			fmt.Println(err)
		}
		err = docOutput(wi, string(dat))
		if err != nil {
			fmt.Printf("[-] Unable to create .docx file: %s", err)
		} else {
			fmt.Printf("[+] %s.docx created successfully!", wi.DomainName )
		}
	case "raw":
		fmt.Printf("%s\n", wi.DomainName)
		fmt.Printf("%s\n", wi.RegistrationDate)
		fmt.Printf("%s\n", wi.UpdateDate )
		fmt.Printf("%s\n", wi.ExpireDate)
		fmt.Printf("%s\n", wi.Registrar)
		fmt.Printf("%s\n", wi.Registrant)
		fmt.Printf("%s\n", wi.RegistrantCountry)
		fmt.Printf("%s\n", strings.Join(wi.IP, ", "))
		fmt.Printf("%s\n", strings.Join(wi.MXRecord, ", "))
	default:
		fmt.Println("UNKNOWN OUTPUT FORMAT")
	}

}

func trimmer(str string, slice []string) string{

	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.Trim(str, substr)
			return value
		}
	}

	return ""
}

// parseDate parses 0Z timezone to +3 UTC
func parseDate (date string) string {
	var slice []string
	date = strings.Trim(date, ".0Z")
	raw := strings.Split(date, "T")
	slice = append(slice, raw[0])
	rawTime := strings.Split(raw[1], ":")
	rh, _ := strconv.Atoi(rawTime[0])
	h := rh + 3
	hToInt := strconv.Itoa(h)
	time := hToInt + ":" + rawTime[1] + ":" + rawTime[2] + " (UTC)"
	slice = append(slice, time)
	utcDate := strings.Join(slice, " ")

	return utcDate

}

// getWhoisHistoryFree makes request to osint.sh/whoishistory/ free service
// and parses response to extract whois history information.
func getWhoisHistoryFree (target string, position int) (string, error) {

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

	body, err := ioutil.ReadAll(resp.Body)
	if err !=nil {
		return "", err
	}

	re := regexp.MustCompile(`<div class="col-lg-8">[\s\S]*</div>`)
	submatchall := re.FindAllStringSubmatch(string(body), -1)

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