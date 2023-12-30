package src

import (
	"fmt"
	"github.com/biter777/countries"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var(

	crCommon  = []string{"Creation Date:"}
	udCommon  = []string{"Updated Date:", "Last Modified:"}
	edCommon  = []string{"Registry Expiry Date:", "Registrar Registration Expiration Date:"}
	rrCommon  = []string{"Registrar:", "Registrar Name:" }
	rtCommon  = []string{"Registrant Name:"}
	rtcCommon = []string{"Registrant Country:" }

)

/*
	There is placed template parser for sites with .online, .net and similar top level domain.
*/

func CommonTemplate(html []byte, target string) *Whois {

	var wasThereAlready bool
	var err error
	var wi = new(Whois)

	re := regexp.MustCompile(`<br.*?>(.*)<br>`)
	submatchall := re.FindAllStringSubmatch(string(html), -1)
	for _, element := range submatchall {
		s := strings.Split(element[1], "<br>")
		for _, str := range s {
			if strings.Contains(str, "For more information on Whois") {
				break
			}
			if str == "" {
				continue
			}
			if strings.Contains(str, crCommon[0])  {

				value := CommonTrimmer(str, crCommon)

				if value == "" { // If there is no information in current whois record then we check whois history.
					value, err = GetWhoisHistoryFree(target, 2)
					if err != nil {
						fmt.Println(err)
					}
					if value == "" { // If whois history doesn't have this info too then we give up.
						wi.RegistrationDate = "-"
						continue
					}
				}

				value = parseOnlineDate(value)
				wi.RegistrationDate = value

			}
			if strings.Contains(str, udCommon[0]) || strings.Contains(str, udCommon[1]) {

				value := CommonTrimmer(str, udCommon)

				if value == "" { // If there is no information in current whois record then we check whois history.
					value, err = GetWhoisHistoryFree(target, 2)
					if err != nil {
						fmt.Println(err)
					}
					if value == "" { // If whois history doesn't have this info too then we give up.
						wi.UpdateDate = "-"
						continue
					}
				}

				value = parseOnlineDate(value)
				wi.UpdateDate = value
			}
			if strings.Contains(str, edCommon[0]) || strings.Contains(str, edCommon[1]) {

				value := CommonTrimmer(str, edCommon)

				if value == "" { // If there is no information in current whois record then we check whois history.
					value, err = GetWhoisHistoryFree(target, 3)
					if err != nil {
						fmt.Println(err)
					}
					if value == "" {
						wi.ExpireDate = "-"
						continue
					}
				}

				value = parseOnlineDate(value)
				wi.ExpireDate = value
			}
			if strings.Contains(str, rrCommon[0]) {

				value := CommonTrimmer(str, rrCommon)
				value = strings.TrimPrefix(value, " ")
				wi.Registrar = value
			}
			if strings.Contains(str, rtCommon[0]) {

				value := CommonTrimmer(str, rtCommon)

				// If the current information about registrant is hidden
				// then check whois history to see if there is some additional information
				if strings.Contains(value,"Privacy") {
					value, err = GetWhoisHistoryFree(target, 4)
					if err != nil {
						fmt.Println(err)
					}
					wi.Registrant = value
				}
				wi.Registrant = value
			}
			if strings.Contains(str, rtcCommon[0]) {
				value := strings.Replace(str, rtcCommon[0],"", 1)
				value = strings.TrimSpace(value)
				country := countries.ByName(value)
				wi.RegistrantCountry = country.StringRus()

			}
			// If there is no strings in current whois information like "Registrant Name:", "registrant:", "owner:"
			// then we need to check whois history information.
			if !wasThereAlready {
				if !strings.Contains(string(html), rtCommon[0]) {
					value, err := GetWhoisHistoryFree(target, 4)
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

	// If there is no information about country
	// then set the string that tells about it.
	if wi.RegistrantCountry == "" {
		wi.RegistrantCountry = "Страна регистранта не указана"
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

	return wi
}

// parseDate parses 0Z timezone to +3 UTC
func parseOnlineDate (date string) string {

	var slice []string

	date = strings.Trim(date, ".0Z")
	raw := strings.Split(date, "T")

	slice = append(slice, raw[0])

	rawTime := strings.Split(raw[1], ":")
	rh, _ := strconv.Atoi(rawTime[0])

	h := rh + 3
	hToStr := fmt.Sprintf("%02d", h) // returns hToStr in two digit format: 2 -> 02
	if hToStr == "24" {
		hToStr = "00"
	}
	if hToStr == "25" {
		hToStr = "01"
	}
	if hToStr == "26" {
		hToStr = "02"
	}

	time := hToStr + ":" + rawTime[1] + ":" + rawTime[2] + " (UTC)"
	slice = append(slice, time)
	utcDate := strings.Join(slice, " ")

	return utcDate

}
