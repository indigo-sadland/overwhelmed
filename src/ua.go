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

	crUa  = []string{"created:"}
	udUa  = []string{"changed:"}
	edUa  = []string{"expires:"}
	rrUa  = []string{"registrar:"}
	rtUa  = []string{"person:"}
	rtcUa = []string{"country:"}

	trigger = []string{"notpublished", "n/a", ""}

)

/*
	There is placed template parser for Hostmaster Whois Service
	that is for web sites in .ua top-level domain
*/

func UaTemplate(html []byte, target string) *Whois {

	var wasThereAlready bool
	var gotCreatedAlready bool
	var gotChangedAlready bool
	var gotExpiresAlready bool
	var gotPersonAlready bool
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
			if strings.Contains(str, crUa[0]) {
				if !gotCreatedAlready {
					value := UaDateTrimmer(str, crUa)

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

					value = parseUaDate(value)
					wi.RegistrationDate = value
					gotCreatedAlready = true
				}

			}
			if strings.Contains(str, udUa[0]) {

				if !gotChangedAlready {
					value := UaDateTrimmer(str, udUa)

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

					value = parseUaDate(value)
					wi.UpdateDate = value
					gotChangedAlready = true
				}

			}
			if strings.Contains(str, edUa[0]) {

				if !gotExpiresAlready {

					value := UaDateTrimmer(str, edUa)

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

					value = parseUaDate(value)
					wi.ExpireDate = value
					gotExpiresAlready = true
				}

			}
			if strings.Contains(str, rrUa[0]) {

				value := UaTrimmer(str, rrUa)
				value = strings.TrimPrefix(value, " ")
				wi.Registrar = value
			}
			if strings.Contains(str, rtUa[0]) {
				if !gotPersonAlready {
					value := UaTrimmer(str, rtUa)

					// If the current information about registrant is hidden
					// then check whois history to see if there is some additional information
					if strings.Contains(value,"n/a") || strings.Contains(value, "not published") {
						value, err = GetWhoisHistoryFree(target, 4)
						if err != nil {
							fmt.Println(err)
						}
						wi.Registrant = value
					}
					wi.Registrant = value
					gotPersonAlready = true
				}

			}
			if strings.Contains(str, rtcUa[0]) {
				value := strings.Replace(str, rtcUa[0],"", 1)
				value = strings.TrimSpace(value)
				country := countries.ByName(value)
				wi.RegistrantCountry = country.StringRus()

			}
			// If there is no strings in current whois information like "person:"
			// then we need to check whois history information.
			if !wasThereAlready {
				if !strings.Contains(string(html), rtUa[0]) {
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
	if wi.Registrant == trigger[0] || wi.Registrant == trigger[1] || wi.Registrant == trigger[2] {
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


// parseUaDate parses timezone to +3 UTC
func parseUaDate(date string) string {

	var slice []string

	re := regexp.MustCompile(`(\+\d*)`)

	raw := strings.Split(date, " ")
	slice = append(slice, raw[0])

	raw[1] = strings.ReplaceAll(raw[1], re.FindStringSubmatch(raw[1])[0], "")
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
