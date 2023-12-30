package src

import (
	"github.com/dlclark/regexp2"
	"strings"
)

// RuTrimmer gets value of a field and removes whitespaces for ru.go template
func RuTrimmer(str string, slice []string) string{

	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.TrimPrefix(str, substr)
			return strings.TrimPrefix(value, " ")
		}
	}

	return ""
}

// UaDateTrimmer gets value of a date field and removes whitespaces for ru.go template
// I use this because I don't know how to deal with such date string as "     date time"
// If I just replace all whitespaces then I'll need to separate "datetime" string and so I've chose this way of dealing.
func UaDateTrimmer(str string, slice []string) string {
	re := regexp2.MustCompile("[^#]*\\d", 0)
	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.TrimPrefix(str, substr)
			value = strings.ReplaceAll(value, " ", "#")
			match, _ := re.FindStringMatch(value)
			year := match.Capture.String()
			rawTime := strings.ReplaceAll(value, match.Capture.String(), "")
			time := strings.ReplaceAll(rawTime, "#", "")
			date := year + " " + time
			return date
		}
	}

	return ""
}

// UaTrimmer gets value of a field and removes whitespaces for ua.go template
func UaTrimmer(str string, slice []string) string {

	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.TrimPrefix(str, substr)
			return strings.ReplaceAll(value, " ", "")
		}
	}

	return ""
}

// CommonTrimmer gets value of a field for common.go template
func CommonTrimmer(str string, slice []string) string {

	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.TrimPrefix(str, substr)
			return strings.TrimPrefix(value, " ")
		}
	}

	return ""

}

// ComTrimmer gets value of a field for com.go template
func ComTrimmer(str string, slice []string) string {

	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.TrimPrefix(str, substr)
			return strings.TrimPrefix(value, " ")
		}
	}

	return ""

}

// EuTrimmer gets value of a field for com.go template
func EuTrimmer(str string, slice []string) string {

	for _, substr := range slice {
		if strings.Contains(str, substr) {
			value := strings.TrimPrefix(str, substr)
			return strings.TrimPrefix(value, " ")
		}
	}

	return ""

}
