package main

import (
	"log"
	"regexp"
	"testing"
)

func TestUrlParse(t *testing.T) {
	testUrl := "http://example.com/activate/123radek"

	// u, err := url.Parse(testUrl)
	// if err != nil {
	// 	t.Error(err)
	// }
	r := regexp.MustCompile(".*\\/activate\\/")
	output := r.ReplaceAllString(testUrl, "")
	log.Println(output)
}
