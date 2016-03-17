package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func subjectToString(subject pkix.Name) string {
	out := []string{}
	if subject.CommonName != "" {
		out = append(out, fmt.Sprintf("CN=%s", subject.CommonName))
	}
	if len(subject.Organization) != 0 {
		out = append(out, fmt.Sprintf("O=[%s]", strings.Join(subject.Organization, ", ")))
	}
	if len(subject.OrganizationalUnit) != 0 {
		out = append(out, fmt.Sprintf("OU=[%s]", strings.Join(subject.OrganizationalUnit, ", ")))
	}
	if len(subject.Locality) != 0 {
		out = append(out, fmt.Sprintf("L=[%s]", strings.Join(subject.Locality, ", ")))
	}
	if len(subject.Province) != 0 {
		out = append(out, fmt.Sprintf("ST=[%s]", strings.Join(subject.Province, ", ")))
	}
	if len(subject.Country) != 0 {
		out = append(out, fmt.Sprintf("C=[%s]", strings.Join(subject.Country, ", ")))
	}
	if len(out) == 0 {
		return "???"
	}
	return strings.Join(out, "; ")
}

func main() {
	logURI := flag.String("log", "", "")
	flag.Parse()
	resp, err := http.Get(fmt.Sprintf("%s/ct/v1/get-roots", *logURI))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get CT log roots: %s\n", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read CT log roots response: %s\n", err)
		return
	}
	var encodedRoots struct {
		Certificates []string `json:"certificates"`
	}
	err = json.Unmarshal(body, &encodedRoots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse CT log roots response: %s\n", err)
		return
	}
	for _, encodedRoot := range encodedRoots.Certificates {
		rawCert, err := base64.StdEncoding.DecodeString(encodedRoot)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			continue
		}
		fmt.Println(subjectToString(cert.Subject))
	}
}
