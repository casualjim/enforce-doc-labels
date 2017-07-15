package main

// This microservice reopens issues in GitHub that are not labelled correctly for documentation impact
// Set "docsHasImpact" and "docsNoImpact" to the two labels that will allow closure of issues
// Set repoName and repoOwner to the repository name and github user respectively, ie: https://github.com/repoOwner/repoName
// Before execution, run:
// export DOC_ENFORCER_SECRET_TOKEN='a generated secret also stored in the repo settings'
// export DOC_ENFORCER_GITHUB_ACCESS_TOKEN='github access token for the user you want messages to be from'

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

var secretToken []byte
var githubAccessToken string

const docsHasImpact = "docs/has-impact"
const docsNoImpact = "docs/no-impact"

const repoName = "vic"
const repoOwner = "vmware"

// Github signs its messages, so this routine securely checks the signature in a received message
// so that we know for sure that it's from Github
func validateHeaderSig(headers map[string][]string, body []byte) (validated bool) {
	validated = false
	for k, v := range headers {
		if http.CanonicalHeaderKey(k) == "X-Hub-Signature" {
			if len(v) != 1 {
				fmt.Fprintf(os.Stderr, "Got suspicious signature")
				return
			}
			mac := hmac.New(sha1.New, secretToken)
			if n, err := mac.Write(body); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write request body to HMAC to calculate signature")
				if n <= 0 {
					fmt.Fprintf(os.Stderr, "Body of request was empty")
					return
				}
				return
			}
			signature := mac.Sum(nil)

			// hmac.Equal prevents side-channel timing attacks :)
			validated = hmac.Equal([]byte(v[0]), []byte("sha1="+hex.EncodeToString(signature)))
			return
		}
	}
	return
}

func reopenIssue(issue *github.Issue) error {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubAccessToken})
	ctx := context.TODO()
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	comment := &github.IssueComment{
		Body: github.String(fmt.Sprintf("Please help keep our documentation up to date by adding either `%s` or `%s` as a label to this issue to notify our documentation authors as to whether or not this issue affects the documentation.", docsNoImpact, docsHasImpact)),
	}

	if _, _, err := client.Issues.CreateComment(ctx, repoOwner, repoName, issue.GetNumber(), comment); err != nil {
		fmt.Fprintf(os.Stderr, "Got %s trying to add a friendly comment to the issue", err)
		return err
	}

	openState := &github.IssueRequest{State: github.String("open")}
	if _, _, err := client.Issues.Edit(ctx, repoOwner, repoName, issue.GetNumber(), openState); err != nil {
		fmt.Fprintf(os.Stderr, "Got %s trying to reopen the issue", err)
		return err
	}

	return nil
}

// handles events generated from github
func receiver(w http.ResponseWriter, req *http.Request) {
	var event *github.IssueEvent

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "can't read body", http.StatusBadRequest)
		return
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	if !validateHeaderSig(req.Header, body) {
		return
	}

	decoder := json.NewDecoder(req.Body)
	if err := decoder.Decode(&event); err != nil {
		fmt.Fprintf(os.Stderr, "Could not decode json: %+v", err)
		return
	}

	if event.Issue == nil {
		return
	}

	if *event.Issue.State == "closed" && !hasDocLabels(event.Issue.Labels) {
		err = reopenIssue(event.Issue)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Got error reopening issue: %s", err)
			return
		}
	}
}

func hasDocLabels(labels []github.Label) bool {
	for _, label := range labels {
		name := label.GetName()
		if name == docsHasImpact || name == docsNoImpact {
			return true
		}
	}
	return false
}

func getLabels(labels []github.Label) *[]string {
	s := []string{}
	for _, label := range labels {
		s = append(s, label.GetName())
	}
	return &s
}

func main() {
	secretToken = []byte(os.Getenv("DOC_ENFORCER_SECRET_TOKEN"))
	githubAccessToken = os.Getenv("DOC_ENFORCER_GITHUB_ACCESS_TOKEN")
	http.HandleFunc("/github_endpoint", receiver)
	http.HandleFunc("/whoami", http.HandlerFunc(func(r http.ResponseWriter, req *http.Request) {
		r.Write([]byte(`github webhook for enforcing doc labels on PR's
`))
	}))
	log.Println("serving webhook at 0.0.0.0:9399")
	log.Fatal(http.ListenAndServe(":9399", nil))
}
