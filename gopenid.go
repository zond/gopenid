package gopenid

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	discovery    = "https://www.google.com/accounts/o8/id"
	maxOldNonces = 100000
)

type oldNonce struct {
	at    time.Time
	nonce string
	next  *oldNonce
	prev  *oldNonce
}

type oldNonces struct {
	nonceMap       map[string]*oldNonce
	nonceListStart *oldNonce
	nonceListEnd   *oldNonce
	max            int
	lock           *sync.RWMutex
}

func newOldNonces() *oldNonces {
	return &oldNonces{
		nonceMap: make(map[string]*oldNonce),
		max:      maxOldNonces,
		lock:     &sync.RWMutex{},
	}
}

func (self *oldNonces) String() string {
	self.lock.RLock()
	defer self.lock.RUnlock()
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "%v\n", self.nonceMap)
	for n := self.nonceListStart; n != nil; n = n.next {
		fmt.Fprintf(buf, "%v@%v =>\n", n.nonce, n.at)
	}
	return string(buf.Bytes())
}

func (self *oldNonces) size() int {
	self.lock.RLock()
	defer self.lock.RUnlock()
	return len(self.nonceMap)
}

func (self *oldNonces) add(s string) bool {
	self.lock.Lock()
	defer self.lock.Unlock()
	if _, found := self.nonceMap[s]; found {
		return false
	}
	n := &oldNonce{
		at:    time.Now(),
		nonce: s,
		next:  self.nonceListStart,
	}
	self.nonceListStart = n
	if n.next != nil {
		n.next.prev = n
	}
	if self.nonceListEnd == nil {
		self.nonceListEnd = self.nonceListStart
	}
	self.nonceMap[s] = self.nonceListStart
	for len(self.nonceMap) > self.max {
		last := self.nonceListEnd
		last.prev.next = nil
		self.nonceListEnd = last.prev
		delete(self.nonceMap, last.nonce)
	}
	return true
}

var nonces = newOldNonces()
var endpoint *url.URL

type xrdDoc struct {
	XRD string `xml:"XRD>Service>URI"`
}

func join(u *url.URL, q url.Values) (result *url.URL, err error) {
	buf := bytes.NewBufferString(u.Scheme)
	fmt.Fprint(buf, "://")
	if u.User != nil {
		fmt.Fprintf(buf, "%v@", u.User.String())
	}
	fmt.Fprint(buf, u.Host)
	if u.Path != "" {
		fmt.Fprint(buf, u.Path)
	}
	if u.Fragment != "" {
		fmt.Fprintf(buf, "#%v", u.Fragment)
	}
	if u.RawQuery == "" {
		fmt.Fprintf(buf, "?%v", q.Encode())
	} else {
		fmt.Fprintf(buf, "?%v&%v", u.RawQuery, q.Encode())
	}
	result, err = url.Parse(buf.String())
	return
}

func getEndpoint() (result *url.URL, err error) {
	if endpoint == nil {
		var req *http.Request
		if req, err = http.NewRequest("GET", discovery, nil); err != nil {
			return
		}
		var resp *http.Response
		if resp, err = new(http.Client).Do(req); err != nil {
			return
		}
		dec := xml.NewDecoder(resp.Body)
		var x xrdDoc
		if err = dec.Decode(&x); err != nil {
			return
		}
		result, err = url.Parse(x.XRD)
	}
	return
}

/*
VerifyAuth verifies that r is a valid return redirect from a Google OpenID query where the user allowed his/identity
to be publicized by returning the returnTo url provided in GetAuthURL, the identity and whether the validation was ok.
*/
func VerifyAuth(r *http.Request) (returnTo *url.URL, result string, ok bool, err error) {
	endp, err := getEndpoint()
	if err != nil {
		return
	}
	query := endp.Query()
	r.ParseForm()
	var nonce string
	for key, values := range r.Form {
		for _, value := range values {
			if key == "openid.ext1.value.email" {
				result = value
			}
			if key == "openid.secondary_return_to" {
				if returnTo, err = url.Parse(value); err != nil {
					return
				}
			}
			if key == "openid.response_nonce" {
				nonce = value
			}
			query.Add(key, value)
		}
	}
	query.Set("openid.mode", "check_authentication")
	joined, err := join(endp, query)
	if err != nil {
		return
	}
	response, err := new(http.Client).Get(joined.String())
	if err != nil {
		return
	}
	bod, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(bod), "\n") {
		kv := strings.SplitN(line, ":", 2)
		switch kv[0] {
		case "is_valid":
			if kv[1] == "true" {
				if nonces.add(nonce) {
					ok = true
				}
			}
		case "ns":
			if kv[1] != "http://specs.openid.net/auth/2.0" {
				err = fmt.Errorf("Unknown namespace: %v", kv[1])
				return
			}
		}
	}
	return
}

/*
GetAuthURL returns a url that will validate a users identity via Google OpenID and then return with
a redirect that will return the same returnTo url when VerifyAuth is called.
*/
func GetAuthURL(r *http.Request, returnTo *url.URL) (result *url.URL, err error) {
	endp, err := getEndpoint()
	if err != nil {
		return
	}
	query := endp.Query()
	query.Add("openid.mode", "checkid_setup")
	query.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	query.Add("openid.return_to", "http://"+r.Host+"/openid?openid.secondary_return_to="+returnTo.String())
	query.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
	query.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	query.Add("openid.ns.ax", "http://openid.net/srv/ax/1.0")
	query.Add("openid.ax.mode", "fetch_request")
	query.Add("openid.ax.required", "email")
	query.Add("openid.ax.type.email", "http://axschema.org/contact/email")
	return join(endp, query)
}
