package oauthprovider

import (
	"bufio"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

//hard code the consumer key
type FakeStore map[string]string

func (f FakeStore) ConsumerSecret(consumer_key string) string {
	return f[consumer_key]
}
func (f FakeStore) Uniqueness(nonce, customer_key, token_key string) bool {
	return true //fake always accept stuff
}
func (f FakeStore) ValidateToken(token, consumer_key string) bool {
	return true
}

func (f FakeStore) CreateToken(consumer_key string) (token_key, token_secret string) {
	return "token_key", "token_secret"
}

func Test_Check(t *testing.T) {
	//the following request has been generated using http://term.ie/oauth/example/client.php
	req := ReadRequest(`
GET http://photos.example.net/initiate HTTP/1.1
Host: photos.example.net
Authorization: OAuth realm="Photos",
	oauth_version="1.0",
	oauth_consumer_key="dpf43f3p2l4k3l03",
	oauth_signature_method="HMAC-SHA1",
	oauth_timestamp="1375199363",
	oauth_nonce="47fb7230ed0de7dc1ca6114e250e0dae",
	oauth_signature="pKOpG%2FRH4CfmX%2Bk5zAKqJtRUNuU%3D"

`) // the extra space is required
	store := make(FakeStore)
	store["dpf43f3p2l4k3l03"] = "kd94hf93k423kf44"
	_, err := NewAuthenticatedRequest(req, store)
	if err != nil {
		t.Fatalf("Failed to authenticate the request %v", err)
	}

}

func Test_Crypto_HMAC(t *testing.T) {
	//1 generate a random private key
	message := `POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7`
	key := "this is my magic key dude"
	signature := HMAC_Sign(message, key)

	if !_HMAC_SHA1_Verify(message, key, signature) {
		t.Fatalf("Failed to verify ")
	}
}

func HMAC_Sign(message string, key string) string {
	hashfun := hmac.New(sha1.New, []byte(key))
	hashfun.Write([]byte(message))
	rawsignature := hashfun.Sum(nil)
	base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
	base64.StdEncoding.Encode(base64signature, rawsignature)
	return string(base64signature)
}

func Test_Crypto_RSA(t *testing.T) {
	//1 generate a random private key
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("even failed to generate private key %v", err)
	}
	pbytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("even failed to generate public  key %v", err)
	}
	publicKey := base64.StdEncoding.EncodeToString(pbytes)
	message := `POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7`
	signature := RSA_Sign(key, message, "ignored")

	if !_RSA_SHA1_Verify(message, publicKey, signature) {
		t.Fatalf("Failed to verify ")
	}
}
func RSA_Sign(private *rsa.PrivateKey, message string, key string) string {
	//key is ignored in rsa_sha1
	hashfun := sha1.New()
	hashfun.Write([]byte(message))
	hashed := hashfun.Sum(nil)

	rawsignature, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA1, hashed)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(rawsignature)
}

//ReadRequest is a simple utility to create a request from string for test purpose
func ReadRequest(request string) *http.Request {
	request = strings.TrimLeft(request, "\n \t")
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	if err != nil {
		panic(err)
	}
	//req.Body = ioutil.NopCloser(strings.NewReader(body))
	return req
}
func Test_signatureBaseStringI(t *testing.T) {

	req := ReadRequest(`
POST http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
Authorization: OAuth realm="Example",
               oauth_consumer_key="9djdj82h48djs9d2",
               oauth_token="kkk9d7dh3k39sjv7",
               oauth_signature_method="HMAC-SHA1",
               oauth_timestamp="137131201",
               oauth_nonce="7d8f3e4a",
               oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

c2&a3=2+q`)

	store := make(FakeStore)
	u := ParsingRequest(req, store)
	if len(u.OtherParameters["a3"]) != 2 {

		t.Fatalf("a3=%v instead of ", u.OtherParameters["a3"])
	}

	res := u.SignatureBaseString()
	expected := `POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7`
	if res != expected {
		t.Fatalf("unexpected signatureBaseString result \ngot:%s\nnot:%s", res, expected)
	}

}

func Test_signatureBaseString(t *testing.T) {

	vals := make(url.Values)
	vals["oauth_consumer_key"] = []string{"9djdj82h48djs9d2"}
	vals["oauth_token"] = []string{"kkk9d7dh3k39sjv7"}
	vals["oauth_signature_method"] = []string{"HMAC-SHA1"}
	vals["oauth_timestamp"] = []string{"137131201"}
	vals["oauth_nonce"] = []string{"7d8f3e4a"}
	//vals["oauth_signature"] = []string{"bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"}
	vals["b5"] = []string{"=%3D"}
	vals["a3"] = []string{"2 q", "a"}
	vals["c@"] = []string{""}
	vals["a2"] = []string{"r b"}
	vals["c2"] = []string{""}

	u, _ := url.Parse("http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")
	req := &UnauthenticatedRequest{
		Request:         &http.Request{URL: u},
		OAuthParameters: vals,
		Method:          "POST",
		Realm:           "Example",
	}
	res := req.SignatureBaseString()
	expected := `POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7`
	if res != expected {
		t.Fatalf("unexpected signatureBaseString result \ngot:%s\nnot:%s", res, expected)
	}
	// if req.Signature != "bYT5CMsGcbgUdFHObYMEfcx6bsw=" {
	// 	t.Fatalf("unexpected signature result \ngot:%s\nnot:%s", req.Signature, "bYT5CMsGcbgUdFHObYMEfcx6bsw=")
	// }

}

func Test_basStringUri(t *testing.T) {
	u1, _ := url.Parse("HTTP://EXAMPLE.COM:80/r%20v/X?id=123")
	x := `http://example.com/r%20v/X`
	res := filterBaseStringURI(u1).String()
	if res != x {
		t.Fatalf("unexpected baseStringUri result \ngot:%s\nnot:%s", res, x)
	}
}

func Test_formatRequestParameters(t *testing.T) {
	x := `a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7`
	vals := make(url.Values)
	vals["b5"] = []string{"=%3D"}
	vals["a3"] = []string{"2 q", "a"}
	vals["c@"] = []string{""}
	vals["a2"] = []string{"r b"}
	vals["oauth_consumer_key"] = []string{"9djdj82h48djs9d2"}
	vals["oauth_token"] = []string{"kkk9d7dh3k39sjv7"}
	vals["oauth_signature_method"] = []string{"HMAC-SHA1"}
	vals["oauth_timestamp"] = []string{"137131201"}
	vals["oauth_nonce"] = []string{"7d8f3e4a"}
	vals["c2"] = []string{""}

	res := formatRequestParameters(vals)
	if res != x {
		t.Fatalf("unexpected formatRequestParameters result \ngot:%s\nnot:%s", res, x)
	}

}

func Test_parseAuthorizationHeader(t *testing.T) {
	header := `  OAuth realm="Example",
        oauth_consumer_key="0685bd9184jfhq22",
        oauth_token="ad180jjd733klru7",
        oauth_signature_method="HMAC-SHA1",
        oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK2FPY%3D",
        oauth_timestamp="137131200",
        oauth_nonce="4572616e48616d6d65724c61686176",
        oauth_version="1.0"`
	realm, vals, err := _parseAuthorizationHeader(header)
	switch {
	case err != nil:
		t.Fatalf("error %v", err)
	case realm != "Example":
		t.Fatalf("invalid realm %v", realm)
	case vals["oauth_signature"][0] != "wOJIO9A2W5mFwDgiDvZbTSMK2FPY=": // yes after parsing the values MUST be decoded
		t.Fatalf("invalid realm %v", realm)

	}
}

type encGolden struct {
	src, expected string
}

func (g *encGolden) Check(t *testing.T, actual string) {
	if actual != g.expected {
		t.Fatalf("Failed: %v -> %v not %v\n", g.src, actual, g.expected)
	}
}

var (
	EncGolden = []*encGolden{
		&encGolden{"abcdefghijklmnopqrstuvwxyz0123456789-._~", "abcdefghijklmnopqrstuvwxyz0123456789-._~"},
		&encGolden{"@", "%40"},
		&encGolden{" ", "%20"},
		&encGolden{"%", "%25"},
		&encGolden{"a+a", "a%2Ba"},
		&encGolden{"=%3D", "%3D%253D"},
		&encGolden{"a", "a"},
		&encGolden{"", ""},
		&encGolden{"r b", "r%20b"},
		&encGolden{"9djdj82h48djs9d2", "9djdj82h48djs9d2"},
		&encGolden{"kkk9d7dh3k39sjv7", "kkk9d7dh3k39sjv7"},
		&encGolden{"HMAC-SHA1", "HMAC-SHA1"},
		&encGolden{"137131201", "137131201"},
		&encGolden{"7d8f3e4a", "7d8f3e4a"},
		&encGolden{"", ""},
		&encGolden{"2 q", "2%20q"},
	}
)

func TestPercentEncode(t *testing.T) {
	for _, gold := range EncGolden {
		actual := PercentEncode(gold.src)
		gold.Check(t, actual)
	}
}
