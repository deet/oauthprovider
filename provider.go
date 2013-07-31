// oauthprovider is a full implementation of http://tools.ietf.org/html/rfc5849. Objects and methods are closely named after the RFC vocabulary, and the most significant parts of the RFC are cited in comments.
//
// Usage:
// 
// 1 - Provide an implementation of the interface BackendStore, mainly to provide access to storage/security policy.
// BackendStore is a very simple interface.
//
// 2 - Authenticate an http.Request as follow
//
//    func httpHandler(w http.Writer, r *http.Request) {
//     authenticatedRequest, err := NewAuthenticatedRequest(req, store)
//    }
//
// Where:
//
//"store" is the BackendStore provided.
//
// "authenticatedRequest" has made all the checks required by RFC. It also provides access to all the oauth parameters.
// 
//
package oauthprovider

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

/*
Note to implementers: start from the bottom, add as many unit test as possible.

Status: only the structure has been set.

*/

const (
	HMAC_SHA1 = "HMAC-SHA1"
	RSA_SHA1  = "RSA-SHA1"
	PLAINTEXT = "PLAINTEXT"

	CONTENT_TYPE_HEADER = "Content-Type"
	FORM_URLENCODED     = "application/x-www-form-urlencoded"

	OAUTH_VERSION            = "1.0"
	CALLBACK_PARAM           = "oauth_callback"
	CONSUMER_KEY_PARAM       = "oauth_consumer_key"
	NONCE_PARAM              = "oauth_nonce"
	SIGNATURE_METHOD_PARAM   = "oauth_signature_method"
	SIGNATURE_PARAM          = "oauth_signature"
	TIMESTAMP_PARAM          = "oauth_timestamp"
	TOKEN_PARAM              = "oauth_token"
	TOKEN_SECRET_PARAM       = "oauth_token_secret"
	VERIFIER_PARAM           = "oauth_verifier"
	VERSION_PARAM            = "oauth_version"
	CALLBACK_CONFIRMED_PARAM = "oauth_callback_confirmed"
)

var (
	realmExp          = regexp.MustCompile(` *(OAuth)( +realm="(.*?)")?`)
	paramExp          = regexp.MustCompile(`(\w+)="(.*?)"`)
	notAnOAuthRequest = errors.New("Not an OAuth Request")
)

//BackendStore is used during the verification process to "validate" any http.Request as defined in the RFC5849
type BackendStore interface {
	//ConsumerSecret returns the consumer secret key associated with the consumer key.
	// in RSA_SHA1 signing method, the "consumer_key" must be the base64 std encoding of the PKIX marshalled public key
	// it means that to get a rsa.PublicKey object you need to convert the string key into []byte using base64 std encoding, then x509.ParsePublicKeyPKIX()
	ConsumerSecret(consumer_key string) string
	//Uniqueness implements the uniqueness check of the nonce parameter. @see RFC5849 section 3.3
	Uniqueness(nonce, consumer_key, token_key string) bool
	//ValidateToken verifying the scope and status of the
	//      client authorization as represented by the token (the server MAY
	//      choose to restrict token usage to the client to which it was
	//      issued).
	ValidateToken(token_key, consumer_key string) bool
	CreateToken(consumer_key string) (token_key, token_secret string)
}

//EndPoints provides the three endpoints implementation as defined in RFC5849 
//
//   OAuth uses tokens to represent the authorization granted to the
//   client by the resource owner.  Typically, token credentials are
//   issued by the server at the resource owner's request, after
//   authenticating the resource owner's identity (usually using a
//   username and password).
//
//   There are many ways in which a server can facilitate the provisioning
//   of token credentials.  This section defines one such way, using HTTP
//   redirections and the resource owner's user-agent.  This redirection-
//   based authorization method includes three steps:
//
//   1.  The client obtains a set of temporary credentials from the server
//       (in the form of an identifier and shared-secret).  The temporary
//       credentials are used to identify the access request throughout
//       the authorization process.
//
//   2.  The resource owner authorizes the server to grant the client's
//       access request (identified by the temporary credentials).
//
//   3.  The client uses the temporary credentials to request a set of
//       token credentials from the server, which will enable it to access
//       the resource owner's protected resources.
//
//   The server MUST revoke the temporary credentials after being used
//   once to obtain the token credentials.  It is RECOMMENDED that the
//   temporary credentials have a limited lifetime.  Servers SHOULD enable
//   resource owners to revoke token credentials after they have been
//   issued to clients.
//
//   In order for the client to perform these steps, the server needs to
//   advertise the URIs of the following three endpoints:
//
//   Temporary Credential Request
//         The endpoint used by the client to obtain a set of temporary
//         credentials as described in Section 2.1.
//
//   Resource Owner Authorization
//         The endpoint to which the resource owner is redirected to grant
//         authorization as described in Section 2.2.
//
//   Token Request
//         The endpoint used by the client to request a set of token
//         credentials using the set of temporary credentials as described
//         in Section 2.3.
//
//   The three URIs advertised by the server MAY include a query component
//   as defined by [RFC3986], Section 3, but if present, the query MUST
//   NOT contain any parameters beginning with the "oauth_" prefix, to
//   avoid conflicts with the protocol parameters added to the URIs when
//   used.
//
//   The methods in which the server advertises and documents its three
//   endpoints are beyond the scope of this specification.  Clients should
//   avoid making assumptions about the size of tokens and other server-
//   generated values, which are left undefined by this specification.  In
//   addition, protocol parameters MAY include values that require
//   encoding when transmitted.  Clients and servers should not make
//   assumptions about the possible range of their values.
type EndPoints struct {
	store BackendStore // used to create tokens
}

func NewEndPoints(store BackendStore) *EndPoints {
	return &EndPoints{store}
}

//TemporaryCredentialRequest is a valid http.HandlerFunc that can be used as the temporary credential request endpoint, defined in the RFC
//
//   temporary credential request is the endpoint used by the client to obtain a set of temporary
//   credentials as described in http://tools.ietf.org/html/rfc5849#section-2.1 
//   The client obtains a set of temporary credentials from the server by
//   making an authenticated ( http://tools.ietf.org/html/rfc5849#Section-3 ) HTTP "POST" request to the
//   Temporary Credential Request endpoint (unless the server advertises
//   another HTTP request method for the client to use).  The client
//   constructs a request URI by adding the following REQUIRED parameter
//   to the request (in addition to the other protocol parameters, using
//   the same parameter transmission method):
//  
//   oauth_callback:  An absolute URI back to which the server will
//                    redirect the resource owner when the Resource Owner
//                    Authorization step ( http://tools.ietf.org/html/rfc5849#Section-2.2 ) is completed.  If
//                    the client is unable to receive callbacks or a
//                    callback URI has been established via other means,
//                    the parameter value MUST be set to "oob" (case
//                    sensitive), to indicate an out-of-band
//                    configuration.
//  
//   Servers MAY specify additional parameters.
//  
//   When making the request, the client authenticates using only the
//   client credentials.  The client MAY omit the empty "oauth_token"
//   protocol parameter from the request and MUST use the empty string as
//   the token secret value.
//  
//   Since the request results in the transmission of plain text
//   credentials in the HTTP response, the server MUST require the use of
//   a transport-layer mechanisms such as TLS or Secure Socket Layer (SSL)
//   (or a secure channel with equivalent protections).
//
//   The server MUST verify (http://tools.ietf.org/html/rfc5849#Section-3.2 ) the request and if valid,
//   respond back to the client with a set of temporary credentials (in
//   the form of an identifier and shared-secret).  The temporary
//   credentials are included in the HTTP response body using the
//   "application/x-www-form-urlencoded" content type as defined by
//   [W3C.REC-html40-19980424] with a 200 status code (OK).
//
//   The response contains the following REQUIRED parameters:
//
//   oauth_token
//         The temporary credentials identifier.
//
//   oauth_token_secret
//         The temporary credentials shared-secret.
//
//   oauth_callback_confirmed
//         MUST be present and set to "true".  The parameter is used to
//         differentiate from previous versions of the protocol.
func (e *EndPoints) TemporaryCredentialRequest(w http.ResponseWriter, r *http.Request) {
	auth, err := NewAuthenticatedRequest(r, e.store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var consumer_key string
	var ok bool
	consumer_key, ok = auth.GetOAuthParameter(CONSUMER_KEY_PARAM)
	if !ok {
		http.Error(w, "Missing OAuth Client Credentials: No Consumer Key", http.StatusInternalServerError)
		return
	}
	token_key, token_secret := e.store.CreateToken(consumer_key)

	result := make(url.Values)
	result.Set(TOKEN_PARAM, token_key)
	result.Set(TOKEN_SECRET_PARAM, token_secret)
	result.Set(CALLBACK_CONFIRMED_PARAM, "true")

	w.Header().Set(CONTENT_TYPE_HEADER, FORM_URLENCODED)
	w.Write(([]byte)(result.Encode()))
}

//ResourceOwnerAuthorization is a valid http.HandlerFunc that can be used as the resource owner authorization endpoint, defined in the RFC
//   resource owner authorization is the endpoint to which the resource owner is redirected to grant
//   authorization as described in http://tools.ietf.org/html/rfc5849#section-2.2
//
//   Before the client requests a set of token credentials from the
//   server, it MUST send the user to the server to authorize the request.
//   The client constructs a request URI by adding the following REQUIRED
//   query parameter to the Resource Owner Authorization endpoint URI:
//   oauth_token
//         The temporary credentials identifier obtained in Section 2.1 in
//         the "oauth_token" parameter.  Servers MAY declare this
//         parameter as OPTIONAL, in which case they MUST provide a way
//         for the resource owner to indicate the identifier through other
//         means.
//
//   Servers MAY specify additional parameters.
//
//   The client directs the resource owner to the constructed URI using an
//   HTTP redirection response, or by other means available to it via the
//   resource owner's user-agent.  The request MUST use the HTTP "GET"
//   method.
//
//   For example, the client redirects the resource owner's user-agent to
//   make the following HTTPS request:
//
//     GET /authorize_access?oauth_token=hdk48Djdsa HTTP/1.1
//     Host: server.example.com
//
//   The way in which the server handles the authorization request,
//   including whether it uses a secure channel such as TLS/SSL is beyond
//   the scope of this specification.  However, the server MUST first
//   verify the identity of the resource owner.
//
//   When asking the resource owner to authorize the requested access, the
//   server SHOULD present to the resource owner information about the
//   client requesting access based on the association of the temporary
//   credentials with the client identity.  When displaying any such
//   information, the server SHOULD indicate if the information has been
//   verified.
//
//   After receiving an authorization decision from the resource owner,
//   the server redirects the resource owner to the callback URI if one
//   was provided in the "oauth_callback" parameter or by other means.
//
//   To make sure that the resource owner granting access is the same
//   resource owner returning back to the client to complete the process,
//   the server MUST generate a verification code: an unguessable value
//   passed to the client via the resource owner and REQUIRED to complete
//   the process.  The server constructs the request URI by adding the
//   following REQUIRED parameters to the callback URI query component:
//
//   oauth_token
//         The temporary credentials identifier received from the client.
//   oauth_verifier
//         The verification code.
//
//   If the callback URI already includes a query component, the server
//   MUST append the OAuth parameters to the end of the existing query.
//
//   For example, the server redirects the resource owner's user-agent to
//   make the following HTTP request:
//
//     GET /cb?x=1&oauth_token=hdk48Djdsa&oauth_verifier=473f82d3 HTTP/1.1
//     Host: client.example.net
//
//   If the client did not provide a callback URI, the server SHOULD
//   display the value of the verification code, and instruct the resource
//   owner to manually inform the client that authorization is completed.
//   If the server knows a client to be running on a limited device, it
//   SHOULD ensure that the verifier value is suitable for manual entry.
func (*EndPoints) ResourceOwnerAuthorization(w http.ResponseWriter, r *http.Request) {}

//TokenCredentials  is a valid http.HandlerFunc that can be used as the token credentials endpoint, defined in the RFC
//
//   token credentials endpoint is the endpoint used by the client to request a set of token
//   credentials using the set of temporary credentials as described in http://tools.ietf.org/html/rfc5849#section-2.3
//   The client obtains a set of token credentials from the server by
//   making an authenticated (Section 3) HTTP "POST" request to the Token
//   Request endpoint (unless the server advertises another HTTP request
//   method for the client to use).  The client constructs a request URI
//   by adding the following REQUIRED parameter to the request (in
//   addition to the other protocol parameters, using the same parameter
//   transmission method):
//
//   oauth_verifier
//         The verification code received from the server in the previous
//         step.
//
//   When making the request, the client authenticates using the client
//   credentials as well as the temporary credentials.  The temporary
//   credentials are used as a substitute for token credentials in the
//   authenticated request and transmitted using the "oauth_token"
//   parameter.
//
//   Since the request results in the transmission of plain text
//   credentials in the HTTP response, the server MUST require the use of
//   a transport-layer mechanism such as TLS or SSL (or a secure channel
//   with equivalent protections).
//
//   For example, the client makes the following HTTPS request:
//
//     POST /request_token HTTP/1.1
//     Host: server.example.com
//     Authorization: OAuth realm="Example",
//        oauth_consumer_key="jd83jd92dhsh93js",
//        oauth_token="hdk48Djdsa",
//        oauth_signature_method="PLAINTEXT",
//        oauth_verifier="473f82d3",
//        oauth_signature="ja893SD9%26xyz4992k83j47x0b"
//
//   The server MUST verify (Section 3.2) the validity of the request,
//   ensure that the resource owner has authorized the provisioning of
//   token credentials to the client, and ensure that the temporary
//   credentials have not expired or been used before.  The server MUST
//   also verify the verification code received from the client.  If the
//   request is valid and authorized, the token credentials are included
//   in the HTTP response body using the
//   "application/x-www-form-urlencoded" content type as defined by
//   [W3C.REC-html40-19980424] with a 200 status code (OK).
//
//   The response contains the following REQUIRED parameters:
//
//   oauth_token
//         The token identifier.
//
//   oauth_token_secret
//         The token shared-secret.
//
//   For example:
//
//     HTTP/1.1 200 OK
//     Content-Type: application/x-www-form-urlencoded
//
//     oauth_token=j49ddk933skd9dks&oauth_token_secret=ll399dj47dskfjdk
//
//   The server must retain the scope, duration, and other attributes
//   approved by the resource owner, and enforce these restrictions when
//   receiving a client request made with the token credentials issued.
//
//   Once the client receives and stores the token credentials, it can
//   proceed to access protected resources on behalf of the resource owner
//   by making authenticated requests (Section 3) using the client
//   credentials together with the token credentials received.
func (*EndPoints) TokenCredentials(w http.ResponseWriter, r *http.Request) {}

//AuthenticatedRequest provide uniform access to all the oauth parameters, if the 
//http.Request is a valid OAuth request. As defined in the RFC:
//
//   The HTTP authentication methods defined by [RFC2617] enable clients
//   to make authenticated HTTP requests.  Clients using these methods
//   gain access to protected resources by using their credentials
//   (typically, a username and password pair), which allow the server to
//   verify their authenticity.  Using these methods for delegation
//   requires the client to assume the role of the resource owner.
//
//   OAuth provides a method designed to include two sets of credentials
//   with each request, one to identify the client, and another to
//   identify the resource owner.  Before a client can make authenticated
//   requests on behalf of the resource owner, it must obtain a token
//   authorized by the resource owner.  Section 2 provides one such method
//   through which the client can obtain a token authorized by the
//   resource owner.
//
//   The client credentials take the form of a unique identifier and an
//   associated shared-secret or RSA key pair.  Prior to making
//   authenticated requests, the client establishes a set of credentials
//   with the server.  The process and requirements for provisioning these
//   are outside the scope of this specification.  Implementers are urged
//   to consider the security ramifications of using client credentials,
//   some of which are described in Section 4.6.
//
//   Making authenticated requests requires prior knowledge of the
//   server's configuration.  OAuth includes multiple methods for
//   transmitting protocol parameters with requests (Section 3.5), as well
//   as multiple methods for the client to prove its rightful ownership of
//   the credentials used (Section 3.4).  The way in which clients
//   discover the required configuration is outside the scope of this
//   specification.
type AuthenticatedRequest struct {
	*http.Request
	oauthParameters url.Values // to later get back to them
}

//NewAuthenticatedRequest execute the following steps
//
// - parses the http.Request for OAuth parameters,
//
// - do all the checks, and callbacks to the BackendStore instance
//
// - return an AuthenticatedRequest instance if and only if everything is ok as defined in the RFC:
//
//   Servers receiving an authenticated request MUST validate it by:
//
//   o  Recalculating the request signature independently as described in
//      Section 3.4 and comparing it to the value received from the client
//      via the "oauth_signature" parameter.
//      
//   o  If using the "HMAC-SHA1" or "RSA-SHA1" signature methods, ensuring
//      that the combination of nonce/timestamp/token (if present)
//      received from the client has not been used before in a previous
//      request (the server MAY reject requests with stale timestamps as
//      described in Section 3.3).
//
//   o  If a token is present, verifying the scope and status of the
//      client authorization as represented by the token (the server MAY
//      choose to restrict token usage to the client to which it was
//      issued).
//
//   o  If the "oauth_version" parameter is present, ensuring its value is
//      "1.0".
//
//   If the request fails verification, the server SHOULD respond with the
//   appropriate HTTP response status code.  The server MAY include
//   further details about why the request was rejected in the response
//   body.
//
//   The server SHOULD return a 400 (Bad Request) status code when
//   receiving a request with unsupported parameters, an unsupported
//   signature method, missing parameters, or duplicated protocol
//   parameters.  The server SHOULD return a 401 (Unauthorized) status
//   code when receiving a request with invalid client credentials, an
//   invalid or expired token, an invalid signature, or an invalid or used
//   nonce.
func NewAuthenticatedRequest(r *http.Request, store BackendStore) (q *AuthenticatedRequest, err error) {
	u := ParsingRequest(r, store)
	var ok bool
	ok = u.CheckOAuthVersion()
	if !ok {
		return nil, errors.New("Invalid Request: Unsupported OAuth version")
	}
	ok = u.CheckNonceAndTimestamp()
	if !ok {
		return nil, errors.New("Invalid Request: Bad timestamp/nonce")
	}
	ok = u.CheckSignature()
	if !ok {
		return nil, errors.New("Invalid Request: Bad signature")
	}
	ok = u.CheckToken()
	if !ok {
		return nil, errors.New("Invalid Request: rejected token")
	}
	return &AuthenticatedRequest{r, u.OAuthParameters}, nil
}

//GetOAuthParameter provides a unified access to all oauth parameters present in the request.
// If a parameter is not present in the request, then it returns the empty string and the exists boolean is set to false.
func (req *AuthenticatedRequest) GetOAuthParameter(name string) (value string, exists bool) {
	vals := req.oauthParameters[name]
	if len(vals) == 1 {
		return vals[0], true
	} else {
		return "", false
	}
	panic("unreachable statement")
}

//UnauthenticatedRequest holds all the relevant (for authentication) information, and provide atomic check access. 
// It is not intendent for "normal" use, but to dive into the OAuth intricacies, as defined by the RFC:
//
//   An authenticated request includes several protocol parameters.  Each
//   parameter name begins with the "oauth_" prefix, and the parameter
//   names and values are case sensitive.  Clients make authenticated
//   requests by calculating the values of a set of protocol parameters
//   and adding them to the HTTP request as follows:
//
//   1.  The client assigns value to each of these REQUIRED (unless
//       specified otherwise) protocol parameters:
//
//       oauth_consumer_key
//         The identifier portion of the client credentials (equivalent to
//         a username).  The parameter name reflects a deprecated term
//         (Consumer Key) used in previous revisions of the specification,
//         and has been retained to maintain backward compatibility.
//
//       oauth_token
//         The token value used to associate the request with the resource
//         owner.  If the request is not associated with a resource owner
//         (no token available), clients MAY omit the parameter.
//
//       oauth_signature_method
//         The name of the signature method used by the client to sign the
//         request, as defined in Section 3.4.
//
//       oauth_timestamp
//         The timestamp value as defined in Section 3.3.  The parameter
//         MAY be omitted when using the "PLAINTEXT" signature method.
//
//       oauth_nonce
//         The nonce value as defined in Section 3.3.  The parameter MAY
//         be omitted when using the "PLAINTEXT" signature method.
//
//       oauth_version
//         OPTIONAL.  If present, MUST be set to "1.0".  Provides the
//         version of the authentication process as defined in this
//         specification.
//
//   2.  The protocol parameters are added to the request using one of the
//       transmission methods listed in Section 3.5.  Each parameter MUST
//       NOT appear more than once per request.
//
//   3.  The client calculates and assigns the value of the
//       "oauth_signature" parameter as described in Section 3.4 and adds
//       the parameter to the request using the same method as in the
//       previous step.
//
//   4.  The client sends the authenticated HTTP request to the server.
//
//   For example, to make the following HTTP request authenticated (the
//   "c2&a3=2+q" string in the following examples is used to illustrate
//   the impact of a form-encoded entity-body):
//
//     POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
//     Host: example.com
//     Content-Type: application/x-www-form-urlencoded
//
//     c2&a3=2+q
//
//
//   The client assigns values to the following protocol parameters using
//   its client credentials, token credentials, the current timestamp, a
//   uniquely generated nonce, and indicates that it will use the
//   "HMAC-SHA1" signature method:
//
//     oauth_consumer_key:     9djdj82h48djs9d2
//     oauth_token:            kkk9d7dh3k39sjv7
//     oauth_signature_method: HMAC-SHA1
//     oauth_timestamp:        137131201
//     oauth_nonce:            7d8f3e4a
//
//   The client adds the protocol parameters to the request using the
//   OAuth HTTP "Authorization" header field:
//
//     Authorization: OAuth realm="Example",
//                    oauth_consumer_key="9djdj82h48djs9d2",
//                    oauth_token="kkk9d7dh3k39sjv7",
//                    oauth_signature_method="HMAC-SHA1",
//                    oauth_timestamp="137131201",
//                    oauth_nonce="7d8f3e4a"
//
//   Then, it calculates the value of the "oauth_signature" parameter
//   (using client secret "j49sk3j29djd" and token secret "dh893hdasih9"),
//   adds it to the request, and sends the HTTP request to the server:
//
//     POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
//     Host: example.com
//     Content-Type: application/x-www-form-urlencoded
//     Authorization: OAuth realm="Example",
//                    oauth_consumer_key="9djdj82h48djs9d2",
//                    oauth_token="kkk9d7dh3k39sjv7",
//                    oauth_signature_method="HMAC-SHA1",
//                    oauth_timestamp="137131201",
//                    oauth_nonce="7d8f3e4a",
//                    oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
//
//     c2&a3=2+q
//
// Usage:
//
// Call the ParsingRequest function to instanciate a valid UnauthenticatedRequest. You can then use it to query parameters, and/or do some checks.
type UnauthenticatedRequest struct {
	*http.Request                // to gain full access to the http.Request 
	OAuthParameters url.Values   // after parsing, contains a uniform access to all oauth parameters but oauth_signature
	OtherParameters url.Values   // any other parameters found during the parsing
	Realm           string       // realm as parsed in header authentication
	Method          string       // uppercased version of the request method
	Signature       string       //received signature
	store           BackendStore // when parsing a request we need to resolve some key -> value stuff (like consumer_id consumer_secret )
}

//ParsingRequest reads from an anctual http.Request and turn it into a UnauthenticatedRequest.
func ParsingRequest(r *http.Request, store BackendStore) (q *UnauthenticatedRequest) {
	q = &UnauthenticatedRequest{
		Request: r,
		Method:  strings.ToUpper(r.Method),
		store:   store,
	}
	q.parseParameterTransmission()
	return
}

//CheckOAuthVersion checks oauth version 1.0 as stated in the RFC
//
//    If the "oauth_version" parameter is present, ensuring its value is "1.0".
func (u *UnauthenticatedRequest) CheckOAuthVersion() bool {
	version, ok := u.GetOAuthParameter("oauth_version")
	return !ok || version == "1.0"
}

//CheckToken checks the oauth token
//
//      if a token is present, verifying the scope and status of the
//      client authorization as represented by the token (the server MAY
//      choose to restrict token usage to the client to which it was
//      issued).
func (u *UnauthenticatedRequest) CheckToken() bool {
	token, ok_token := u.GetOAuthParameter("oauth_token")
	consumer_key, ok_consumer := u.GetOAuthParameter("oauth_consumer_key") //consumer is required
	return ok_consumer && (!ok_token || u.store.ValidateToken(token, consumer_key))
}

//CheckNonceAndTimestamp checks the timestamp and Nonce parameters
//
//   The timestamp value MUST be a positive integer.  Unless otherwise
//   specified by the server's documentation, the timestamp is expressed
//   in the number of seconds since January 1, 1970 00:00:00 GMT.
//
//   A nonce is a random string, uniquely generated by the client to allow
//   the server to verify that a request has never been made before and
//   helps prevent replay attacks when requests are made over a non-secure
//   channel.  The nonce value MUST be unique across all requests with the
//   same timestamp, client credentials, and token combinations.
//
//   To avoid the need to retain an infinite number of nonce values for
//   future checks, servers MAY choose to restrict the time period after
//   which a request with an old timestamp is rejected.  Note that this
//   restriction implies a level of synchronization between the client's
//   and server's clocks.  Servers applying such a restriction MAY provide
//   a way for the client to sync with the server's clock; alternatively,
//   both systems could synchronize with a trusted time service.  Details
//   of clock synchronization strategies are beyond the scope of this
//   specification.
func (u *UnauthenticatedRequest) CheckNonceAndTimestamp() bool {
	var timestamps, nonce, consumer_key, token_key string
	var ok bool
	if timestamps, ok = u.GetOAuthParameter("oauth_timestamp"); !ok {
		return false
	}
	timestamp, err := strconv.Atoi(timestamps)
	if err != nil || timestamp < 0 {
		//fmt.Printf("wrong timestamp value %v: err=%v\n", timestamp, err)
		return false
	}
	if nonce, ok = u.GetOAuthParameter("oauth_nonce"); !ok {
		//fmt.Printf("wrong nonce\n")
		return false
	}
	if consumer_key, ok = u.GetOAuthParameter("oauth_consumer_key"); !ok {
		//fmt.Printf("wrong consumer key\n")
		return false
	}
	token_key, _ = u.GetOAuthParameter("oauth_token_key") // token key is optional 
	return u.store.Uniqueness(nonce, consumer_key, token_key)
}

//GetOAuthParameter retrieve any oauth parameter, return default if it doesn't exist
func (u *UnauthenticatedRequest) GetOAuthParameter(name string) (value string, exists bool) {
	vals := u.OAuthParameters[name]
	if len(vals) == 1 {
		return vals[0], true
	} else {
		return "", false
	}
	panic("unreachable statement")
}

//CheckSignature checks the signature parameter as defined by the RFC
//
//   OAuth-authenticated requests can have two sets of credentials: those
//   passed via the "oauth_consumer_key" parameter and those in the
//   "oauth_token" parameter.  In order for the server to verify the
//   authenticity of the request and prevent unauthorized access, the
//   client needs to prove that it is the rightful owner of the
//   credentials.  This is accomplished using the shared-secret (or RSA
//   key) part of each set of credentials.
//
//   OAuth provides three methods for the client to prove its rightful
//   ownership of the credentials: "HMAC-SHA1", "RSA-SHA1", and
//   "PLAINTEXT".  These methods are generally referred to as signature
//   methods, even though "PLAINTEXT" does not involve a signature.  In
//   addition, "RSA-SHA1" utilizes an RSA key instead of the shared-
//   secrets associated with the client credentials.
//
//   OAuth does not mandate a particular signature method, as each
//   implementation can have its own unique requirements.  Servers are
//   free to implement and document their own custom methods.
//   Recommending any particular method is beyond the scope of this
//   specification.  Implementers should review the Security
//   Considerations section (Section 4) before deciding on which method to
//   support.
//
//   The client declares which signature method is used via the
//   "oauth_signature_method" parameter.  It then generates a signature
//   (or a string of an equivalent value) and includes it in the
//   "oauth_signature" parameter.  The server verifies the signature as
//   specified for each method.
//
//   The signature process does not change the request or its parameters,
//   with the exception of the "oauth_signature" parameter.
func (u *UnauthenticatedRequest) CheckSignature() bool {
	var method, consumer_key string
	var ok bool
	if method, ok = u.GetOAuthParameter("oauth_signature_method"); !ok {
		return false
	}

	if consumer_key, ok = u.GetOAuthParameter("oauth_consumer_key"); !ok {
		return false
	}

	key := u.store.ConsumerSecret(consumer_key)
	switch method {
	case PLAINTEXT:
		return u.PlainTextSignature(key) == u.Signature
	case HMAC_SHA1:
		//yes the pseudo signature is the key used in hmac_sha1
		return _HMAC_SHA1_Verify(u.SignatureBaseString(), u.PlainTextSignature(key), u.Signature)
	case RSA_SHA1:
		return _RSA_SHA1_Verify(u.SignatureBaseString(), key, u.Signature)
	default:
		return false
	}

	return false
}

//PlainTextSignature returns the string used in PLAINTEXT signature, and also used as key in the HMAC_SHA1. The RFC defines the PLAINTEXT signature as:
//
//   The "PLAINTEXT" method does not employ a signature algorithm.  It
//   MUST be used with a transport-layer mechanism such as TLS or SSL (or
//   sent over a secure channel with equivalent protections).  It does not
//   utilize the signature base string or the "oauth_timestamp" and
//   "oauth_nonce" parameters.
//
//   The "oauth_signature" protocol parameter is set to the concatenated
//   value of:
//
//   1.  The client shared-secret, after being encoded (Section 3.6).
//
//   2.  An "&" character (ASCII code 38), which MUST be included even
//       when either secret is empty.
//
//   3.  The token shared-secret, after being encoded (Section 3.6).
func (u *UnauthenticatedRequest) PlainTextSignature(consumer_secret string) (pseudosignature string) {

	token_share_secret, _ := u.GetOAuthParameter("oauth_token_secret")
	return PercentEncode(consumer_secret) + "&" + PercentEncode(token_share_secret)

}

//SignatureBaseString build the signature base string for HMAC-SHA1 and RSA-SHA1 methods as defined in the RFC:
//
//   The signature base string is a consistent, reproducible concatenation
//   of several of the HTTP request elements into a single string.  The
//   string is used as an input to the "HMAC-SHA1" and "RSA-SHA1"
//   signature methods.
//
//   The signature base string includes the following components of the
//   HTTP request:
//
//   o  The HTTP request method (e.g., "GET", "POST", etc.).
//
//   o  The authority as declared by the HTTP "Host" request header field.
//
//   o  The path and query components of the request resource URI.
//
//   o  The protocol parameters excluding the "oauth_signature".
//
//   o  Parameters included in the request entity-body if they comply with
//      the strict restrictions defined in Section 3.4.1.3.
//
//   The signature base string does not cover the entire HTTP request.
//   Most notably, it does not include the entity-body in most requests,
//   nor does it include most HTTP entity-headers.  It is important to
//   note that the server cannot verify the authenticity of the excluded
//   request components without using additional protections such as SSL/
//   TLS or other methods.
//
//   String Construction
//
//   The signature base string is constructed by concatenating together,
//   in order, the following HTTP request elements:
//
//   1.  The HTTP request method in uppercase.  For example: "HEAD",
//       "GET", "POST", etc.  If the request uses a custom HTTP method, it
//       MUST be encoded (Section 3.6).
//
//   2.  An "&" character (ASCII code 38).
//
//   3.  The base string URI from Section 3.4.1.2, after being encoded
//       (Section 3.6).
//
//   4.  An "&" character (ASCII code 38).
//
//   5.  The request parameters as normalized in Section 3.4.1.3.2, after
//       being encoded (Section 3.6).
//
//   For example, the HTTP request:
//
//     POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
//     Host: example.com
//     Content-Type: application/x-www-form-urlencoded
//     Authorization: OAuth realm="Example",
//                    oauth_consumer_key="9djdj82h48djs9d2",
//                    oauth_token="kkk9d7dh3k39sjv7",
//                    oauth_signature_method="HMAC-SHA1",
//                    oauth_timestamp="137131201",
//                    oauth_nonce="7d8f3e4a",
//                    oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
//
//     c2&a3=2+q
//
//   is represented by the following signature base string (line breaks
//   are for display purposes only):
//
//     POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q
//     %26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_
//     key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m
//     ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk
//     9d7dh3k39sjv7
func (u *UnauthenticatedRequest) SignatureBaseString() string {
	return PercentEncode(strings.ToUpper(u.Method)) + "&" + PercentEncode(u.BaseStringURI()) + "&" + PercentEncode(u.RequestParameters())
}

//BaseStringURI computes the Base string URI required in the Signature base string as defined in the RFC:
//
//   The scheme, authority, and path of the request resource URI [RFC3986]
//   are included by constructing an "http" or "https" URI representing
//   the request resource (without the query or fragment) as follows:
//
//   1.  The scheme and host MUST be in lowercase.
//
//   2.  The host and port values MUST match the content of the HTTP
//       request "Host" header field.
//
//   3.  The port MUST be included if it is not the default port for the
//       scheme, and MUST be excluded if it is the default.  Specifically,
//       the port MUST be excluded when making an HTTP request [RFC2616]
//       to port 80 or when making an HTTPS request [RFC2818] to port 443.
//       All other non-default port numbers MUST be included.
//
//   For example, the HTTP request:
//
//     GET /r%20v/X?id=123 HTTP/1.1
//     Host: EXAMPLE.COM:80
//
//   is represented by the base string URI: "http://example.com/r%20v/X".
//
//   In another example, the HTTPS request:
//
//     GET /?q=1 HTTP/1.1
//     Host: www.example.net:8080
//
//   is represented by the base string URI:
//   "https://www.example.net:8080/".
func (u *UnauthenticatedRequest) BaseStringURI() string {
	return filterBaseStringURI(u.URL).String()
}
func filterBaseStringURI(fullURL *url.URL) (filtered *url.URL) {
	filtered = &url.URL{
		Scheme: strings.ToLower(fullURL.Scheme),
		Host:   strings.ToLower(fullURL.Host),
		Path:   fullURL.Path,
	}
	filtered.Host = portFilter(filtered.Scheme, filtered.Host)
	return
}
func portFilter(scheme, host string) (fhost string) {
	splitted := strings.Split(host, ":")
	switch {
	case len(splitted) == 2 && splitted[1] == "80" && scheme == "http":
		return splitted[0]
	case len(splitted) == 2 && splitted[1] == "443" && scheme == "https":
		return splitted[0]
	default:
		return host
	}
	panic("unreachable statement")
}

//RequestParameters format all the request parameters in the format required by the Signature base string as defined in the RFC:
//
//   In order to guarantee a consistent and reproducible representation of
//   the request parameters, the parameters are collected and decoded to
//   their original decoded form.  They are then sorted and encoded in a
//   particular manner that is often different from their original
//   encoding scheme, and concatenated into a single string.
//
//   Parameter Sources
//
//   The parameters from the following sources are collected into a single
//   list of name/value pairs:
//
//   o  The query component of the HTTP request URI as defined by
//      [RFC3986], Section 3.4.  The query component is parsed into a list
//      of name/value pairs by treating it as an
//      "application/x-www-form-urlencoded" string, separating the names
//      and values and decoding them as defined by
//      [W3C.REC-html40-19980424], Section 17.13.4.
//
//   o  The OAuth HTTP "Authorization" header field (Section 3.5.1) if
//      present.  The header's content is parsed into a list of name/value
//      pairs excluding the "realm" parameter if present.  The parameter
//      values are decoded as defined by Section 3.5.1.
//
//   o  The HTTP request entity-body, but only if all of the following
//      conditions are met:
//
//      *  The entity-body is single-part.
//
//      *  The entity-body follows the encoding requirements of the
//         "application/x-www-form-urlencoded" content-type as defined by
//         [W3C.REC-html40-19980424].
//
//      *  The HTTP request entity-header includes the "Content-Type"
//         header field set to "application/x-www-form-urlencoded".
//
//      The entity-body is parsed into a list of decoded name/value pairs
//      as described in [W3C.REC-html40-19980424], Section 17.13.4.
//
//   The "oauth_signature" parameter MUST be excluded from the signature
//   base string if present.  Parameters not explicitly included in the
//   request MUST be excluded from the signature base string (e.g., the
//   "oauth_version" parameter when omitted).
//
//
//   For example, the HTTP request:
//
//       POST /request?b5=%3D%253D&a3=a&c%40=&a2=r%20b HTTP/1.1
//       Host: example.com
//       Content-Type: application/x-www-form-urlencoded
//       Authorization: OAuth realm="Example",
//                      oauth_consumer_key="9djdj82h48djs9d2",
//                      oauth_token="kkk9d7dh3k39sjv7",
//                      oauth_signature_method="HMAC-SHA1",
//                      oauth_timestamp="137131201",
//                      oauth_nonce="7d8f3e4a",
//                      oauth_signature="djosJKDKJSD8743243%2Fjdk33klY%3D"
//
//       c2&a3=2+q
//
//   contains the following (fully decoded) parameters used in the
//   signature base sting:
//
//               +------------------------+------------------+
//               |          Name          |       Value      |
//               +------------------------+------------------+
//               |           b5           |       =%3D       |
//               |           a3           |         a        |
//               |           c@           |                  |
//               |           a2           |        r b       |
//               |   oauth_consumer_key   | 9djdj82h48djs9d2 |
//               |       oauth_token      | kkk9d7dh3k39sjv7 |
//               | oauth_signature_method |     HMAC-SHA1    |
//               |     oauth_timestamp    |     137131201    |
//               |       oauth_nonce      |     7d8f3e4a     |
//               |           c2           |                  |
//               |           a3           |        2 q       |
//               +------------------------+------------------+
//
//   Note that the value of "b5" is "=%3D" and not "==".  Both "c@" and
//   "c2" have empty values.  While the encoding rules specified in this
//   specification for the purpose of constructing the signature base
//   string exclude the use of a "+" character (ASCII code 43) to
//   represent an encoded space character (ASCII code 32), this practice
//   is widely used in "application/x-www-form-urlencoded" encoded values,
//   and MUST be properly decoded, as demonstrated by one of the "a3"
//   parameter instances (the "a3" parameter is used twice in this
//   request).
//
//   Parameters Normalization
//
//   The parameters collected in Section 3.4.1.3 are normalized into a
//   single string as follows:
//
//   1.  First, the name and value of each parameter are encoded
//       (Section 3.6).
//
//   2.  The parameters are sorted by name, using ascending byte value
//       ordering.  If two or more parameters share the same name, they
//       are sorted by their value.
//
//   3.  The name of each parameter is concatenated to its corresponding
//       value using an "=" character (ASCII code 61) as a separator, even
//       if the value is empty.
//
//   4.  The sorted name/value pairs are concatenated together into a
//       single string by using an "&" character (ASCII code 38) as
//       separator.
//
//   For example, the list of parameters from the previous section would
//   be normalized as follows:
//
//                                 Encoded:
//
//               +------------------------+------------------+
//               |          Name          |       Value      |
//               +------------------------+------------------+
//               |           b5           |     %3D%253D     |
//               |           a3           |         a        |
//               |          c%40          |                  |
//               |           a2           |       r%20b      |
//               |   oauth_consumer_key   | 9djdj82h48djs9d2 |
//               |       oauth_token      | kkk9d7dh3k39sjv7 |
//               | oauth_signature_method |     HMAC-SHA1    |
//               |     oauth_timestamp    |     137131201    |
//               |       oauth_nonce      |     7d8f3e4a     |
//               |           c2           |                  |
//               |           a3           |       2%20q      |
//               +------------------------+------------------+
//
//
//                                  Sorted:
//
//               +------------------------+------------------+
//               |          Name          |       Value      |
//               +------------------------+------------------+
//               |           a2           |       r%20b      |
//               |           a3           |       2%20q      |
//               |           a3           |         a        |
//               |           b5           |     %3D%253D     |
//               |          c%40          |                  |
//               |           c2           |                  |
//               |   oauth_consumer_key   | 9djdj82h48djs9d2 |
//               |       oauth_nonce      |     7d8f3e4a     |
//               | oauth_signature_method |     HMAC-SHA1    |
//               |     oauth_timestamp    |     137131201    |
//               |       oauth_token      | kkk9d7dh3k39sjv7 |
//               +------------------------+------------------+
//
//                            Concatenated Pairs:
//
//                  +-------------------------------------+
//                  |              Name=Value             |
//                  +-------------------------------------+
//                  |               a2=r%20b              |
//                  |               a3=2%20q              |
//                  |                 a3=a                |
//                  |             b5=%3D%253D             |
//                  |                c%40=                |
//                  |                 c2=                 |
//                  | oauth_consumer_key=9djdj82h48djs9d2 |
//                  |         oauth_nonce=7d8f3e4a        |
//                  |   oauth_signature_method=HMAC-SHA1  |
//                  |      oauth_timestamp=137131201      |
//                  |     oauth_token=kkk9d7dh3k39sjv7    |
//                  +-------------------------------------+
//
//   and concatenated together into a single string (line breaks are for
//   display purposes only):
//
//     a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
//     dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
//     &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7
//
//
func (u *UnauthenticatedRequest) RequestParameters() string {

	return formatRequestParameters(u.OAuthParameters, u.OtherParameters)
}

func formatRequestParameters(values ...url.Values) string {

	// the parameters can be found in u.Parameters
	// build the list of key value pair
	kvs := make(kvslice, 0, 100)
	for _, vals := range values {
		for k, v := range vals {
			for _, s := range v { // v is a slice of string, representing several occurence of the same key in the url => hence the inner loop
				fmt.Printf("sign param %v = %v\n", k, s)
				kvs = append(kvs, &kv{
					key:   PercentEncode(k),
					value: PercentEncode(s),
				})
			}
		}
	}
	//step 1/ : accomplished: now kvs is fully generated and key and value are PercentEncoded
	sort.Sort(kvs) // inplace sorting the key value pair
	fmt.Printf("Sorted params \n")
	for _, kv := range kvs {
		fmt.Printf("%v = %v\n", kv.key, kv.value)
	}
	fmt.Printf("Done\n")
	//step 3 
	params := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		params = append(params, kv.String())
	}

	return strings.Join(params, "&")
}

//kv is an internal representation of a key value pair, used to sort the list
type kv struct{ key, value string }

func (k *kv) Less(that *kv) bool {
	//implement the step 2 condition:
	//       The parameters are sorted by name, using ascending byte value
	//       ordering.  If two or more parameters share the same name, they
	//       are sorted by their value.
	if k.key == that.key {
		return k.value < that.value
	}
	return k.key < that.key
}
func (k *kv) String() string {
	return fmt.Sprintf("%s=%s", k.key, k.value)
}

type kvslice []*kv              //make it sortable
func (s kvslice) Len() int      { return len(s) }
func (s kvslice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s kvslice) Less(i, j int) bool {
	return s[i].Less(s[j])
}

//parseParameterTransmission parses all the authentication parameters and make them available regardless of where thy come from.
//
//   When making an OAuth-authenticated request, protocol parameters as
//   well as any other parameter using the "oauth_" prefix SHALL be
//   included in the request using one and only one of the following
//   locations, listed in order of decreasing preference:
//
//   1.  The HTTP "Authorization" header field as described in
//       Section 3.5.1.
//
//   2.  The HTTP request entity-body as described in Section 3.5.2.
//
//
//   3.  The HTTP request URI query as described in Section 3.5.3.
//
//   In addition to these three methods, future extensions MAY define
//   other methods for including protocol parameters in the request.
func (u *UnauthenticatedRequest) parseParameterTransmission() (err error) {
	//implementation note: should be called only once.
	//decided which of the three above
	u.OtherParameters = make(url.Values)
	// parse all parameters
	oauthBodyParam, err := u.parseFormEncodedBody() // read all non oauth parameters into u.OtherParameters return the possible  oauth candidate
	if err != nil {
		return
	}
	oauthQueryParam := u.parseRequestURIQuery() // read all non oauth parameters from 
	oauthHeaderParam := u.parseAuthorizationHeader()
	// only one of the three oatuh values is valid, in the following order

	switch {
	case len(oauthHeaderParam) > 0:
		u.OAuthParameters = oauthHeaderParam
	case len(oauthBodyParam) > 0:
		u.OAuthParameters = oauthBodyParam
	case len(oauthQueryParam) > 0:
		u.OAuthParameters = oauthQueryParam
	default:
		return notAnOAuthRequest
	}
	// remove the oauthsignature, and move it to "signature field"
	if signature, ok := u.GetOAuthParameter("oauth_signature"); ok {
		u.Signature = signature
		delete(u.OAuthParameters, "oauth_signature")
	}
	return
}

//parseAuthorizationHeader
//
//   Protocol parameters can be transmitted using the HTTP "Authorization"
//   header field as defined by [RFC2617] with the auth-scheme name set to
//   "OAuth" (case insensitive).
//
//   For example:
//
//     Authorization: OAuth realm="Example",
//        oauth_consumer_key="0685bd9184jfhq22",
//        oauth_token="ad180jjd733klru7",
//        oauth_signature_method="HMAC-SHA1",
//        oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
//        oauth_timestamp="137131200",
//        oauth_nonce="4572616e48616d6d65724c61686176",
//        oauth_version="1.0"
//
//   Protocol parameters SHALL be included in the "Authorization" header
//   field as follows:
//
//   1.  Parameter names and values are encoded per Parameter Encoding
//       (Section 3.6).
//
//   2.  Each parameter's name is immediately followed by an "=" character
//       (ASCII code 61), a """ character (ASCII code 34), the parameter
//       value (MAY be empty), and another """ character (ASCII code 34).
//
//   3.  Parameters are separated by a "," character (ASCII code 44) and
//       OPTIONAL linear whitespace per [RFC2617].
//
//   4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
//       [RFC2617] section 1.2.
//
//   Servers MAY indicate their support for the "OAuth" auth-scheme by
//   returning the HTTP "WWW-Authenticate" response header field upon
//   client requests for protected resources.  As per [RFC2617], such a
//   response MAY include additional HTTP "WWW-Authenticate" header
//   fields:
//
//   For example:
//
//     WWW-Authenticate: OAuth realm="http://server.example.com/"
//
//   The realm parameter defines a protection realm per [RFC2617], Section
//   1.2.
func (u *UnauthenticatedRequest) parseAuthorizationHeader() (vals url.Values) {
	auth := u.Header.Get("Authorization")
	realm, vals, err := _parseAuthorizationHeader(auth)
	// realm is not checked, yet. I don't know how
	// as said [here](http://stackoverflow.com/questions/8577428/what-does-oauth-1-0-realm-stands-for)
	// the realm mostly exists for basic auth, not for oauth. 
	if err != nil {
		return
	}
	u.Realm = realm
	return
}

//separated for testability purpose
func _parseAuthorizationHeader(header string) (realm string, values url.Values, err error) {
	//first split into 
	x := strings.Split(header, ",")
	method, params := x[0], x[1:]
	//method contains OAuth realm="toto"
	margs := realmExp.FindStringSubmatch(method)
	if margs == nil || margs[1] != "OAuth" {
		err = errors.New("invalid Authorization Header auth-scheme: " + method)
		return
	} else if len(margs) > 3 {
		realm = margs[3]
	}
	values = make(url.Values)
	for _, p := range params {
		pargs := paramExp.FindStringSubmatch(p)
		values[pargs[1]] = []string{PercentDecode(pargs[2])}
	}
	return
}

//parseFormEncodedBody
//
//   Protocol parameters can be transmitted in the HTTP request entity-
//   body, but only if the following REQUIRED conditions are met:
//
//   o  The entity-body is single-part.
//
//   o  The entity-body follows the encoding requirements of the
//      "application/x-www-form-urlencoded" content-type as defined by
//      [W3C.REC-html40-19980424].
//
//   o  The HTTP request entity-header includes the "Content-Type" header
//      field set to "application/x-www-form-urlencoded".
//
//   For example (line breaks are for display purposes only):
//
//     oauth_consumer_key=0685bd9184jfhq22&oauth_token=ad180jjd733klr
//     u7&oauth_signature_method=HMAC-SHA1&oauth_signature=wOJIO9A2W5
//     mFwDgiDvZbTSMK%2FPY%3D&oauth_timestamp=137131200&oauth_nonce=4
//     572616e48616d6d65724c61686176&oauth_version=1.0
//
//   The entity-body MAY include other request-specific parameters, in
//   which case, the protocol parameters SHOULD be appended following the
//   request-specific parameters, properly separated by an "&" character
//   (ASCII code 38).
func (u *UnauthenticatedRequest) parseFormEncodedBody() (oauthVals url.Values, err error) {
	content, _, _ := mime.ParseMediaType(u.Header.Get("Content-Type"))
	if content != "application/x-www-form-urlencoded" {
		return
	}

	body, err := ioutil.ReadAll(u.Body)
	defer u.Body.Close() // caveat this means that the body is no longer readable
	if err != nil {
		return
	}

	vals, err := url.ParseQuery(string(body))
	return u.filterOAuth(vals), nil
}

//parseRequestURIQuery
//
//   Protocol parameters can be transmitted by being added to the HTTP
//   request URI as a query parameter as defined by [RFC3986], Section 3.
//
//   For example (line breaks are for display purposes only):
//
//     GET /example/path?oauth_consumer_key=0685bd9184jfhq22&
//     oauth_token=ad180jjd733klru7&oauth_signature_method=HM
//     AC-SHA1&oauth_signature=wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%
//     3D&oauth_timestamp=137131200&oauth_nonce=4572616e48616
//     d6d65724c61686176&oauth_version=1.0 HTTP/1.1
//
//   The request URI MAY include other request-specific query parameters,
//   in which case, the protocol parameters SHOULD be appended following
//   the request-specific parameters, properly separated by an "&"
//   character (ASCII code 38).
//
//Implementation note: we totally rely on net/http .
func (u *UnauthenticatedRequest) parseRequestURIQuery() (oauthVals url.Values) {
	vals := u.URL.Query()
	return u.filterOAuth(vals)
}

//filterOAuth append the values to the current OtherParameters values, except for the oauth ones, that are returned
func (u *UnauthenticatedRequest) filterOAuth(vals url.Values) (oauthVals url.Values) {
	oauthVals = make(url.Values)
	for k, v := range vals {
		if strings.HasPrefix(k, "oauth_") {
			oauthVals[k] = v
		} else {
			u.OtherParameters[k] = append(u.OtherParameters[k], v...)
		}
	}
	return
}

//PercentEncode convert any string into the percent-encoding format as defined in the RFC:
//
//   Existing percent-encoding methods do not guarantee a consistent
//   construction of the signature base string.  The following percent-
//   encoding method is not defined to replace the existing encoding
//   methods defined by [RFC3986] and [W3C.REC-html40-19980424].  It is
//   used only in the construction of the signature base string and the
//   "Authorization" header field.
//
//   This specification defines the following method for percent-encoding
//   strings:
//
//   1.  Text values are first encoded as UTF-8 octets per [RFC3629] if
//       they are not already.  This does not include binary values that
//       are not intended for human consumption.
//
//   2.  The values are then escaped using the [RFC3986] percent-encoding
//       (%XX) mechanism as follows:
//
//       *  Characters in the unreserved character set as defined by
//          [RFC3986], Section 2.3 (ALPHA, DIGIT, "-", ".", "_", "~") MUST
//          NOT be encoded.
//
//       *  All other characters MUST be encoded.
//
//       *  The two hexadecimal characters used to represent encoded
//          characters MUST be uppercase.
//
//   This method is different from the encoding scheme used by the
//   "application/x-www-form-urlencoded" content-type (for example, it
//   encodes space characters as "%20" and not using the "+" character).
//   It MAY be different from the percent-encoding functions provided by
//   web-development frameworks (e.g., encode different characters, use
//   lowercase hexadecimal characters).
func PercentEncode(src string) (encoded string) {
	t := make([]byte, 0, 3*len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		if isEscapable(c) {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		} else {
			t = append(t, src[i])
		}
	}
	return string(t)
}

func isEscapable(b byte) bool {
	return !('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~')

}

//PercentDecode decodes any percent-encoded string into the original value. See PercentEncode for more details.
func PercentDecode(src string) (decoded string) {
	decoded, _ = url.QueryUnescape(src)
	return
}

//Verify the source of the message based on the public key associated with 
func _RSA_SHA1_Verify(message, key, signature string) bool {
	//key is ignored in rsa_sha1
	keybytes, err := base64.StdEncoding.DecodeString(key)
	publicKey, err := x509.ParsePKIXPublicKey(keybytes)
	rsaPublicKey := publicKey.(*rsa.PublicKey)
	hashfun := sha1.New()
	hashfun.Write([]byte(message))
	hashed := hashfun.Sum(nil)

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA1, hashed, sig)
	return err == nil
}

func _HMAC_SHA1_Verify(message, key, signature string) bool {
	hashfun := hmac.New(sha1.New, []byte(key))
	hashfun.Write([]byte(message))
	rawsignature := hashfun.Sum(nil)
	sig := base64.StdEncoding.EncodeToString(rawsignature)
	fmt.Printf("signature = %v ?=? %v : %v\n", sig, signature, sig == signature)
	return sig == signature
}
