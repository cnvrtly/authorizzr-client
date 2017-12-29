package authorizzr_client

import (
	"net/http"
	"github.com/cnvrtly/adaptr"
	"errors"
	"encoding/json"
	"google.golang.org/appengine/urlfetch"
	"context"
	"strings"
	"io/ioutil"
	"github.com/dgrijalva/jwt-go"
)

func ValidateToken(tokenCtxKey interface{}, authorizzrCheckTokenUrl string, apiKey string) adaptr.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tknCtxVal := r.Context().Value(tokenCtxKey)
			if tknCtxVal != nil && isTokenValid(r.Context(), tknCtxVal.(string), authorizzrCheckTokenUrl, apiKey) == nil {
				h.ServeHTTP(w, r)
				return
			}
			http.Error(w, "Not authorized", http.StatusForbidden)
		})
	}
}

func isTokenValid(ctx context.Context, token string, authorizzrCheckTokenUrl string, apiKey string) error {
	//TODO add memcache that expires at token time
	if token == "" || authorizzrCheckTokenUrl == "" || apiKey == "" {
		return errors.New("no token value")
	}

	bodyJson, err := json.Marshal(map[string]string{
		"token":  token,
		"apiKey": apiKey,
	})
	if err != nil {
		return err
	}
	client := urlfetch.Client(ctx)
	response, err := client.Post(authorizzrCheckTokenUrl, "application/json", strings.NewReader(string(bodyJson)))
	if err != nil {
		//fmt.Println("AUTH ERR=",err.Error())
		return err
	}
	defer response.Body.Close()

	responseJson, err := ioutil.ReadAll(response.Body)

	//fmt.Println("CHECKING AUTH resp=", string(responseJson),"err=",err, "apiKey=", apiKey, " token=",token)

	if err == nil && string(responseJson) != `{"valid":true}` {
		err=errors.New(string(responseJson))
	}
	if err != nil {
		return err
	}

	return nil
}

func UserIdentAndAudience2Ctx(ctxTokenKey interface{}, ctxUserIdentKey interface{}, tknAudKey ) adaptr.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tknClaims, err := GetRawTokenClaims(adaptr.GetCtxValue(r, ctxTokenKey).(string))
			if err != nil {
				http.Error(w, "can not get tkn claims err="+err.Error(), http.StatusBadRequest)
				return
			}

			userIdent := tknClaims.Subject
			if userIdent == "" {
				http.Error(w, "empty user ident in token", http.StatusBadRequest)
				return
			}
			_, _, err = apiKey.ParseUserIdent(userIdent)
			if err != nil {
				http.Error(w, "user ident err="+err.Error(), http.StatusBadRequest)
				return
			}

			audience := tknClaims.Audience
			if audience == "" {
				http.Error(w, "empty audience in token", http.StatusBadRequest)
				return
			}

			_, err = apiKey.ParseWorkspaceIdentString(audience)
			if err != nil {
				http.Error(w, "audience parse err="+err.Error(), http.StatusBadRequest)
				return
			}

			h.ServeHTTP(w, adaptr.SetCtxValue(adaptr.SetCtxValue(r, ctxUserIdentKey, userIdent), tknAudKey, audience))
		})
	}
}

func getTokenPayloadPartRaw(rawJWToken string) (string, error) {
	if len(rawJWToken) < 5 {
		return "", errors.New("token length too small")
	}
	if strings.Count(rawJWToken, ".") != 2 {
		return "", ErrNotAToken
	}
	rawSplit := strings.Split(rawJWToken, ".")
	return rawSplit[1], nil
}

func GetRawTokenClaims(rawJWToken string) (*jwt.StandardClaims, error) {
	var claims *jwt.StandardClaims = nil
	payloadRaw, err := getTokenPayloadPartRaw(rawJWToken)
	if err != nil {
		return claims, err
	}

	payloadStr, err := jwt.DecodeSegment(payloadRaw)
	if err != nil {
		return claims, fmt.Errorf("err decoding tkn payload err=%v", err)
	}
	claims = &jwt.StandardClaims{}
	err = json.Unmarshal([]byte(payloadStr), claims)
	if err != nil {
		return claims, fmt.Errorf("GetRawTokenClaims unmarshall err=%v \n payload=%v", err, string(payloadStr))
	}
	return claims, nil
}
