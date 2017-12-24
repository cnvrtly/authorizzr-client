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
)

func ValidateToken(tokenCtxKey interface{}, authorizzrCheckTokenUrl string, apiKey string) adaptr.Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tknCtxVal := r.Context().Value(tokenCtxKey)
			if tknCtxVal != nil && isTokenValid(r.Context(), tknCtxVal.(string), authorizzrCheckTokenUrl, apiKey) == nil {
				h.ServeHTTP(w, r)
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
		return err
	}
	defer response.Body.Close()

	responseJson, err := ioutil.ReadAll(response.Body)
	if err != nil || string(responseJson) != `{"valid":true}` {
		return err
	}

	return nil
}
