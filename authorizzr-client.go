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
	"fmt"
	"strconv"
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
		err = errors.New(string(responseJson))
	}
	if err != nil {
		return err
	}

	return nil
}

func WorkspaceIdent2Ctx(ctxTokenKey interface{}, ctxWorkspaceIdentKey interface{}, ctxTokenUserIdentKey interface{}) adaptr.Adapter {
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
			_, _, err = ParseUserIdent(userIdent)
			if err != nil {
				http.Error(w, "user ident err="+err.Error(), http.StatusBadRequest)
				return
			}

			audience := tknClaims.Audience
			if audience == "" {
				http.Error(w, "empty audience in token", http.StatusBadRequest)
				return
			}

			wrkspIdent, err := ParseWorkspaceIdentString(audience)
			if err != nil {
				http.Error(w, "workspace ident parse err="+err.Error(), http.StatusBadRequest)
				return
			}

			h.ServeHTTP(w, adaptr.SetCtxValue(adaptr.SetCtxValue(r, ctxTokenUserIdentKey, userIdent), ctxWorkspaceIdentKey, wrkspIdent))
		})
	}
}

func UserIdentAndAudience2Ctx(ctxTokenKey interface{}, ctxUserIdentKey interface{}, ctxAudienceKey interface{}) adaptr.Adapter {
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
			_, _, err = ParseUserIdent(userIdent)
			if err != nil {
				http.Error(w, "user ident err="+err.Error(), http.StatusBadRequest)
				return
			}

			audience := tknClaims.Audience
			if audience == "" {
				http.Error(w, "empty audience in token", http.StatusBadRequest)
				return
			}

			_, err = ParseWorkspaceIdentString(audience)
			if err != nil {
				http.Error(w, "audience parse err="+err.Error(), http.StatusBadRequest)
				return
			}

			h.ServeHTTP(w, adaptr.SetCtxValue(adaptr.SetCtxValue(r, ctxUserIdentKey, userIdent), ctxAudienceKey, audience))
		})
	}
}

func getTokenPayloadPartRaw(rawJWToken string) (string, error) {
	if len(rawJWToken) < 5 {
		return "", errors.New("token length too small")
	}
	if strings.Count(rawJWToken, ".") != 2 {
		return "", errors.New("Not JWT token")
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

func ParseUserIdent(userIdentString string) (namespaceId string, userId int, err error) {
	lastSep := strings.LastIndex(userIdentString, userIdentSeparator)
	if lastSep == -1 {
		return "", 0, errors.New("can not find userIdentSeparator in user ident string")
	}
	if strings.Count(userIdentString, userIdentSeparator) > 2 {
		return "", 0, errors.New("too many user ident separators - only top level users can create sub namespace users")
	}

	namespaceId = userIdentString[0:lastSep]
	userId, err = strconv.Atoi(userIdentString[lastSep+len(userIdentSeparator):])
	if err != nil {
		return "", 0, fmt.Errorf("parsing user ident - userId=%v not number err=%v", userId, err)
	}
	if userId < 0 {
		return "", 0, fmt.Errorf("parsing user ident - user id < 0")
	}
	if namespaceId == "" {
		return "", 0, fmt.Errorf("parsing user ident - namespaceId empty")
	}
	return
}

// nativeTknAudienceValue in form of namespaceId/userId/workspaceName
func ParseWorkspaceIdentString(workspaceIdentString string) (*WorkspaceIdentObject, error) {
	if workspaceIdentString == "" {
		return nil, errors.New("workspaceIdentString is empty")
	}

	lastWrkspSep := strings.LastIndex(workspaceIdentString, workspaceIdentSeparator)
	if lastWrkspSep == -1 {
		return nil, errors.New("no workspace separator found string=" + workspaceIdentString)
	}

	wrksp := workspaceIdentString[lastWrkspSep+len(workspaceIdentSeparator):]
	if strings.Count(workspaceIdentString, workspaceIdentSeparator) > 2 && wrksp != "" {
		return nil, errors.New("too many workspace ident separators - only sub level users can create sub namespace users wrkspIdentStr=" + string(workspaceIdentString))
	}

	permObj := &WorkspaceIdentObject{
		Workspace:       wrksp,
		Value:           WorkspaceIdentString(workspaceIdentString),
		UserIdentString: UserIdentString(workspaceIdentString[0:lastWrkspSep]),
	}

	ns, usrId, err := ParseUserIdent(string(permObj.UserIdentString))
	if err != nil {
		return nil, fmt.Errorf("can not parse userIdent from workspaceIdentString=%v", permObj.UserIdentString)
	}

	permObj.UserId = strconv.Itoa(usrId)
	permObj.UserNamespaceId = ns
	return permObj, nil
}

type WorkspaceIdentObject struct {
	// this is the (parent)namespace under which user was created
	UserNamespaceId string
	// user id number
	UserId string
	// current user's selected workspace
	Workspace string
	// full string raw value that was parsed
	Value WorkspaceIdentString
	// user ident - includes parent workspace path and user id / excludes selected workspace
	UserIdentString UserIdentString
}

type UserIdentString string
type WorkspaceIdentString string

const userIdentSeparator string = "-.-"
const workspaceIdentSeparator string = "._."

func GenerateUserIdentString(userNamespaceId string, userId string) (UserIdentString, error) {
	if userNamespaceId == "" || userId == "" /* || strings.Index(userNamespaceId, userIdentSeparator)!=-1 || strings.Index(userId, userIdentSeparator)!=-1*/ {
		return "", fmt.Errorf("GenerateUserIdentString error value uNS=%v uId=%v", userNamespaceId, userId)
	}
	if strings.Count(userNamespaceId, userIdentSeparator) > 1 {
		return "", errors.New("too many user ident separators in user namespace - only top level users can create sub namespace users")
	}

	usrIdent := userNamespaceId + userIdentSeparator + userId
	/*if strings.Index(usrIdent, workspaceIdentSeparator)!=-1 {
		return "", errors.New("userIdent can not include "+workspaceIdentSeparator+" string")
	}*/
	return UserIdentString(usrIdent), nil
}

func GenerateWorkspaceIdentString(userIdent UserIdentString, currWorkspace string) (WorkspaceIdentString, error) {
	if strings.Count(string(userIdent), workspaceIdentSeparator) > 1 {
		return "", errors.New("too many workspace ident separators in userIdent- only top and sub level users can create namespace ident="+string(userIdent))
	}
	return WorkspaceIdentString(strings.Join([]string{string(userIdent), currWorkspace}, workspaceIdentSeparator)), nil
}