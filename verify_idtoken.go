package gogoogleidtoken

import (
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

func VerifyIdToken(idtoken *string) (GoogleClaims, error) {
	// Validate idtoken
	claimsStruct := GoogleClaims{}
	_, err := jwt.ParseWithClaims(
		*idtoken,
		&claimsStruct,
		func(token *jwt.Token) (interface{}, error) {
			pem, err := GetGooglePublicKey(fmt.Sprintf("%s", token.Header["kid"]))
			if err != nil {
				return nil, err
			}
			key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
			if err != nil {
				return nil, err
			}
			return key, nil
		},
	)
	if err != nil {
		return GoogleClaims{}, err
	}

	return claimsStruct, nil
}
