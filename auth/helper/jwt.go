package helper

import (
	"fmt"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/constant"
	"github.com/FadhlanHawali/Digitalent-Kominfo_Pendalaman-Rest-API/auth/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"log"
	"net/http"
	"strings"
	"time"
)

//Fungsinya untuk generate Token
func CreateToken(role int, idUsr string)  (error, *database.TokenDetails){
	var roleStr string
	if role == constant.ADMIN{
		roleStr = "admin"
	}else if role == constant.CONSUMER{
		roleStr = "consumer"
	}

	//Token Detail Initialization
	td := &database.TokenDetails{}
	//Set Waktu Access Token Expiry
	td.AtExpires = time.Now().Add(time.Minute *15).Unix()
	//Set Waktu Refresh Token
	td.RtExpires = time.Now().Add(time.Hour).Unix()

	//Set Header + PlayLoad
	at := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"id_user": idUsr,
		"role": role,
		"exp": td.AtExpires,
	})

	//Set Salt
	//Admin Salt -> secret_admin_digitalent
	//Consumer salt -> secret_consumer_digitalent
	var err error
	td.AccesToken, err = at.SignedString([]byte(fmt.Sprintf("secret_%s_digitalent", roleStr))); if err != nil{
		return err, &database.TokenDetails{}
	}

	//Set Header + Payload Refresh Token
	rt := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"id_user": idUsr,
		"role": role,
		"exp": td.RtExpires,
	})
	td.RefreshToken, err = rt.SignedString([]byte(fmt.Sprintf("refresh_secret_%s_digitalent", roleStr))); if err != nil{
		return err, &database.TokenDetails{}
	}
	return nil, td
}

//Extract /parsing ambil data
func ExtractToken(roles int, r *http.Request) string {
	var bearToken string
	//Ambil dari Key Header nya
	if roles == constant.ADMIN{
		bearToken = r.Header.Get("digitalent-admin")
	}else if roles == constant.CONSUMER{
		bearToken = r.Header.Get("digitalent-consumer")
	}

	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}

	return ""
}

//Verivikasi Jenis Token
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	var roleStr string
	var roles int

	if r.Header.Get("digitalent-admin") != ""{
		roleStr = "admin"
		roles = constant.ADMIN
	}else if r.Header.Get("digitalent-consumer") != ""{
		roleStr = "cunsumer"
		roles = constant.CONSUMER
	}else {
		return nil, errors.Errorf("Session Invalid")
	}

	tokenString := ExtractToken(roles, r)
	log.Println(tokenString)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Cek Signing Header apakah HS256
		if jwt.GetSigningMethod("HS256") != token.Method{
			return nil, errors.Errorf("Unexpected signing method ; %v", token.Header["alg"])
		}

		return []byte(fmt.Sprintf("secret_%s_digitalent", roleStr)), nil
	})

	if err != nil{
		return nil, err
	}
	return token, nil
}

//Token Validation /
func TokenValid(r *http.Request) (string, int, error) {
	//manggil fungsi verifikasi
	token, err := VerifyToken(r)
	if err != nil {
		return "", 0, err
	}

	//Proses Claim Playload Data dari Token
	if claims, ok := token.Claims.(jwt.MapClaims);ok && token.Valid{
		idUser, ok := claims["id_user"].(string)
		role, ok := claims["role"]
		if  ! ok {
			return "", 0, nil
		}
		return idUser, int(role.(float64)), nil
	}
	return "", 0, nil
}