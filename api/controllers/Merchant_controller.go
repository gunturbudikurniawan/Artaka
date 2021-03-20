package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	"github.com/gunturbudikurniawan/Artaka/api/auth"
	"github.com/gunturbudikurniawan/Artaka/api/models"
	"github.com/gunturbudikurniawan/Artaka/api/security"
	"github.com/gunturbudikurniawan/Artaka/api/utils/errors"
	"github.com/gunturbudikurniawan/Artaka/api/utils/formaterror"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")

var client *redis.Client

func init() {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "usahaku99-ro.uh8ptm.ng.0001.apse1.cache.amazonaws.com:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port
	})
	_, err := client.Ping().Result()
	if err != nil {
		panic(err)
	}
}

func (server *Server) UpdatePassword(c *gin.Context) {
	tokenBearer := strings.TrimSpace(c.Request.Header.Get("Authorization"))
	tokenString := strings.Split(tokenBearer, " ")[1]

	token, err := jwt.Parse(tokenString, nil)
	if err == nil {
		c.JSON(http.StatusOK, "Token")

	}
	claims, _ := token.Claims.(jwt.MapClaims)

	formerSubscribers := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("id = ?", claims["id"]).Take(&formerSubscribers).Error
	if err != nil {
		errList["User_invalid"] = "The user is does not exist"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	var input models.FormUpdatePassword
	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not decode input"})
		return
	}
	pass, err := bcrypt.GenerateFromPassword([]byte(input.Secret_password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password Encryption  failed"})
		return
	}
	input.Secret_password = string(pass)
	server.DB.Debug().Model(&models.Subscribers{}).Where("id = ?", claims["id"]).Take(&models.Subscribers{}).UpdateColumns(
		map[string]interface{}{
			"secret_password": input.Secret_password,
		},
	)
	c.JSON(http.StatusOK, gin.H{"data": "Update successful"})

}

func (server *Server) CreateUsahaku(c *gin.Context) {

	db := server.DB
	keys := c.Request.URL.Query()
	token := keys.Get("token")
	resp, _ := http.Get("https://api.digitalcore.telkomsel.com/preprod-web/isv_fulfilment/events/" + token)
	if resp.StatusCode != 200 {
		c.Status(http.StatusUnauthorized)
		return
	}
	event := models.Event{}
	data, _ := ioutil.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &event)
	x := event.Payload.Company.PhoneNumber
	i := strings.Index(x, "+")
	var phone string
	if i > -1 {
		phone = event.Payload.Company.PhoneNumber
	} else {
		phone = "+" + event.Payload.Company.PhoneNumber
	}
	hasil := db.Create(&models.Subscribers{Create_dtm: time.Now(),
		User_id:          phone,
		Email:            event.Payload.Company.Email,
		Owner_name:       event.Payload.Company.Name,
		Secret_password:  "",
		Fcm_token:        "",
		Idcard_name:      "",
		Idcard_number:    "",
		Bank_holder_name: "",
		Bank_name:        "",
		Bank_account:     "",
		Idcard_image:     json.RawMessage(`["https://www.generationsforpeace.org/wp-content/uploads/2018/07/empty.jpg"]`),
		Referral_code:    ""})

	tokenInfo, err := CreateToken(hasil.Value.(*models.Subscribers).ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	err = CreateAuth(hasil.Value.(*models.Subscribers).Owner_name, tokenInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make(map[string]interface{})
	result["id"] = hasil.Value.(*models.Subscribers).ID
	result["token"] = tokenInfo.AccessToken
	c.JSON(http.StatusOK, result)
	if result["token"] != "" {
		from := "gunturkurniawan238@gmail.com"
		password := "p!Nu$16051995"
		to := []string{
			"gunturbudikurniawan16@gmail.com",
			"gunturkurniawan239@gmail.com",
		}
		smtpServer := smtpServer{host: "smtp.gmail.com", port: "587"}
		message := []byte("To: Merchant Artaka \r\n" +
			"Subject: Hallo Artaka!\r\n" +
			"\r\n" +
			"This is the email body.\r\n" + "https://master.d3mr68pgup3qa4.amplifyapp.com/reset/" + tokenInfo.AccessToken)
		auth := smtp.PlainAuth("", from, password, smtpServer.host)
		err := smtp.SendMail(smtpServer.Address(), auth, from, to, message)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Email Sent!")
	}

}

type smtpServer struct {
	host string
	port string
} // Address URI to smtp server
func (s *smtpServer) Address() string {
	return s.host + ":" + s.port
}

func CreateToken(id uint32) (*models.TokenDetails, error) {
	tokenInfo := &models.TokenDetails{}
	tokenInfo.AccessTokenExpires = time.Now().AddDate(0, 1, 0).Unix()

	tokenInfo.RefreshTokenExpires = time.Now().Add(time.Hour * 24 * 7).Unix()

	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "artaka") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true

	atClaims["id"] = id
	atClaims["exp"] = tokenInfo.AccessTokenExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	tokenInfo.AccessToken, err = at.SignedString([]byte("ACCESS_SECRET"))
	if err != nil {
		return nil, err
	}
	//Creating Refresh Token
	os.Setenv("REFRESH_SECRET", "artaka") //this should be in an env file
	rtClaims := jwt.MapClaims{}
	rtClaims["username"] = id
	rtClaims["exp"] = tokenInfo.RefreshTokenExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	tokenInfo.RefreshToken, err = rt.SignedString([]byte("REFRESH_SECRET"))
	if err != nil {
		return nil, err
	}

	return tokenInfo, nil
}

func CreateAuth(id string, td *models.TokenDetails) error {
	at := time.Unix(td.AccessTokenExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RefreshTokenExpires, 0)
	now := time.Now()

	errAccess := client.Set(id, td.AccessToken, at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	key := "username" + "_refreshtoken"
	errRefresh := client.Set(key, td.RefreshToken, rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}
func (server *Server) CreateMerchants(c *gin.Context) {

	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}

	merchant := models.Subscribers{}

	err = json.Unmarshal(body, &merchant)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  "Failed",
			Error:   "Unmarshal_error",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return

	}
	merchant.Prepare()
	errorMessages := merchant.Validate("")
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	userCreated, err := merchant.SaveUser(server.DB)
	if err != nil {
		formattedError := formaterror.FormatError(err.Error())

		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusInternalServerError,
			"error":  formattedError,
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":   http.StatusCreated,
		"response": userCreated,
	})
}

func (server *Server) LoginMerchant(c *gin.Context) {

	//clear previous error if any
	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":      http.StatusUnprocessableEntity,
			"first error": "Unable to get request",
		})
		return
	}
	merchant := models.Subscribers{}
	err = json.Unmarshal(body, &merchant)
	log.Println(err)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  "Failed",
			Error:   "Unmarshal_error",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return

	}
	merchant.Prepare()
	errorMessages := merchant.Validate("login")
	if len(errorMessages) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errorMessages,
		})
		return
	}
	merchantData, err := server.SignInMerchant(merchant.Email, merchant.Secret_password)
	if err != nil {
		formattedError := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  formattedError,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": merchantData,
	})
}

func (server *Server) SignInMerchant(email, password string) (map[string]interface{}, error) {

	var err error

	merchantData := make(map[string]interface{})

	merchant := models.Subscribers{}

	err = server.DB.Debug().Model(models.Subscribers{}).Where("email = ?", email).Take(&merchant).Error
	if err != nil {
		fmt.Println("this is the error getting the user: ", err)
		return nil, err
	}
	err = security.VerifyPassword(merchant.Secret_password, password)
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		fmt.Println("this is the error hashing the password: ", err)
		return nil, err
	}
	// token, err := auth.CreateToken(merchant.ID)
	if err != nil {
		fmt.Println("this is the error creating the token: ", err)
		return nil, err
	}
	// merchantData["token"] = token
	merchantData["id"] = merchant.ID
	merchantData["email"] = merchant.Email

	return merchantData, nil
}

func (server *Server) UpdateMerchant(c *gin.Context) {

	errList = map[string]string{}

	userID := c.Param("id")
	uid, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Invalid Request",
			Status:  "Failed",
			Error:   "Invalid_request",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return
	}
	tokenID, _, _, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	if tokenID != 0 && tokenID != uint32(uid) {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}

	requestBody := map[string]string{}
	err = json.Unmarshal(body, &requestBody)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  "Failed",
			Error:   "Unmarshal_error",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return

	}
	formerMerchant := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("id = ?", uid).Take(&formerMerchant).Error
	if err != nil {
		errList["User_invalid"] = "The user is does not exist"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}

	newMerchant := models.Subscribers{}

	if requestBody["current_password"] == "" && requestBody["new_password"] != "" {
		errList["Empty_current"] = "Please Provide current password"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	if requestBody["current_password"] != "" && requestBody["new_password"] == "" {
		errList["Empty_new"] = "Please Provide new password"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	if requestBody["current_password"] != "" && requestBody["new_password"] != "" {
		if len(requestBody["new_password"]) < 6 {
			errList["Invalid_password"] = "Password should be atleast 6 characters"
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"status": http.StatusOK,
				"error":  errList,
			})
			return
		}
		//if they do, check that the former password is correct
		err = security.VerifyPassword(formerMerchant.Secret_password, requestBody["current_password"])
		if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
			errList["Password_mismatch"] = "The password not correct"
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"status": http.StatusOK,
				"error":  errList,
			})
			return
		}
		newMerchant.Owner_name = formerMerchant.Owner_name
		newMerchant.Email = requestBody["email"]
		newMerchant.Secret_password = requestBody["new_password"]
	}
	newMerchant.Owner_name = formerMerchant.Owner_name
	newMerchant.Email = requestBody["email"]

	newMerchant.Prepare()
	errorMessages := newMerchant.Validate("update")
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	updatedMerchant, err := newMerchant.UpdateMerchant(server.DB, uint32(uid))
	if err != nil {
		errList := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusInternalServerError,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": updatedMerchant,
	})
}

func (server *Server) CreateSavedOrder(c *gin.Context) {

	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	savedorder := &models.Saved_orders{}
	err = json.Unmarshal(body, &savedorder)
	log.Println(err)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  "Failed",
			Error:   "Unmarshal_error",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return

	}
	uid, _, _, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		log.Println(err)
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	merchant := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("id = ?", uid).Take(&merchant).Error
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	savedorder.User_id = merchant.User_id
	savedorder.Prepare()

	errorMessages := savedorder.Validate()
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	orderCreated, err := savedorder.SaveOrder(server.DB)
	log.Println(err)
	if err != nil {
		log.Println(err)
		errList := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusInternalServerError,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":   http.StatusCreated,
		"response": orderCreated,
	})
}

func (server *Server) CreateSales(c *gin.Context) {

	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	saveSales := &models.Sales{}
	err = json.Unmarshal(body, &saveSales)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  "Failed",
			Error:   "Unmarshal_error",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return

	}
	uid, _, _, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	merchant := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("id = ?", uid).Take(&merchant).Error
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	saveSales.UserID = merchant.User_id
	saveSales.Prepare()

	errorMessages := saveSales.Validate()
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	salesCreated, err := saveSales.SaveSales(server.DB)
	if err != nil {
		errList := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusInternalServerError,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":   http.StatusCreated,
		"response": salesCreated,
	})
}

func (server *Server) CreateOnlineSales(c *gin.Context) {

	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	saveOnlineSales := &models.Onlinesales{}
	err = json.Unmarshal(body, &saveOnlineSales)
	log.Println(err)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  "Failed",
			Error:   "Unmarshal_error",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return

	}
	uid, _, _, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	merchant := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("id = ?", uid).Take(&merchant).Error
	if err != nil {

		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	saveOnlineSales.User_id = merchant.User_id
	saveOnlineSales.Prepare()

	errorMessages := saveOnlineSales.Validate()
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}
	salesOnlineCreated, err := saveOnlineSales.SaveOnlineSales(server.DB)
	if err != nil {
		log.Println(err)
		errList := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusInternalServerError,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":   http.StatusCreated,
		"response": salesOnlineCreated,
		"Error":    "Null",
	})
}
func (server *Server) GetCertainSubscribers(c *gin.Context) {
	// Is this user authenticated?
	_, referral_code, role, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}

	err, datas := models.ShowSubscribers(server.DB, referral_code, role)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Tidak ada merchants",
			"response": "null",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "Success",
		"response": datas,
		"error":    "null",
	})
}

func (server *Server) GetMerchant(c *gin.Context) {

	errList = map[string]string{}

	userID := c.Param("id")

	uid, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Invalid Request",
			Status:  "Failed",
			Error:   "Invalid_request",
		}
		c.JSON(http.StatusBadRequest, restErr)
		return
	}
	merchant := models.Subscribers{}

	merchantGotten, err := merchant.FindMerchantByID(server.DB, uint32(uid))
	if err != nil {
		errList["No_user"] = "No User Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": merchantGotten,
	})
}

func (server *Server) GetLastMerchant(c *gin.Context) {

	transaction := models.Sales{}

	merchantLast, err := transaction.FindSales(server.DB)
	if err != nil {
		errList["No_user"] = "No User Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": merchantLast,
	})
}

func (server *Server) GetLastSaved(c *gin.Context) {

	transaction := models.Saved_orders{}

	merchantLast, err := transaction.FindSaved(server.DB)
	if err != nil {
		errList["No_user"] = "No User Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": merchantLast,
	})
}

func (server *Server) GetLastOnline(c *gin.Context) {

	transaction := models.Onlinesales{}

	merchantLast, err := transaction.FindOnline(server.DB)
	if err != nil {
		errList["No_user"] = "No User Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": merchantLast,
	})
}
