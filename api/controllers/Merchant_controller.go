package controllers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"net/url"
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
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		// dsn = "127.0.0.1:6379"
		dsn = "my-cluster-usahaku.uh8ptm.0001.apse1.cache.amazonaws.com:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn,
	})
	_, err := client.Ping().Result()
	if err != nil {
		fmt.Println(err)
	}
}

type Value struct {
	Message string `json:"message"`
	User_id string `json:"user_id"`
}
type Address1 struct {
	Alamat   string `json:"alamat"`
	Kota     string `json:"kota"`
	Provinsi string `json:"provinsi"`
}
type Subscribers1 struct {
	User_id          string   `json:"user_id"`
	Email            string   `json:"email"`
	Owner_name       string   `json:"owner_name"`
	Secret_password  string   `json:"secret_password"`
	Fcm_token        string   `json:"fcm_token"`
	Idcard_name      string   `json:"Idcard_name"`
	Idcard_number    string   `json:"Idcard_number"`
	Bank_holder_name string   `json:"bank_holder_name"`
	Bank_name        string   `json:"bank_name"`
	Bank_account     string   `json:"Bank_account"`
	Idcard_image     []string `json:"idcard_image"`
	Referral_code    string   `json:"referral_code"`
}

func (server *Server) UpdatePassword(c *gin.Context) {
	tokenBearer := strings.TrimSpace(c.Request.Header.Get("Authorization"))
	tokenString := strings.Split(tokenBearer, " ")[1]
	token, err := jwt.Parse(tokenString, nil)
	if err == nil {
		c.JSON(http.StatusOK, "Token")

	}
	claims, _ := token.Claims.(jwt.MapClaims)
	var input models.FormUpdatePassword
	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not decode input"})
		return
	}
	password := input.Secret_password

	formerMerchant := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("email = ?", claims["email"]).Take(&formerMerchant).Error
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "Failed",
			"error":  "Token Not Valid",
		})
		return
	}

	server.DB.Debug().Model(&models.Subscribers{}).Where("email = ?", claims["email"]).Take(&models.Subscribers{}).UpdateColumns(
		map[string]interface{}{
			"secret_password": input.Secret_password,
		},
	)
	id_user := fmt.Sprintf("%s", claims["user_id"])
	emailuser := fmt.Sprintf("%s", claims["email"])
	owneruser := fmt.Sprintf("%s", claims["owner_name"])

	in := Subscribers1{
		User_id:          id_user,
		Email:            emailuser,
		Owner_name:       owneruser,
		Secret_password:  password,
		Fcm_token:        "",
		Idcard_name:      "",
		Idcard_number:    "",
		Bank_holder_name: "",
		Bank_name:        "",
		Bank_account:     "",
		Idcard_image:     []string{"https://www.generationsforpeace.org/wp-content/uploads/2018/07/empty.jpg"},
		Referral_code:    "99usahaku",
	}
	b, err := json.Marshal(in)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}
	var jsonstr = []byte(b)
	req, err := http.NewRequest("POST", "https://artaka-api.com/api/subscriber/add", bytes.NewBuffer(jsonstr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	// defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
	value := Value{}
	_ = json.Unmarshal(body, &value)
	if value.Message == "outlet already exists" {
		c.JSON(http.StatusOK, gin.H{
			"status":   "failed",
			"response": "subscribers already exist",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"response": "subscribers Created",
		})
	}
}
func (server *Server) UpdateOutlet(c *gin.Context) {
	tokenBearer := strings.TrimSpace(c.Request.Header.Get("Authorization"))
	tokenString := strings.Split(tokenBearer, " ")[1]
	token, err := jwt.Parse(tokenString, nil)
	if err == nil {
		c.JSON(http.StatusOK, "Token")

	}
	claims, _ := token.Claims.(jwt.MapClaims)
	var input models.FormUpdateOutlet
	if err := c.ShouldBindJSON(&input); err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not decode input"})
		return
	}

	formerMerchant := models.Subscribers{}
	err = server.DB.Debug().Model(models.Subscribers{}).Where("email = ?", claims["email"]).Take(&formerMerchant).Error
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status": "Failed",
			"error":  "Token Not Valid",
		})
		return
	}
	id_user := fmt.Sprintf("%s", claims["user_id"])
	phone := id_user
	if phone[:1] == "0" {
		phone = "+62" + phone[1:]
	} else if phone[:1] == "6" {
		phone = "+62" + phone[2:]
	}

	acc := Accounts{
		KasBank:             0,
		Aset:                0,
		Piutang:             0,
		Hutang:              0,
		AccountingStartDate: "Account Start Date",
	}
	in := Outlets{
		UserID:              phone,
		Accounts:            acc,
		Nama:                input.Nama_outlet,
		Phone:               phone,
		BusinessCategory:    input.Business_category,
		Address:             input.Address,
		IsActive:            "Yes",
		FcmToken:            "",
		Images:              []string{"https://www.generationsforpeace.org/wp-content/uploads/2018/07/empty.jpg"},
		MiniWebsiteUrl:      input.Mini_website_url,
		IsOnlineStoreActive: input.IsActive,
	}
	b, err := json.Marshal(in)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}
	var jsonstr = []byte(b)
	req, err := http.NewRequest("POST", "https://artaka-api.com/api/outlet/add", bytes.NewBuffer(jsonstr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	// defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(body))
	value := Value{}
	_ = json.Unmarshal(body, &value)
	if value.Message == "outlet already exists" {
		c.JSON(http.StatusOK, gin.H{
			"status":   "failed",
			"response": "outlet already exist",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"response": "Outlet Created",
		})
	}
}

const USERNAME = "integrateartaka"
const PASSWORD = "gKOAFuXVSjOzUnzjTeMe"

func (server *Server) GetToken(c *gin.Context) {
	grant := c.PostForm("grant_type")
	scope := c.PostForm("scope")
	username, password, ok := c.Request.BasicAuth()
	isValid := (username == USERNAME) && (password == PASSWORD)
	if !ok {
		c.JSON(http.StatusCreated, gin.H{
			"success":   "False",
			"errorCode": "ACCOUNT_NOT_FOUND",
		})
	} else if !isValid {
		c.JSON(http.StatusCreated, gin.H{
			"success":   "False",
			"errorCode": "NOT_FOUND",
		})
	} else if grant != "client_credentials" {
		restErr := errors.RestErr{
			Message: "Please Check Client Credentials",
			Status:  "Failed",
			Error:   "True",
		}
		c.JSON(http.StatusOK, restErr)
		return
	} else if scope != "post_subscription_events" {
		restErr := errors.RestErr{
			Message: "Please Check Scope",
			Status:  "Failed",
			Error:   "True",
		}
		c.JSON(http.StatusOK, restErr)
		return
	} else {
		tokenInfo, err := CreateToken(rand.Uint32(), "gunturkurniawan238@gmail.com", "guntur", "+6281290858472")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		err = CreateAuth("1", tokenInfo)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		token, err := jwt.Parse(tokenInfo.AccessToken, nil)
		claims, _ := token.Claims.(jwt.MapClaims)
		exp := fmt.Sprintf("%0.f", claims["exp"])

		result := map[string]string{
			"success":      "true",
			"access_token": tokenInfo.AccessToken,
			"expires_in":   exp,
			"scope":        scope,
		}
		c.JSON(http.StatusOK, result)
	}
}

func dumpMap(space string, m map[string]interface{}) {
	for k, v := range m {
		if mv, ok := v.(map[string]interface{}); ok {
			fmt.Printf("{ \"%v\": \n", k)
			dumpMap(space+"\t", mv)
			fmt.Printf("}\n")
		} else {
			fmt.Printf("%v %v : %v\n", space, k, v)
		}
	}
}

type Outlets struct {
	UserID              string `json:"user_id"`
	Nama                string `json:"nama"`
	Phone               string `json:"phone"`
	BusinessCategory    string `json:"business_category"`
	Address             string `json:"address"`
	IsActive            string `json:"is_active"`
	Accounts            Accounts
	FcmToken            string   `json:"fcm_token"`
	Images              []string `json:"images"`
	MiniWebsiteUrl      string   `json:"mini_website_url"`
	IsOnlineStoreActive string   `json:"is_online_store_active"`
}
type Accounts struct {
	KasBank             int    `json:"kas_bank"`
	Aset                int    `json:"aset"`
	Piutang             int    `json:"piutang"`
	Hutang              int    `json:"hutang"`
	AccountingStartDate string `json:"accounting_start_date"`
}
type Payment struct {
	User_id        string `json:"user_id"`
	Payment_status string `json:"payment_status"`
}

func (server *Server) CreateUsahaku(c *gin.Context) {
	var acc99 string
	apiUrl := "https://api.digitalcore.telkomsel.com/isv_fulfilment/oauth2/token"
	data1 := url.Values{}
	data1.Set("grant_type", "client_credentials")
	data1.Add("scope", "ROLE_APPLICATION")

	u, _ := url.ParseRequestURI(apiUrl)
	u.RawQuery = data1.Encode()
	urlStr := fmt.Sprintf("%v", u)

	client := &http.Client{}
	r, _ := http.NewRequest("POST", urlStr, nil)
	r.Header.Add("Authorization", "Basic MVAwVGhaUGZ4TDpnS09BRnVYVlNqT3pVbnpqVGVNZQ==")
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data1.Encode())))

	resp, _ := client.Do(r)
	if resp.StatusCode == http.StatusOK {
		respBody, err := ioutil.ReadAll(resp.Body)
		jsonMap := make(map[string]interface{})
		err = json.Unmarshal(respBody, &jsonMap)
		if err != nil {
			panic(err)
		}
		acc99 = jsonMap["access_token"].(string)
	}
	tokenBearer := strings.TrimSpace(c.Request.Header.Get("Authorization"))
	tokenString := strings.Split(tokenBearer, " ")[1]
	token, err := extractToken(tokenString, "artaka")
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"success":   "false",
			"errorCode": "INVALID_RESPONSE",
			"message":   "invalid token.",
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		id := fmt.Sprintf("%0.f", claims["id"])

		val, err := client.Get(id)
		if err != nil {
			fmt.Println("error")
		}
		if val != nil {
			fmt.Println("error")
		}
	}

	db := server.DB
	eventURL := c.Query("eventUrl")
	r1, err := http.NewRequest("GET", eventURL, nil)
	r1.Header.Add("Authorization", "Bearer "+acc99)
	resp1, _ := client.Do(r1)
	if resp1.StatusCode != 200 {
		c.Status(http.StatusUnauthorized)
		return
	}
	event := models.Event{}
	respBody, _ := ioutil.ReadAll(resp1.Body)
	_ = json.Unmarshal(respBody, &event)
	formerSubscriber := models.Subscribers{}
	if event.Type == "SUBSCRIPTION_ORDER" {

		err = db.Debug().Model(models.Subscribers{}).Where("email = ?", event.Creator.Email).Take(&formerSubscriber).Error
		if err == nil {
			c.JSON(http.StatusOK, gin.H{
				"success":   "false",
				"errorCode": "USER_ALREADY_EXISTS",
				"message":   event.Creator.Address.FullName + " USER_ALREADY_EXISTS IN ARTAKA",
			})
			return
		}

		if event.Creator.Address.Phone == "" && event.Creator.Email == "" && event.Creator.Address.FullName == "" {
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"success":   "false",
				"errorCode": "INVALID_RESPONSE",
				"message":   "The account " + event.Payload.Company.Name + " could not be found.",
			})
			return
		}
		phone := event.Creator.Address.Phone
		if phone[:1] == "0" {
			phone = "+62" + phone[1:]
		} else if phone[:1] == "6" {
			phone = "+62" + phone[2:]
		}
		t := time.Now()
		hasil := db.Create(&models.Subscribers{Create_dtm: time.Now(),
			User_id:          phone,
			Email:            event.Creator.Email,
			Owner_name:       event.Creator.Address.FullName,
			Secret_password:  "",
			Fcm_token:        "",
			Idcard_name:      "",
			Idcard_number:    "",
			Bank_holder_name: "",
			Bank_name:        "",
			Bank_account:     "",
			Idcard_image:     json.RawMessage(`["https://www.generationsforpeace.org/wp-content/uploads/2018/07/empty.jpg"]`),
			Referral_code:    event.Creator.Address.Phone + t.Format("01022006")})

		tokenInfo, err := CreateToken(hasil.Value.(*models.Subscribers).ID, event.Creator.Email, event.Creator.FirstName, phone)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		err = CreateAuth(hasil.Value.(*models.Subscribers).Owner_name, tokenInfo)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if tokenInfo.AccessToken != "" {
			from := "artakajurnal@gmail.com"
			password := "Amazon123@"
			to := []string{
				event.Creator.Email,
				"gunturkurniawan238@gmail.com",
			}
			smtpServer := smtpServer{host: "smtp.gmail.com", port: "587"}
			message := []byte("To: Merchant Artaka \r\n" +
				"Subject: Hallo Artaka!\r\n" +
				"\r\n" +
				"This is for update password.\r\n" + "https://master.d3mr68pgup3qa4.amplifyapp.com/reset/" + tokenInfo.AccessToken)
			auth := smtp.PlainAuth("", from, password, smtpServer.host)
			err := smtp.SendMail(smtpServer.Address(), auth, from, to, message)
			if err != nil {
				return
			}
			t := time.Now()
			result := map[string]string{
				"success":           "true",
				"accountIdentifier": event.Creator.Address.Phone + t.Format("01022006"),
			}
			c.JSON(http.StatusOK, result)
		}
	} else {
		event := models.AutoGenerated{}
		respBody, err := ioutil.ReadAll(resp1.Body)
		_ = json.Unmarshal(respBody, &event)
		if event.Type == "SUBSCRIPTION_NOTICE" {
			if event.Payload.Notice.Type == "DEACTIVATED" {
				phone := event.Creator.Address.Phone
				if phone[:1] == "0" {
					phone = "+62" + phone[1:]
				} else if phone[:1] == "6" {
					phone = "+62" + phone[2:]
				}
				if err == nil {
					in := Payment{
						User_id:        "+6282210068315",
						Payment_status: "Not Paid",
					}
					b, err := json.Marshal(in)
					if err != nil {
						fmt.Printf("Error: %s", err)
						return
					}
					var jsonstr = []byte(b)
					req, err := http.NewRequest("POST", "https://artaka-api.com/api/paymentstatus99/set", bytes.NewBuffer(jsonstr))

					req.Header.Set("Content-Type", "application/json")

					client := &http.Client{}
					resp, err := client.Do(req)
					if err != nil {
						panic(err)
					}
					fmt.Println("response Status:", resp.Status)
					fmt.Println("response Headers:", resp.Header)
					// defer resp.Body.Close()
					t := time.Now()
					result := map[string]string{
						"success":           "true",
						"accountIdentifier": event.Creator.Address.Phone + t.Format("01022006"),
					}
					c.JSON(http.StatusOK, result)
				}

			} else if event.Payload.Notice.Type == "REACTIVATED" {
				phone := event.Creator.Address.Phone
				if phone[:1] == "0" {
					phone = "+62" + phone[1:]
				} else if phone[:1] == "6" {
					phone = "+62" + phone[2:]
				}
				in := Payment{
					User_id:        "+6282210068315",
					Payment_status: "Paid",
				}
				b, err := json.Marshal(in)
				if err != nil {
					fmt.Printf("Error: %s", err)
					return
				}
				var jsonstr = []byte(b)
				req, err := http.NewRequest("POST", "https://artaka-api.com/api/paymentstatus99/set", bytes.NewBuffer(jsonstr))

				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					panic(err)
				}
				// defer resp.Body.Close()
				fmt.Println("response Status:", resp.Status)
				fmt.Println("response Headers:", resp.Header)
				t := time.Now()
				result := map[string]string{
					"success":           "true",
					"accountIdentifier": event.Creator.Address.Phone + t.Format("01022006"),
				}
				c.JSON(http.StatusOK, result)
				fmt.Println("email senty")
			} else if event.Payload.Notice.Type == "CLOSED" {
				phone := event.Creator.Address.Phone
				if phone[:1] == "0" {
					phone = "+62" + phone[1:]
				} else if phone[:1] == "6" {
					phone = "+62" + phone[2:]
				}
				in := Payment{
					User_id:        "+6282210068315",
					Payment_status: "Not Paid",
				}
				b, err := json.Marshal(in)
				if err != nil {
					fmt.Printf("Error: %s", err)
					return
				}
				var jsonstr = []byte(b)
				req, err := http.NewRequest("POST", "https://artaka-api.com/api/paymentstatus99/set", bytes.NewBuffer(jsonstr))

				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					panic(err)
				}
				// defer resp.Body.Close()
				fmt.Println("response Status:", resp.Status)
				fmt.Println("response Headers:", resp.Header)
				t := time.Now()
				result := map[string]string{
					"success":           "true",
					"accountIdentifier": event.Creator.Address.Phone + t.Format("01022006"),
				}
				c.JSON(http.StatusOK, result)
			}

		} else if event.Type == "SUBSCRIPTION_CANCEL" {
			phone := event.Creator.Address.Phone
			if phone[:1] == "0" {
				phone = "+62" + phone[1:]
			} else if phone[:1] == "6" {
				phone = "+62" + phone[2:]
			}
			in := Payment{
				User_id:        "+6282210068315",
				Payment_status: "Not Paid",
			}
			b, err := json.Marshal(in)
			if err != nil {
				fmt.Printf("Error: %s", err)
				return
			}
			var jsonstr = []byte(b)
			req, err := http.NewRequest("POST", "https://artaka-api.com/api/paymentstatus99/set", bytes.NewBuffer(jsonstr))

			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				panic(err)
			}
			// defer resp.Body.Close()
			fmt.Println("response Status:", resp.Status)
			fmt.Println("response Headers:", resp.Header)
			t := time.Now()
			result := map[string]string{
				"success":           "true",
				"accountIdentifier": event.Creator.Address.Phone + t.Format("01022006"),
			}
			c.JSON(http.StatusOK, result)
		}
	}

}

type smtpServer struct {
	host string
	port string
}

func (s *smtpServer) Address() string {
	return s.host + ":" + s.port
}

// extractClaims : extract claim from jwt token
func extractToken(jwtToken, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		fmt.Println("error = ", err)
		return nil, err
	}

	return token, nil
}

func CreateToken(id uint32, email string, owner_name string, user_id string) (*models.TokenDetails, error) {
	tokenInfo := &models.TokenDetails{}
	tokenInfo.AccessTokenExpires = time.Now().Add(time.Minute * 15).Unix()

	tokenInfo.RefreshTokenExpires = time.Now().Add(time.Hour * 24 * 7).Unix()

	var err error
	os.Setenv("ACCESS_SECRET", "artaka")
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true

	atClaims["id"] = id
	atClaims["email"] = email
	atClaims["owner_name"] = owner_name
	atClaims["user_id"] = user_id

	atClaims["exp"] = tokenInfo.AccessTokenExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	tokenInfo.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	os.Setenv("REFRESH_SECRET", "artaka")
	rtClaims := jwt.MapClaims{}
	rtClaims["username"] = id
	rtClaims["exp"] = tokenInfo.RefreshTokenExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	tokenInfo.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}

	return tokenInfo, nil
}

func CreateAuth(id string, td *models.TokenDetails) error {
	at := time.Unix(td.AccessTokenExpires, 0)
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
	if err != nil {
		fmt.Println("this is the error creating the token: ", err)
		return nil, err
	}
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
		"status":   "success",
		"response": datas,
		"error":    "null",
	})
}

func (server *Server) GetbyRef(c *gin.Context) {

	errList = map[string]string{}

	referral_code := c.Param("referral_code")
	fmt.Println(">>>>>>>>", referral_code)
	merchant := models.Subscribers{}

	merchantGotten, err := merchant.FindReferral(server.DB, referral_code)
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

func (server *Server) GetMerchant1(c *gin.Context) {

	errList = map[string]string{}

	userID := c.Param("user_id")

	merchant := models.Subscribers{}

	merchantGotten, err := merchant.FindMerchant(server.DB, userID)
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
