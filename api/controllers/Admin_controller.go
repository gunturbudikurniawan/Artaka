package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gunturbudikurniawan/Artaka/api/auth"
	"github.com/gunturbudikurniawan/Artaka/api/models"
	"github.com/gunturbudikurniawan/Artaka/api/security"
	"github.com/gunturbudikurniawan/Artaka/api/utils/errors"
	"github.com/gunturbudikurniawan/Artaka/api/utils/formaterror"
	"golang.org/x/crypto/bcrypt"
)

func (server *Server) CreateAdmin(c *gin.Context) {
	errList = map[string]string{}
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Invalid Json Body",
			Status:  http.StatusBadRequest,
			Error:   "Bad_request",
		}
		c.JSON(restErr.Status, restErr)
		return
	}
	admin := models.Admin{}
	c.BindJSON(&admin)
	err = json.Unmarshal(body, &admin)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  http.StatusBadRequest,
			Error:   "Unmarshal_error",
		}
		c.JSON(restErr.Status, restErr)
		return

	}
	adminCreated, err := admin.SaveAdmin(server.DB)
	if err != nil {
		formattedError := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status":   http.StatusInternalServerError,
			"error":    formattedError,
			"response": "null",
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":   http.StatusCreated,
		"response": adminCreated,
		"error":    "null",
	})
}

func (server *Server) LoginAdmin(c *gin.Context) {
	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {

		restErr := errors.RestErr{
			Message: "Unable to get request",
			Status:  http.StatusBadRequest,
			Error:   "Unable to get request",
		}
		c.JSON(restErr.Status, restErr)
		return

	}
	admin := models.Admin{}
	err = json.Unmarshal(body, &admin)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Cannot unmarshal body",
			Status:  http.StatusBadRequest,
			Error:   "Unmarshal_error",
		}
		c.JSON(restErr.Status, restErr)
		return

	}
	admin.Prepare()
	errorMessages := admin.Validate("login")
	if len(errorMessages) > 0 {
		c.JSON(http.StatusOK, gin.H{
			"status":   http.StatusInternalServerError,
			"error":    errorMessages,
			"response": "null",
		})
		return
	}
	adminData, err := server.SignIn(admin.Email, admin.Secret_password)
	if err != nil {
		log.Println(err)
		formattedError := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status":   http.StatusInternalServerError,
			"error":    formattedError,
			"response": "null",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": adminData,
	})
}

func (server *Server) SignIn(email string, password string) (map[string]interface{}, error) {
	var err error

	adminData := make(map[string]interface{})

	admin := models.Admin{}

	err = server.DB.Debug().Model(models.Admin{}).Where("email = ?", email).Take(&admin).Error
	if err != nil {
		fmt.Println("this is the error getting the user: ", err)
		return nil, err
	}
	err = security.VerifyPassword(admin.Secret_password, password)
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		fmt.Println("this is the error hashing the password: ", err)
		return nil, err
	}
	token, err := auth.CreateToken(admin.ID)
	if err != nil {
		fmt.Println("this is the error creating the token: ", err)
		return nil, err
	}
	adminData["token"] = token
	adminData["id"] = admin.ID
	adminData["email"] = admin.Email
	adminData["idcard_image"] = admin.Idcard_image
	adminData["username"] = admin.Username

	return adminData, nil
}

// Update Admin

func (server *Server) UpdateAdmin(c *gin.Context) {

	errList = map[string]string{}

	userID := c.Param("id")
	uid, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		restErr := errors.RestErr{
			Message: "Invalid Json Body",
			Status:  http.StatusBadRequest,
			Error:   "Invalid_request",
		}
		c.JSON(restErr.Status, restErr)
		return
	}
	tokenID, err := auth.ExtractTokenID(c.Request)
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
		c.JSON(http.StatusOK, gin.H{
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
			Status:  http.StatusBadRequest,
			Error:   "Unmarshal_error",
		}
		c.JSON(restErr.Status, restErr)
		return

	}
	formerAdmin := models.Admin{}
	err = server.DB.Debug().Model(models.Admin{}).Where("id = ?", uid).Take(&formerAdmin).Error
	if err != nil {
		errList["User_invalid"] = "The user is does not exist"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}

	newAdmin := models.Admin{}

	if requestBody["current_password"] == "" && requestBody["new_password"] != "" {
		errList["Empty_current"] = "Please Provide current password"
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	if requestBody["current_password"] != "" && requestBody["new_password"] == "" {
		errList["Empty_new"] = "Please Provide new password"
		c.JSON(http.StatusOK, gin.H{
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
		err = security.VerifyPassword(formerAdmin.Secret_password, requestBody["current_password"])
		if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
			errList["Password_mismatch"] = "The password not correct"
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"status": http.StatusOK,
				"error":  errList,
			})
			return
		}
		newAdmin.Username = formerAdmin.Username
		newAdmin.Email = requestBody["email"]
		newAdmin.Secret_password = requestBody["new_password"]
	}

	newAdmin.Username = formerAdmin.Username
	newAdmin.Email = requestBody["email"]

	newAdmin.Prepare()
	errorMessages := newAdmin.Validate("update")
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusInternalServerError,
			"error":  errList,
		})
		return
	}
	updatedAdmin, err := newAdmin.UpdateAdmin(server.DB, uint32(uid))
	if err != nil {
		errList := formaterror.FormatError(err.Error())
		c.JSON(http.StatusOK, gin.H{
			"status": http.StatusOK,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": updatedAdmin,
	})
}
