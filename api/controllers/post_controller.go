package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/gunturbudikurniawan/Artaka/api/models"

	"github.com/gin-gonic/gin"
	"github.com/gunturbudikurniawan/Artaka/api/auth"
	"github.com/gunturbudikurniawan/Artaka/api/utils/errors"
)

func (server *Server) CreatePost(c *gin.Context) {

	//clear previous error if any
	errList = map[string]string{}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":   "Failed",
			"error":    "Failed",
			"Response": "Null",
		})
		return
	}
	post := new(models.Post)

	err = json.Unmarshal(body, &post)
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
		c.JSON(http.StatusUnauthorized, gin.H{
			"status":   "Failed",
			"error":    "Failed",
			"Response": "Null",
		})
		return
	}

	user := models.Admin{}
	err = server.DB.Debug().Model(models.Admin{}).Where("id = ?", uid).Take(&user).Error
	if err != nil {
		log.Println(err)
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status":   "Failed",
			"error":    "Invalid Credentials",
			"Response": "Null",
		})
		return
	}

	post.AuthorID = uid //the authenticated user is the one creating the post

	post.Prepare()
	errorMessages := post.Validate()
	if len(errorMessages) > 0 {
		// errList = errorMessages
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":   "Failed",
			"error":    "Failed",
			"Response": "Null",
		})
		return
	}

	postCreated, err := post.SavePost(server.DB)
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":   "Failed",
			"error":    "Invalid Credentials",
			"Response": "Null",
		})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"status":   "Success",
		"response": postCreated,
	})
}

func (server *Server) GetPost(c *gin.Context) {

	postID := c.Param("id")
	pid, err := strconv.ParseUint(postID, 10, 64)
	if err != nil {
		errList["Invalid_request"] = "Invalid Request"
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  errList,
		})
		return
	}
	post := new(models.Post)

	postReceived, err := post.FindPostByID(server.DB, pid)
	if err != nil {
		errList["No_post"] = "No Post Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": postReceived,
	})
}

func (server *Server) UpdatePost(c *gin.Context) {

	//clear previous error if any
	errList = map[string]string{}

	postID := c.Param("id")
	// Check if the post id is valid
	pid, err := strconv.ParseUint(postID, 10, 64)
	if err != nil {
		errList["Invalid_request"] = "Invalid Request"
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  errList,
		})
		return
	}

	origPost := models.Post{}
	err = server.DB.Debug().Model(models.Post{}).Where("id = ?", pid).Take(&origPost).Error
	if err != nil {
		errList["No_post"] = "No Post Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status":   http.StatusNotFound,
			"error":    "No Post Found",
			"response": "null",
		})
		return
	}

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":   http.StatusUnprocessableEntity,
			"error":    "Unable to get request",
			"Response": "Null",
		})
		return
	}
	post := new(models.Post)
	err = json.Unmarshal(body, &post)
	if err != nil {
		errList["Unmarshal_error"] = "Cannot unmarshal body"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":   http.StatusUnprocessableEntity,
			"error":    "Cannot unmarshal body",
			"Response": "Null",
		})
		return
	}
	post.ID = origPost.ID
	post.AuthorID = origPost.AuthorID

	post.Prepare()
	errorMessages := post.Validate()
	if len(errorMessages) > 0 {
		errList = errorMessages
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status":   http.StatusUnprocessableEntity,
			"error":    "Unauthorized",
			"Response": "Null",
		})
		return
	}
	postUpdated, err := post.UpdateAPost(server.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":   http.StatusInternalServerError,
			"error":    "Unauthorized",
			"response": "Null",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": postUpdated,
		"error":    "Null",
	})
}
func (server *Server) DeletePost(c *gin.Context) {

	postID := c.Param("id")
	pid, err := strconv.ParseUint(postID, 10, 64)
	if err != nil {
		errList["Invalid_request"] = "Invalid Request"
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  errList,
		})
		return
	}

	fmt.Println("this is delete post sir")

	uid, _, _, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	post := new(models.Post)
	err = server.DB.Debug().Model(models.Post{}).Where("id = ?", pid).Take(&post).Error
	if err != nil {
		errList["No_post"] = "No Post Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}
	if uid != post.AuthorID {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}
	_, err = post.DeleteAPost(server.DB)
	if err != nil {
		errList["Other_error"] = "Please try again later"
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": http.StatusInternalServerError,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": "Post deleted",
	})
}

func (server *Server) GetUserPosts(c *gin.Context) {

	userID := c.Param("id")
	uid, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		errList["Invalid_request"] = "Invalid Request"
		c.JSON(http.StatusBadRequest, gin.H{
			"status": http.StatusBadRequest,
			"error":  errList,
		})
		return
	}
	post := new(models.Post)
	posts, err := post.FindUserPosts(server.DB, uint32(uid))
	if err != nil {
		errList["No_post"] = "No Post Found"
		c.JSON(http.StatusNotFound, gin.H{
			"status": http.StatusNotFound,
			"error":  errList,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": posts,
	})
}
func (server *Server) Showall(c *gin.Context) {

	_, referral_code, role, err := auth.ExtractTokenID(c.Request)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}

	err, datas := models.Allshow(server.DB, referral_code, role)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Merchant Aktif Semua",
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

func (server *Server) LateRespon(c *gin.Context) {
	uid, referral_code, role, err := auth.ExtractTokenID(c.Request)
	fmt.Println(uid)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}

	err, datas := models.NotRespon(server.DB, referral_code, role)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Tidak Ada Merchant Yang tidak respon",
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

func (server *Server) NotAll(c *gin.Context) {
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

	err, datas := models.Show(server.DB, referral_code, role)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Merchant Aktif Semua",
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

func (server *Server) Already(c *gin.Context) {
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

	err, datas := models.Show1(server.DB, referral_code, role)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Not ALready contacted with admin",
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

func (server *Server) ShowAllReferral(c *gin.Context) {

	err, datas := models.ShowReferralCode(server.DB)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Tidak ada Payment Method Serupa",
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

func (server *Server) ShowOnlineSalesPayment(c *gin.Context) {
	uid, referral_code, role, err := auth.ExtractTokenID(c.Request)
	fmt.Println(referral_code)
	fmt.Println(role)
	fmt.Println(uid)
	if err != nil {
		errList["Unauthorized"] = "Unauthorized"
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": http.StatusUnauthorized,
			"error":  errList,
		})
		return
	}

	err, datas := models.ShowPaymentMethodVAOnlineSales(server.DB, referral_code, role)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"status":   "Failed",
			"error":    "Tidak ada Payment Method Serupa",
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
