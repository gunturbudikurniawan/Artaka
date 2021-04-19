package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	ginserver "github.com/go-oauth2/gin-server"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
)

func (s *Server) initialRoutes() {
	manager := manage.NewDefaultManager()

	// token store
	manager.MustTokenStorage(store.NewFileTokenStore("data.db"))

	// client store
	clientStore := store.NewClientStore()
	clientStore.Set("000000", &models.Client{
		ID:     "000000",
		Secret: "999999",
		Domain: "https://monitoring.alih.in",
	})
	manager.MapClientStorage(clientStore)

	// Initialize the oauth2 service
	ginserver.InitServer(manager)
	ginserver.SetAllowGetAccessRequest(true)
	ginserver.SetClientInfoHandler(server.ClientFormHandler)
	auth := s.Router.Group("/oauth2")
	{
		auth.GET("/token", ginserver.HandleTokenRequest)
	}
	api := s.Router.Group("/api")
	{
		api.Use(ginserver.HandleTokenVerify())
		api.GET("/test", func(c *gin.Context) {
			ti, exists := c.Get(ginserver.DefaultConfig.TokenKey)
			if exists {
				c.JSON(http.StatusOK, ti)
				return
			}
			c.String(http.StatusOK, "not found")
		})
	}

	v1 := s.Router.Group("/api/admin")
	{
		v1.GET("/transactionsaved", s.GetLastSaved)
		v1.GET("/transactionOnline", s.GetLastOnline)
		v1.POST("/NotYetContact", s.NotAll)
		v1.POST("/Already", s.Already)
		v1.POST("/ShowSleep", s.Showall)
		v1.POST("/NotRespon", s.LateRespon)
		v1.POST("/ShowReferral", s.ShowAllReferral)
		v1.POST("/ShowOnlineSalesPayment", s.ShowOnlineSalesPayment)
		v1.POST("/GetAllSubcribers", s.GetCertainSubscribers)

		v1.GET("/getall/:id", s.GetMerchant)
		v1.POST("/register", s.CreateAdmin)
		v1.POST("/login", s.LoginAdmin)
		v1.PUT("/update/:id", s.UpdateAdmin)

	}

	v2 := s.Router.Group("/api/merchant")
	{
		v2.POST("/regis", s.CreateUsahaku)
		v2.POST("/update", s.UpdatePassword)
		v2.GET("/:user_id", s.GetMerchant1)

		v2.POST("/register", s.CreateMerchants)
		v2.POST("/login", s.LoginMerchant)
		v2.PUT("/update/:id", s.UpdateMerchant)
	}
	v3 := s.Router.Group("/api/post")
	{
		v3.POST("/create", s.CreatePost)
		v3.PUT("/:id", s.UpdatePost)
		v3.GET("/getpost/:id", s.GetPost)

	}
	v4 := s.Router.Group("/api/transaction")
	{
		v4.POST("/savedorder", s.CreateSavedOrder)
		v4.POST("/onlinesales", s.CreateOnlineSales)
		v4.POST("/sales", s.CreateSales)
	}
}
