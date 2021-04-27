# Artaka-Show-Sleep-Merchants

## Register Admin

curl -i -X POST -H "Content-Type: application/json" -d '{
"username":"Guntur",
"email":"gunturkurniawan@gmail.com",
"secret_password":"admin12",
"phone":"081290858463"
}' https://artaka.herokuapp.com/api/admin/register

## Sigin admin with email & Password

curl -i -X POST -H "Content-Type: application/json" -d '{
"email":"gunturkurniawan@gmail.com",
"secret_password":"admin12"
}' https://artaka.herokuapp.com/api/admin/register

## Sigin admin with phone & Password

curl -i -X POST -H "Content-Type: application/json" -d '{
"phone":"081290858463",
"secret_password":"admin12"
}' https://artaka.herokuapp.com/api/admin/register

## Show Sleep Merchants

curl -i -X GET -H "Content-Type: application/json"  
https://artaka.herokuapp.com/api/admin/ShowSleep

## Get Post by id

curl -i -X GET -H "Content-Type: application/json"  
https://artaka.herokuapp.com/api/post/getpost/1

## Update Post by id

curl -i -X PUT -H "Content-Type: application/json" -d '{
"phone":"+6282264291947","contacted": "0","content":"Sudah diangkaat"

}' https://artaka.herokuapp.com/api/post/1

## Show Sleep Already

curl -i -X GET -H "Content-Type: application/json"  
https://artaka.herokuapp.com/api/admin/Already

## Show Sleep Not Respon

curl -i -X GET -H "Content-Type: application/json"  
https://artaka.herokuapp.com/api/admin/NotRespon

## Show Sleep Not Contacted

curl -i -X GET -H "Content-Type: application/json" https://artaka.herokuapp.com/api/admin/NotYetContact

# Postgres Live

API_SECRET=secret
DB_HOST=mpos.cvhuy9njnz7l.ap-southeast-1.rds.amazonaws.com
DB_DRIVER=postgres
DB_USER=bambang_susilo
DB_PASSWORD=Artaka16!
DB_NAME=mpos1
DB_PORT=5432
PORT1=5000

REDIS_DSN=redis:6379

ACCESS_SECRET=artakasecret
REFRESH_SECRET=refreshsecret

curl -i -X POST -H "Content-Type: application/json" https://monitoring.alih.in/api/merchant/regis?token=7a69ff49-26b0-4395-b62e-f46ef4ef7ef6

curl --location --request POST 'https://monitoring.alih.in/api/merchant/update' \
--header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJleHAiOjE2MTkyNTI3MTUsImlkIjoxNTA5fQ.vsJeUJVO7gscyFX4GI0hJMzI4xpZIdzkobbyXzSTVAg' \
--header 'Content-Type: application/json' \
--data-raw '{
"secret_password":"passssaaaaaaaaaaaaaa"
}'

curl --location --request POST 'https://monitoring.alih.in/api/merchant/regis' \
--header 'Authorization: Bearer 7a69ff49-26b0-4395-b62e-f46ef4ef7ef6'

curl --location --request POST 'https://monitoring.alih.in/api/merchant/regiss?eventUrl=https://api.digitalcore.telkomsel.com/preprod-web/isv_fulfilment/events/7a69ff49-26b0-4395-b62e-f46ef4ef7ef6' --header 'Authorization: Bearer 7a69ff49-26b0-4395-b62e-f46ef4ef7ef6' --noproxy "\*" -k

// func (server *Server) CreateUsahaku(c *gin.Context) {
// tokenString := c.Request.Header.Get("Authorization")
// claims, ok := extractClaims(tokenString, "JWT Secret")
// if !ok {
// c.JSON(http.StatusUnprocessableEntity, gin.H{
// "success": "false",
// "errorCode": "INVALID_RESPONSE",
// "message": "invalid token.",
// })
// return
// }

// id := claims["id"].(string)
// fmt.Println("id from token : ", id)

// val := client.Get(id)
// if val == nil {
// c.JSON(http.StatusUnprocessableEntity, gin.H{
// "success": "false",
// "errorCode": "INVALID_RESPONSE",
// "message": "The account could not be found.",
// })
// return
// }
// db := server.DB
// eventURL := c.Query("eventURL")
// resp, err := http.Get(eventURL)
// if resp.StatusCode != 200 {
// c.Status(http.StatusUnauthorized)
// return
// }

// event := models.Event{}
// data, _ := ioutil.ReadAll(resp.Body)
// _ = json.Unmarshal(data, &event)

// if event.Creator.Address.Phone == "" && event.Creator.Email == "" && event.Creator.Address.FullName == "" {
// c.JSON(http.StatusUnprocessableEntity, gin.H{
// "success": "false",
// "errorCode": "INVALID_RESPONSE",
// "message": "The account " + event.Payload.Company.Name + " could not be found.",
// })
// return
// }
// x := event.Creator.Address.Phone
// i := strings.Index(x, "+")
// var phone string
// if i > -1 {
// phone = event.Creator.Address.Phone
// } else {
// phone = "+" + event.Creator.Address.Phone
// }

// hasil := db.Create(&models.Subscribers{Create_dtm: time.Now(),
// User_id: phone,
// Email: event.Creator.Email,
// Owner_name: event.Creator.Address.FullName,
// Secret_password: "",
// Fcm_token: "",
// Idcard_name: "",
// Idcard_number: "",
// Bank_holder_name: "",
// Bank_name: "",
// Bank_account: "",
// Idcard_image: json.RawMessage(`["https://www.generationsforpeace.org/wp-content/uploads/2018/07/empty.jpg"]`),
// Referral_code: ""})

// tokenInfo, err := CreateToken(hasil.Value.(*models.Subscribers).ID)
// if err != nil {
// c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// return
// }
// err = CreateAuth(hasil.Value.(*models.Subscribers).Owner_name, tokenInfo)
// if err != nil {
// c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// return
// }

// result := map[string]string{
// "Success": "true",
// "accountIdentifier": phone,
// }
// c.JSON(http.StatusOK, result)
// if tokenInfo.AccessToken != "" {
// from := "artakajurnal@gmail.com"
// password := "Amazon123@"
// to := []string{
// event.Creator.Email,
// "gunturkurniawan238@gmail.com",
// }
// smtpServer := smtpServer{host: "smtp.gmail.com", port: "587"}
// message := []byte("To: Merchant Artaka \r\n" +
// "Subject: Hallo Artaka!\r\n" +
// "\r\n" +
// "This is for update password.\r\n" + "https://master.d3mr68pgup3qa4.amplifyapp.com/reset/" + tokenInfo.AccessToken)
// auth := smtp.PlainAuth("", from, password, smtpServer.host)
// err := smtp.SendMail(smtpServer.Address(), auth, from, to, message)
// if err != nil {
// return
// }
// fmt.Println("Email Sent!")
// }
// }

// type smtpServer struct {
// host string
// port string
// }

// func (s \*smtpServer) Address() string {
// return s.host + ":" + s.port
// }
