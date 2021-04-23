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
