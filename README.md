# example-spring-authorization-server
OAuth2 认证授权服务



## 暴露地址


- POST /oauth2/authorize
- POST /oauth2/token
- POST /oauth2/introspect 查看token 的信息
- POST /oauth2/revoke 撤销令牌
- GET /oauth2/jwks 查看JWK信息
- POST /.well-known/oauth-authorization-server

##


- jwt授权服务器

example-spring-security-jwt:example-spring-security-jwt-secret

```shell
curl -i -X POST \
   -H "Authorization:Basic ZXhhbXBsZS1zcHJpbmctc2VjdXJpdHktand0OmV4YW1wbGUtc3ByaW5nLXNlY3VyaXR5LWp3dC1zZWNyZXQ=" \
 'http://localhost:8080/oauth2/token?grant_type=client_credentials'
```


```shell
curl -i -X GET \
   -H "Authorization:Bearer eyJraWQiOiIxMjM0NTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJleGFtcGxlLXNwcmluZy1zZWN1cml0eS1qd3QiLCJhdWQiOiJleGFtcGxlLXNwcmluZy1zZWN1cml0eS1qd3QiLCJuYmYiOjE2NjM2NTYwODMsInNjb3BlIjpbInJlYWQiLCJvcGVuaWQiLCJ3cml0ZSJdLCJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MFwvIiwiZXhwIjoxNjYzNjU5NjgzLCJpYXQiOjE2NjM2NTYwODN9.H1vxnuWx_JYGUwD9MbH5zrhNvReroJCmvzRDfw6HRpqXAfBFhpPitHlnaG07I29eInXkjBDe6s5B6FEi1m2PRTD-UAT5brJy_hqEgyo1unL5HFqhGt0BB7qZtViSY7RIPBtVramETGtAg6ueekwjWoXiLrelTdcFJ7I3codXxi1sjbgGRtqr5LnUcnGtp_lHhOk4n06IvVGoPisWo3H7PtuKU3HGzoJR8RGKSwUmRDmqkF1VRAZder_-ma3p8S_teTaphpYGOpABHSz1Dd2qpCsSS2mPIVUY5VQa-8sOjXHzWROar7iHIvlr84w3YK94XFtWjATGBD13ZNWnDhiomg" \
   'http://localhost:8090'
```

- jwe授权服务器

example-spring-security-jwe:example-spring-security-jwe-secret

```shell
curl -i -X POST \
   -H "Authorization:Basic ZXhhbXBsZS1zcHJpbmctc2VjdXJpdHktandlOmV4YW1wbGUtc3ByaW5nLXNlY3VyaXR5LWp3ZS1zZWNyZXQ=" \
 'http://localhost:8080/oauth2/token?grant_type=client_credentials'
```


```shell
curl -i -X GET \
   -H "Authorization:Bearer qUnScVb5T3sAq6n1qYivYP6HbP64L5KvIqL1UImzatykIGTSoHP_QZLLCIfgsDWi_e8Av3OyId6EiP0hAPsgU1WMRRZksG2caEDCrB79hSOiqbWVEgSy63trdwsFa6ZO" \
   'http://localhost:8090'
```
