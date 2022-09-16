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


- 授权服务器

example-client-1:example-client-secret-1

```shell
curl -i -X POST \
   -H "Authorization:Basic ZXhhbXBsZS1jbGllbnQtMTpleGFtcGxlLWNsaWVudC1zZWNyZXQtMQ==" \
 'http://localhost:9080/oauth2/token?grant_type=client_credentials'
```

example-client-1:example-client-secret-1

```shell
curl -i -X POST \
   -H "Authorization:Basic ZXhhbXBsZS1jbGllbnQtMTpleGFtcGxlLWNsaWVudC1zZWNyZXQtMQ==" \
 'http://localhost:9080/oauth2/token?grant_type=client_credentials'
```



```shell
curl -i -X GET \
   -H "Authorization:Bearer xxxx.xxxx.xxxx" \
   'http://localhost:8090/messages'
```

```shell
curl -i -X GET \
   -H "Authorization:Bearer xxxx.xxxx.xxxx" \
   'http://localhost:8090/messages'
```
