# example-spring-authorization-server
OAuth2 认证授权服务



## 暴露地址


- POST /oauth2/authorize
- POST /oauth2/token
- POST /oauth2/introspect 查看token 的信息
- POST /oauth2/revoke 撤销令牌
- GET /oauth2/jwks 查看JWK信息
- GET /.well-known/oauth-authorization-server
- GET /.well-known/openid-configuration
- GET 

## 登录认证流程


### client_credentials 方式认证

- jwt方式

```shell
curl -s -X POST \
 'http://localhost:9000/oauth2/token' \
  -u 'example:example-secret' \
  -d 'grant_type=client_credentials' \
  -d 'scope=write' | jq -r .access_token
```


```shell
curl -i -X GET \
   -H "Authorization:Bearer eyJraWQiOiIxMjM0NTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIiwiYXVkIjoiZXhhbXBsZSIsIm5iZiI6MTY3MTI5MTc5NSwic2NvcGUiOlsid3JpdGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjcxMzEzMzk1LCJpYXQiOjE2NzEyOTE3OTV9.O0UaUdxjwUaMS_okeXM-Sj8jXaYPBouPnp0N5IpBrKUjTHeLc2j1U1vWZxK-x4Ste1cXBTTxHbhHU0px7fbb77x-8LIQZzutvPDmPi_7UFy1IvTqO3YoZUZpiq4Rai8T1j9OS1frJxA5w8a4DQcccKytk5FrQe8BaH2QkEDV3pJfTpBbmtJIsO9Jd0o0_BzwORHsglXWKsrebAH5I9TJRYBj2Zmaj3zNkmLSJhnVcr2Q9iBCtN3rjfz34xUrNfl2jScRFVUNBk1taA4ugtFBhSoPWEYHkZI6PZBifSfgAM-qGl_40FyjweaKYUcTGd1XcKE2uiMxG8DrIoVsyro7EQ" \
   'http://localhost:8070'
```

- opaque方式

example-spring-security-opaque:example-spring-security-opaque-secret

```shell
curl -i -X POST \
   -H "Authorization:Basic ZXhhbXBsZS1zcHJpbmctc2VjdXJpdHktb3BhcXVlOmV4YW1wbGUtc3ByaW5nLXNlY3VyaXR5LW9wYXF1ZS1zZWNyZXQ=" \
 'http://localhost:8080/oauth2/token?grant_type=client_credentials'
```

```shell
curl -i -X GET \
   -H "Authorization:Bearer qUnScVb5T3sAq6n1qYivYP6HbP64L5KvIqL1UImzatykIGTSoHP_QZLLCIfgsDWi_e8Av3OyId6EiP0hAPsgU1WMRRZksG2caEDCrB79hSOiqbWVEgSy63trdwsFa6ZO" \
   'http://localhost:8090'
```


### PASSWORD 方式认证

```shell
curl -i -X POST \
  -u 'example:example-secret' \
  'http://localhost:9000/oauth2/token' \
  -d 'grant_type=password' \
  -d 'username=admin' \
  -d 'password=123456' \
  -d 'client_id=example' \
  -d 'client_secret=example-secret'

```

### AUTHORIZATION_CODE 方式认证


- jwt方式

example-spring-security-jwt:example-spring-security-jwt-secret

1. 浏览器访问获取code

http://localhost:8080/oauth2/authorize?response_type=code&scope=read%20write&client_id=example-spring-security-oauth2-sso-jwt&redirect_uri=http://127.0.0.1:8080/authorized

```shell
curl -i -X POST \
   -H "Authorization:Basic ZXhhbXBsZS1zcHJpbmctc2VjdXJpdHktand0OmV4YW1wbGUtc3ByaW5nLXNlY3VyaXR5LWp3dC1zZWNyZXQ=" \
 'http://localhost:8080/oauth2/token?grant_type=authorization_code&code=2cJEsyFuhTP-KtLBt8DDk-7khG4ayXV8JaGVmKBkiFpF-pMMgxC4mvCS6EIupcwVZcxREizYS-LmEVw6vfyv01Up_t93rflWLeCJ6iNNNy09oWCh1NhY_zCVhUD7cFp-&redirect_uri=http://127.0.0.1:8080/authorized'

```

得道响应信息：

```json
{
  "access_token":"eyJraWQiOiIxMjM0NTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6ImV4YW1wbGUtc3ByaW5nLXNlY3VyaXR5LWp3dCIsIm5iZiI6MTY2MzY2MjEwMiwic2NvcGUiOlsicmVhZCIsIndyaXRlIl0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwXC8iLCJleHAiOjE2NjM2NjU3MDIsImlhdCI6MTY2MzY2MjEwMn0.VSX1_QgEgNvJC2pcoyNandIe6avgdflwpo8UF6QEEFiztoInxFDXTCAhBij7xux-o4f7RmiDdZ9MyL0uIQ2XNEf2DrIo8GGsCHGr19FiFs1jv8uiURXVlDm4_RMCohwqSM_r5dfRSyQZRW3875KzZdkSUydCwr-GuZZKybK-hCqM_XUNoNdu3SSN-1G5ExgsssIhFhDgHhZlNwnNQS06D6Y_N8UjAWVj-u-gIteKx1BgCGJLMzP5KPuot1AN2FhLytCGBRAKaTNvxcDqg_iDgf-iRiUAyDdWCMQeZxtHthFCph5gvDPABDmkNT-yYPlE5qTtPKCd6R0Jl_nRPKpgVw",
  "refresh_token":"zDknLO0p1tt0fWs20DrW2lhP2HRU__QXfsGwzRr2S9mIWatMmjLbeFLq_0H5k5jsyU-la8a-MY_idTBIbQ9VxIprKWHBwkAb4IHHVCNzipol3WCw8DrfU_ulpaiwlbPM",
  "scope":"read write",
  "token_type":"Bearer",
  "expires_in":3599
}
```

```shell
curl -i -X GET \
   -H "Authorization:Bearer eyJraWQiOiIxMjM0NTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJleGFtcGxlLXNwcmluZy1zZWN1cml0eS1qd3QiLCJhdWQiOiJleGFtcGxlLXNwcmluZy1zZWN1cml0eS1qd3QiLCJuYmYiOjE2NjM2NTYwODMsInNjb3BlIjpbInJlYWQiLCJvcGVuaWQiLCJ3cml0ZSJdLCJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MFwvIiwiZXhwIjoxNjYzNjU5NjgzLCJpYXQiOjE2NjM2NTYwODN9.H1vxnuWx_JYGUwD9MbH5zrhNvReroJCmvzRDfw6HRpqXAfBFhpPitHlnaG07I29eInXkjBDe6s5B6FEi1m2PRTD-UAT5brJy_hqEgyo1unL5HFqhGt0BB7qZtViSY7RIPBtVramETGtAg6ueekwjWoXiLrelTdcFJ7I3codXxi1sjbgGRtqr5LnUcnGtp_lHhOk4n06IvVGoPisWo3H7PtuKU3HGzoJR8RGKSwUmRDmqkF1VRAZder_-ma3p8S_teTaphpYGOpABHSz1Dd2qpCsSS2mPIVUY5VQa-8sOjXHzWROar7iHIvlr84w3YK94XFtWjATGBD13ZNWnDhiomg" \
   'http://localhost:8090'
```

## 问题

- https://stackoverflow.com/questions/39756748/spring-oauth-authorization-server-requires-scope
