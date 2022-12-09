package middleware

import (
	"go-app/app/code"
	"go-app/config"
	"go-app/lib/jwt"
	"go-app/lib/response"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// JWTAuth 中间件，检查token
func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get(config.JWT.HeaderField)
		if token == "" {
			if config.APP.Mode == config.MODE_API {
				c.JSON(http.StatusUnauthorized, response.NewJson().Error(code.ErrEmptyToken))
			} else if config.APP.Mode == config.MODE_WEB {
				c.Redirect(http.StatusTemporaryRedirect, config.JWT.RedirectUrl)
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			c.Abort()
			return
		}

		token = strings.ReplaceAll(token, "Bearer ", "")

		// parseToken 解析token包含的信息
		claims, err := jwt.ParseToken(token)
		if err != nil {
			if config.APP.Mode == config.MODE_API {
				if err == jwt.ErrTokenExpired {
					c.JSON(http.StatusUnauthorized, response.NewJson().Error(code.ErrToken))
				} else {
					c.JSON(http.StatusUnauthorized, response.NewJson().Error(code.ErrToken))
				}
			} else if config.APP.Mode == config.MODE_WEB {
				c.Redirect(http.StatusTemporaryRedirect, config.JWT.RedirectUrl)
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			c.Abort()
			return
		}
		// 继续交由下一个路由处理,并将解析出的信息传递下去
		c.Set("JwtAuth", claims)

		c.Next()
	}
}
