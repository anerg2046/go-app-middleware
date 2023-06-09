package middleware

import (
	"go-app/app/code"
	"go-app/config"
	"go-app/lib/logger"
	"go-app/lib/rbac"
	"go-app/lib/response"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func CasbinCheck(pathPrefix string) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.MustGet("JwtAuth").(*config.JwtClaims)
		sub := auth.Username
		obj := c.Request.URL.Path
		if pathPrefix != "" {
			obj = strings.Replace(obj, pathPrefix, "", 1)
		}
		act := "request"

		logger.Debug("[Casbin]", zap.Any("sub", sub))
		logger.Debug("[Casbin]", zap.Any("obj", obj))

		if ok, _ := rbac.New().Enforce(sub, obj, act); !ok {
			if config.APP.Mode == config.MODE_API {
				c.JSON(http.StatusUnauthorized, response.NewJson().Error(code.NewError(401, "无访问权限")))
			} else if config.APP.Mode == config.MODE_WEB {
				c.Redirect(http.StatusTemporaryRedirect, config.JWT.RedirectUrl)
			} else {
				c.AbortWithStatus(http.StatusUnauthorized)
			}
			c.Abort()
			return
		}

		c.Next()
	}
}
