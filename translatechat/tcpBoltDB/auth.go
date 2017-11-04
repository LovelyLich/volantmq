package main

import (
	"database/sql"
	"github.com/VolantMQ/volantmq/auth"
	"github.com/VolantMQ/volantmq/configuration"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

type DbAuth struct {
	dataSourceName string
}

func (a DbAuth) Password(user, password string) auth.Status {
	ops := configuration.Options{
		LogWithTs: true,
	}
	configuration.Init(ops)
	logger := configuration.GetLogger().Named("volantmq.auth")
	logger.Info("Starting authorization for",
		zap.String("user", user),
		zap.String("password", password),
	)

	db, err := sql.Open("mysql", "root:qmzpwnxo@tcp/TranslateChat")
	if err != nil {
		logger.Error("Could't connect to database TranslateChat!")
	}
	defer db.Close()

	var dbToken, expireTime string
	err = db.QueryRow("SELECT token, token_expire_time FROM user_auth WHERE phoneno = ?", user).Scan(&dbToken, &expireTime)
	if err != nil {
		logger.Error("Couldn't query table user_auth", zap.Error(err))
		return auth.StatusDeny
	}
	//校验Token是否正确
	if isExpired(expireTime) {
		logger.Error("Token has been expired", zap.String("user", user))
		return auth.StatusDeny
	}
	err = bcrypt.CompareHashAndPassword([]byte(dbToken), []byte(password))
	if err != nil {
		return auth.StatusDeny
	}

	return auth.StatusAllow
}

// nolint: golint
func (a DbAuth) ACL(clientID, user, topic string, access auth.AccessType) auth.Status {
	return auth.StatusAllow
}
