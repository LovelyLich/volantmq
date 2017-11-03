package main

import (
	"database/sql"
	"github.com/VolantMQ/volantmq/auth"
	"github.com/VolantMQ/volantmq/configuration"

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

	var passwd string
	err = db.QueryRow("SELECT passwd FROM user_auth WHERE phoneno = ?", user).Scan(&passwd)
	logger.Info("Query database result:",
		zap.String("database_user", user),
		zap.String("database_password", passwd),
	)
	if err != nil {
		logger.Error("Couldn't query table user_auth", zap.Error(err))
		return auth.StatusDeny
	}

	if password == passwd {
		logger.Info("authorization success", zap.String("user", user))
		return auth.StatusAllow
	}
	return auth.StatusDeny
}

// nolint: golint
func (a DbAuth) ACL(clientID, user, topic string, access auth.AccessType) auth.Status {
	return auth.StatusAllow
}
