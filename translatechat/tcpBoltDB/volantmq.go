// Copyright (c) 2017 The VolantMQ Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/VolantMQ/persistence-boltdb"
	"github.com/VolantMQ/volantmq"
	"github.com/VolantMQ/volantmq/auth"
	"github.com/VolantMQ/volantmq/configuration"
	"github.com/VolantMQ/volantmq/transport"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	_ "net/http/pprof"
	_ "runtime/debug"
)

type RegisterInfo struct {
	PhoneNo      string
	NickName     string
	ValidateCode string
	Imei         string
}

func handleUserRegister(w http.ResponseWriter, r *http.Request) (int, string) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return 400, "Invalid Parameters"
	}
	var regInfo RegisterInfo
	err = json.Unmarshal(body, &regInfo)
	if err != nil {
		return 400, "Invalid Parameters"
	}

	db, err := sql.Open("mysql", "root:qmzpwnxo@tcp/TranslateChat")
	if err != nil {
		logger.Error("Could't connect to database TranslateChat!")
	}
	defer db.Close()

	var userName string

	err := db.QueryRow("SELECT phoneno FROM users WHERE phoneno=?", regInfo.PhoneNo).Scan(&user)

	switch {
	case err == sql.ErrNoRows:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		_, err = db.Exec("INSERT INTO users(username, password) VALUES(?, ?)", username, hashedPassword)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}

		res.Write([]byte("User created!"))
		return
	}
}
func handleGetValidateCode(w http.ResponseWriter, r *http.Request) {}
func handleLogin(w http.ResponseWriter, r *http.Request)           {}
func handleGetUserInfo(w http.ResponseWriter, r *http.Request)     {}
func handleGetFriendList(w http.ResponseWriter, r *http.Request)   {}
func handleAddFriend(w http.ResponseWriter, r *http.Request)       {}
func handleDelFriend(w http.ResponseWriter, r *http.Request)       {}

func startApiListener() {
	//路由配置
	http.HandleFunc("/users/register", handleUserRegister)
	http.HandleFunc("/users/register/get_validate_code", handleGetValidateCode)
	http.HandleFunc("/users/login", handleLogin)
	http.HandleFunc("/users/get_user_info", handleGetUserInfo)
	http.HandleFunc("/friends/get_list", handleGetFriendList)
	http.HandleFunc("/friends/add_friend", handleAddFriend)
	http.HandleFunc("/friends/del_friend", handleDelFriend)
	go func() {
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			logger.Error("Couldn't start Api listener", zap.Error(err))
		}
	}()
}

func main() {
	ops := configuration.Options{
		LogWithTs: true,
	}

	configuration.Init(ops)

	logger := configuration.GetLogger().Named("volantmq")

	var err error

	logger.Info("Starting application")
	logger.Info("Allocated cores", zap.Int("GOMAXPROCS", runtime.GOMAXPROCS(0)))
	viper.SetConfigName("config")
	viper.AddConfigPath("conf")
	viper.SetConfigType("json")

	//go func() {
	//	http.ListenAndServe("localhost:6061", nil) // nolint: errcheck
	//}()

	logger.Info("Initializing configs")
	if err = viper.ReadInConfig(); err != nil {
		logger.Error("Couldn't read config file", zap.Error(err))
		os.Exit(1)
	}
	// initialize auth database
	var db struct {
		DataSourceName string `json:"DSN"`
	}
	if err = viper.UnmarshalKey("mqtt.auth.dbAuth", &db); err != nil {
		logger.Error("Couldn't unmarshal config", zap.Error(err))
		os.Exit(1)
	}

	dbAuth := DbAuth{
		dataSourceName: db.DataSourceName,
	}
	if err = auth.Register("dbAuth", dbAuth); err != nil {
		logger.Error("Couldn't register *internal* auth provider", zap.Error(err))
		os.Exit(1)
	}

	var srv volantmq.Server

	listenerStatus := func(id string, status string) {
		logger.Info("Listener status", zap.String("id", id), zap.String("status", status))
	}

	serverConfig := volantmq.NewServerConfig()
	serverConfig.OfflineQoS0 = true
	serverConfig.TransportStatus = listenerStatus
	serverConfig.AllowDuplicates = true
	serverConfig.Authenticators = "dbAuth"

	serverConfig.Persistence, err = boltdb.New(&boltdb.Config{
		File: "./persist.db",
	})

	if err != nil {
		logger.Error("Couldn't init BoltDB persistence", zap.Error(err))
		os.Exit(1)
	}

	srv, err = volantmq.NewServer(serverConfig)

	if err != nil {
		logger.Error("Couldn't create server", zap.Error(err))
		os.Exit(1)
	}

	var authMng *auth.Manager

	if authMng, err = auth.NewManager("dbAuth"); err != nil {
		logger.Error("Couldn't register *amqp* auth provider", zap.Error(err))
		return
	}

	config := transport.NewConfigTCP(
		&transport.Config{
			Port:        "1883",
			AuthManager: authMng,
		})

	if err = srv.ListenAndServe(config); err != nil {
		logger.Error("Couldn't start MQTT listener", zap.Error(err))
	}

	//启动Api接口服务
	startApiListener()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	sig := <-ch
	logger.Info("Received signal", zap.String("signal", sig.String()))

	if err = srv.Close(); err != nil {
		logger.Error("Couldn't shutdown server", zap.Error(err))
	}

	os.Remove("./persist.db") // nolint: errcheck
}
