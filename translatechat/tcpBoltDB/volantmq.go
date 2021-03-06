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
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VolantMQ/persistence-boltdb"
	"github.com/VolantMQ/volantmq"
	"github.com/VolantMQ/volantmq/auth"
	"github.com/VolantMQ/volantmq/configuration"
	"github.com/VolantMQ/volantmq/transport"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	_ "net/http/pprof"
	_ "runtime/debug"
)

var (
	logger   *zap.Logger
	db       *sql.DB
	expireAt = 24 * 7 //默认token超时时间为10天
)

type RegisterInfo struct {
	PhoneNo      string
	ValidateCode string
	Imei         string
}

type LoginInfo struct {
	PhoneNo      string
	ValidateCode string
	Token        string
	Imei         string
}

type UserInfo struct {
	PhoneNo       string
	NickName      string
	Avatar        string
	Region        string
	Signature     string
	Sex           string
	RegisterTime  string
	LastLoginTime string
	QRCodeUrl     string
	IsFriend      bool
}
type SelfInfo struct {
	PhoneNo       string
	NickName      string
	Avatar        string
	Region        string
	Signature     string
	Sex           string
	RegisterTime  string
	LastLoginTime string
	QRCodeUrl     string
}

type GroupedFriendList struct {
	GroupTitle   string
	GroupFriends []UserInfo
}

type FriendList struct {
	Friends []GroupedFriendList
}
type Response struct {
	Data        interface{}
	Code        int
	Description string
}

type TransMsgJson struct {
	Catalog string
	Time    string

	FromLang string
	ToLang   string

	FromText  string
	FromAudio string // base64编码的amr文件

	ToText     string
	ToAudioUrl string // 目标amr文件下载地址
}

func NewResponse(data interface{}, description string, code int) *Response {
	return &Response{Data: data, Description: description, Code: code}
}

func HandleResponse(w http.ResponseWriter, r *http.Request, resp interface{}, err error) {
	var response *Response
	if err != nil {
		response = NewResponse(nil, err.Error(), -1)
	} else {
		response = NewResponse(resp, "OK", 0)
	}
	var body []byte
	body, err = json.Marshal(response)
	if err != nil {
		logger.Error("encode failed ", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, fmt.Sprintf("encode failed: %s.", err))
	}
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func Transact(db *sql.DB, txFunc func(*sql.Tx) error) (err error) {
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // re-throw panic after Rollback
		} else if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()
	err = txFunc(tx)
	return err
}

func checkValidateCode(code string) bool {
	return code == "1104"
}

// check if @t is expire for now
func isExpired(t string) bool {
	expire, err := time.Parse("2006-01-02 15:04:05", t)
	//if time string format is wrong, time is regarded as expired
	if err != nil {
		return true
	}
	if expire.Before(time.Now()) {
		return true
	}
	return false
}

//生成随机字符串
func getRandomString(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func getToken(phoneNo, imei string) string {
	return getRandomString(15)
}

func getAuthFromReq(r *http.Request) (string, string, string, error) {
	auth := r.Header.Get("Auth")
	str := strings.Split(auth, "_")
	if len(str) != 3 {
		return "", "", "", nil
	}
	return str[0], str[1], str[2], nil
}
func checkAuth(phoneNo, token string) bool {
	var dbToken, expireTime string
	//检查用户是否存在
	err := db.QueryRow("SELECT token, token_expire_time FROM user_auth WHERE phoneno=?", phoneNo).Scan(&dbToken, &expireTime)
	if err != nil {
		logger.Error("User auth failed", zap.String("user", phoneNo), zap.Error(err))
		return false
	}
	//校验Token是否正确
	if isExpired(expireTime) {
		err := fmt.Errorf("Token has been expired")
		logger.Error("User auth failed", zap.String("user", phoneNo), zap.Error(err))
		return false
	}
	err = bcrypt.CompareHashAndPassword([]byte(dbToken), []byte(token))
	if err != nil {
		return false
	}
	return true
}

func Users2FriendList(users []UserInfo) FriendList {
	var gfl = GroupedFriendList{
		GroupTitle:   "#",
		GroupFriends: users,
	}
	var fl FriendList
	fl.Friends = append(fl.Friends, gfl)
	return fl
}

func doUserRegister(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	var ret = struct {
		PhoneNo    string
		ExpireTime string
		Token      string
		QrCodeUrl  string
	}{}
	var qrcodeUrl string
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error("Could't read request body", zap.Error(err))
		return nil, err
	}
	var regInfo RegisterInfo
	err = json.Unmarshal(body, &regInfo)
	if err != nil {
		logger.Error("Could't unmarshal body", zap.Error(err))
		return nil, err
	}
	if !checkValidateCode(regInfo.ValidateCode) {
		err = fmt.Errorf("Validate code is wrong")
		return nil, err
	}

	var dbPhoneNo string
	err = db.QueryRow("SELECT phoneno FROM user_auth WHERE phoneno=?", regInfo.PhoneNo).Scan(&dbPhoneNo)

	switch {
	case err == sql.ErrNoRows:
		//创建新账号
		//生成Password
		token := getToken(regInfo.PhoneNo, regInfo.Imei)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("Server error, unable to create your account", zap.Error(err))
			return nil, err
		}
		//为该账号生成二维码图片并保存
		dir := "./upload/" + regInfo.PhoneNo
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return nil, err
		}
		err = qrcode.WriteFile(regInfo.PhoneNo, qrcode.Medium, 256, dir+"/qrcode.png")
		if err != nil {
			logger.Error("Server error, unable to create qr code", zap.String("user", regInfo.PhoneNo), zap.Error(err))
			return nil, err
		}
		//保存下载路径到数据库
		qrcodeUrl = "download/" + regInfo.PhoneNo + "/qrcode.png"

		t := time.Now().Add(time.Hour * time.Duration(expireAt))
		expireTime := t.Format("2006-01-02 15:04:05")

		err = Transact(db, func(tx *sql.Tx) error {
			if _, err := tx.Exec("INSERT INTO user_auth(phoneno, token, token_expire_time) VALUES(?, ?, ?)", regInfo.PhoneNo, hashedPassword, expireTime); err != nil {
				return err
			}
			now := time.Now().Format("2006-01-02 15:04:05")
			if _, err := tx.Exec("INSERT INTO users(phoneno, nickname, qrcode_url, register_time, last_login_time) VALUES(?, ?, ?, ?, ?)",
				regInfo.PhoneNo, regInfo.PhoneNo, qrcodeUrl, now, now); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			logger.Error("Create account failed", zap.Error(err))
			return nil, err
		}
		ret.PhoneNo = regInfo.PhoneNo
		ret.Token = token
		ret.ExpireTime = expireTime
		ret.QrCodeUrl = qrcodeUrl

		logger.Info("Create account success", zap.String("PhoneNo", regInfo.PhoneNo))
		return ret, nil
	default:
		err = fmt.Errorf("User %s already exists!", regInfo.PhoneNo)
		return nil, err
	}
}

func doGetValidateCode(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	return "beaf", nil
}

func doLogin(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	var ret = struct {
		PhoneNo    string
		Token      string
		ExpireTime string
	}{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error("Could't read request body", zap.Error(err))
		return nil, err
	}
	var login LoginInfo
	err = json.Unmarshal(body, &login)
	if err != nil {
		logger.Error("Could't unmarshal body", zap.Error(err))
		return nil, err
	}

	if login.ValidateCode != "" {
		//校验码登录
		if !checkValidateCode(login.ValidateCode) {
			err = fmt.Errorf("Validate code is wrong")
			return nil, err
		}

		var dbPhoneNo string
		//检查用户是否存在
		err = db.QueryRow("SELECT phoneno FROM user_auth WHERE phoneno=?", login.PhoneNo).Scan(&dbPhoneNo)

		if err != nil {
			logger.Error("User login failed", zap.String("user", login.PhoneNo))
			return nil, err
		}
		//更新生成新的Token并返回
		token := getToken(login.PhoneNo, login.Imei)
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("Server error, can't authorizate your account", zap.Error(err))
			return nil, err
		}
		t := time.Now().Add(time.Hour * time.Duration(expireAt))
		expireTime := t.Format("2006-01-02 15:04:05")
		now := time.Now().Format("2006-01-02 15:04:05")

		err = Transact(db, func(tx *sql.Tx) error {
			if _, err := tx.Exec("UPDATE user_auth set token=?, token_modified_time=?, token_expire_time=? WHERE phoneno=?",
				hashedPassword, now, expireTime, login.PhoneNo); err != nil {
				return err
			}
			if _, err := tx.Exec("UPDATE users set last_login_time=? where phoneno=?", now, login.PhoneNo); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			logger.Error("Update account token failed", zap.String("user", login.PhoneNo), zap.Error(err))
			return nil, err
		}
		ret.PhoneNo = login.PhoneNo
		ret.Token = token
		ret.ExpireTime = expireTime

		logger.Info("Account login success", zap.String("PhoneNo", login.PhoneNo))
		return ret, nil
	} else {
		//Token登录
		var dbToken, expireTime string

		//检查用户是否存在
		err = db.QueryRow("SELECT token, token_expire_time FROM user_auth WHERE phoneno=?", login.PhoneNo).Scan(&dbToken, &expireTime)
		if err != nil {
			logger.Error("User login failed", zap.String("user", login.PhoneNo))
			return nil, err
		}

		//校验Token是否正确
		if isExpired(expireTime) {
			err := fmt.Errorf("Token has been expired")
			return nil, err
		}
		err = bcrypt.CompareHashAndPassword([]byte(dbToken), []byte(login.Token))
		if err != nil {
			return nil, err
		}

		//更新Token过期时间
		t := time.Now().Add(time.Hour * time.Duration(expireAt))
		expireTime = t.Format("2006-01-02 15:04:05")
		now := time.Now().Format("2006-01-02 15:04:05")

		err = Transact(db, func(tx *sql.Tx) error {
			if _, err := tx.Exec("UPDATE user_auth set token_expire_time=? WHERE phoneno=?", expireTime, login.PhoneNo); err != nil {
				return err
			}
			if _, err := tx.Exec("UPDATE users set last_login_time=? where phoneno=?", now, login.PhoneNo); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			logger.Error("Update account token expire time failed", zap.String("user", login.PhoneNo), zap.Error(err))
			return nil, err
		}
		ret.PhoneNo = login.PhoneNo
		ret.Token = login.Token
		ret.ExpireTime = expireTime

		logger.Info("Login account success", zap.String("PhoneNo", login.PhoneNo))
		return ret, nil
	}
}

func doGetUserInfo(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	var user UserInfo
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	queryPhoneNo := r.URL.Query().Get("phoneNo")
	//检查用户是否存在
	err = db.QueryRow("SELECT phoneno, nickname, region, signature, sex, register_time, last_login_time, avatar, qrcode_url FROM users WHERE phoneno=?", queryPhoneNo).Scan(
		&user.PhoneNo, &user.NickName, &user.Region, &user.Signature, &user.Sex, &user.RegisterTime, &user.LastLoginTime, &user.Avatar, &user.QRCodeUrl)
	if err != nil {
		logger.Error("Query user doesn't exists", zap.String("issue_user", phoneNo), zap.String("query_user", queryPhoneNo))
		return nil, err
	}
	//检查朋友关系
	var tmp string
	err = db.QueryRow("SELECT phoneno_a FROM friendship where phoneno_a=? AND phoneno_b=?", phoneNo, queryPhoneNo).Scan(&tmp)
	if err != nil {
		user.IsFriend = false
	} else {
		user.IsFriend = true
	}
	return user, nil
}

func doGetSelfInfo(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	var self SelfInfo
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	//检查用户是否存在
	err = db.QueryRow("SELECT phoneno, nickname, region, signature, sex, register_time, last_login_time, avatar, qrcode_url FROM users WHERE phoneno=?", phoneNo).Scan(
		&self.PhoneNo, &self.NickName, &self.Region, &self.Signature, &self.Sex, &self.RegisterTime, &self.LastLoginTime, &self.Avatar, &self.QRCodeUrl)
	if err != nil {
		logger.Error("Query user doesn't exists", zap.String("issue_user", phoneNo), zap.String("query_user", phoneNo))
		return nil, err
	}
	return self, nil
}

func doChangeUserInfo(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	//检查用户是否存在
	var tmp string
	err = db.QueryRow("SELECT phoneno FROM users WHERE phoneno=?", phoneNo).Scan(&tmp)
	if err != nil {
		logger.Error("User doesn't exists", zap.String("issue_user", phoneNo))
		return nil, err
	}

	changeValue := r.URL.Query().Get("value")
	changeType := r.URL.Query().Get("type")
	if changeType == "nickname" {
		//更新信息
		_, err = db.Exec("UPDATE users SET nickname=? WHERE phoneno=?", changeValue, phoneNo)
		if err != nil {
			logger.Error("Update account info failed", zap.String("user", phoneNo), zap.String("changeType", changeType), zap.String("changeValue", changeValue), zap.Error(err))
			return nil, err
		}
		return nil, nil
	} else if changeType == "region" {
		//更新信息
		_, err = db.Exec("UPDATE users SET region=? WHERE phoneno=?", changeValue, phoneNo)
		if err != nil {
			logger.Error("Update account info failed", zap.String("user", phoneNo), zap.String("changeType", changeType), zap.String("changeValue", changeValue), zap.Error(err))
			return nil, err
		}
		return nil, nil
	} else if changeType == "signature" {
		//更新信息
		_, err = db.Exec("UPDATE users SET signature=? WHERE phoneno=?", changeValue, phoneNo)
		if err != nil {
			logger.Error("Update account info failed", zap.String("user", phoneNo), zap.String("changeType", changeType), zap.String("changeValue", changeValue), zap.Error(err))
			return nil, err
		}
		return nil, nil
	} else if changeType == "sex" {
		//更新信息
		_, err = db.Exec("UPDATE users SET sex=? WHERE phoneno=?", changeValue, phoneNo)
		if err != nil {
			logger.Error("Update account info failed", zap.String("user", phoneNo), zap.String("changeType", changeType), zap.String("changeValue", changeValue), zap.Error(err))
			return nil, err
		}
		return nil, nil
	} else if changeType == "avatar" {
		//更新信息
		_, err = db.Exec("UPDATE users SET avatar=? WHERE phoneno=?", changeValue, phoneNo)
		if err != nil {
			logger.Error("Update account info failed", zap.String("user", phoneNo), zap.String("changeType", changeType), zap.String("changeValue", changeValue), zap.Error(err))
			return nil, err
		}
		return nil, nil
	} else {
		err := fmt.Errorf("Invalid change type!")
		return nil, err

	}
}

func doGetFriendList(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	var rows *sql.Rows
	sqlStr := `SELECT phoneno, nickname, region, signature, sex, register_time, last_login_time, avatar, qrcode_url FROM users WHERE phoneno IN ( SELECT phoneno_b FROM  friendship WHERE phoneno_a=?)`
	rows, err = db.Query(sqlStr, phoneNo)
	if err != nil {
		logger.Error("Query friends failed", zap.String("issue_user", phoneNo), zap.Error(err))
		return nil, err
	}
	defer rows.Close()
	var friends []UserInfo
	for rows.Next() {
		var user UserInfo
		if err := rows.Scan(&user.PhoneNo, &user.NickName, &user.Region, &user.Signature, &user.Sex, &user.RegisterTime, &user.LastLoginTime, &user.Avatar, &user.QRCodeUrl); err != nil {
			logger.Error("Scan friend failed", zap.String("issue_user", phoneNo), zap.Error(err))
		}
		user.IsFriend = true
		friends = append(friends, user)
	}
	if err := rows.Err(); err != nil {
		logger.Error("Scan rows error", zap.String("issue_user", phoneNo), zap.Error(err))
	}
	friendList := Users2FriendList(friends)
	return friendList, nil
}

func doAddFriend(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	queryPhoneNo := r.URL.Query().Get("phoneNo")
	//检查朋友关系
	var tmp string
	err = db.QueryRow("SELECT phoneno_b FROM friendship where phoneno_a=? AND phoneno_b=?", phoneNo, queryPhoneNo).Scan(&tmp)
	if err == sql.ErrNoRows {
		//添加朋友关系
		now := time.Now().Format("2006-01-02 15:04:05")
		err = Transact(db, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO friendship(phoneno_a, phoneno_b, create_time) VALUES(?, ?, ?)`, phoneNo, queryPhoneNo, now); err != nil {
				return err
			}
			if _, err := tx.Exec(`INSERT INTO friendship(phoneno_a, phoneno_b, create_time) VALUES(?, ?, ?)`, queryPhoneNo, phoneNo, now); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			logger.Error("Add friendship failed", zap.String("user1", phoneNo), zap.String("user2", queryPhoneNo), zap.Error(err))
			return nil, err
		}
		return nil, nil
	} else if err != nil {
		logger.Error("Add friend failed", zap.String("issue_user", phoneNo), zap.String("with_user", queryPhoneNo), zap.Error(err))
		return nil, err
	} else {
		err := fmt.Errorf("Already is friend")
		logger.Error("Add friend failed", zap.String("issue_user", phoneNo), zap.String("with_user", queryPhoneNo), zap.Error(err))
		return nil, err
	}
}

func doDelFriend(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	queryPhoneNo := r.URL.Query().Get("phoneNo")
	//检查朋友关系
	var tmp string
	err = db.QueryRow("SELECT phoneno_b FROM friendship where phoneno_a=? AND phoneno_b=?", phoneNo, queryPhoneNo).Scan(&tmp)
	if err == sql.ErrNoRows {
		err := fmt.Errorf("Hasn't been friend")
		logger.Error("Del friend failed", zap.String("issue_user", phoneNo), zap.String("with_user", queryPhoneNo), zap.Error(err))
		return nil, err

	} else if err != nil {
		logger.Error("Del friend failed", zap.String("issue_user", phoneNo), zap.String("with_user", queryPhoneNo), zap.Error(err))
		return nil, err
	} else {
		//删除朋友关系
		err = Transact(db, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`DELETE FROM friendship WHERE phoneno_a=? AND phoneno_b=?`, phoneNo, queryPhoneNo); err != nil {
				return err
			}
			if _, err := tx.Exec(`DELETE FROM friendship WHERE phoneno_a=? AND phoneno_b=?`, queryPhoneNo, phoneNo); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			logger.Error("Del friend failed", zap.String("issue_user", phoneNo), zap.String("with_user", queryPhoneNo), zap.Error(err))
			return nil, err
		}
		return nil, nil
	}
}

func doUploadPhoto(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	var ret = struct {
		AvatarUrl string
	}{}
	phoneNo, token, _, err := getAuthFromReq(r)
	if !checkAuth(phoneNo, token) {
		err := fmt.Errorf("Invalid authorization information!")
		return nil, err
	}
	r.ParseMultipartForm(32 << 20)

	var file multipart.File
	var handler *multipart.FileHeader
	file, handler, err = r.FormFile("uploadfile")
	if err != nil {
		logger.Error("get form file failed", zap.Error(err))
		return nil, err
	}
	defer file.Close()

	//获取文件后缀
	s := strings.Split(handler.Filename, ".")
	if len(s) < 2 {
		err = fmt.Errorf("Invalid form filename %s", handler.Filename)
		return nil, err
	}
	suffix := s[len(s)-1]
	logger.Info("get form file", zap.String("filename", handler.Filename), zap.String("suffix", suffix))

	//构造目录
	dir := "./upload/" + phoneNo
	err = os.MkdirAll(dir, os.ModePerm)
	f, err := os.OpenFile(dir+"/avatar."+suffix, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		logger.Error("Create photo file failed", zap.Error(err))
		return nil, err
	}
	defer f.Close()
	io.Copy(f, file)

	//保存下载路径到数据库
	newFileName := "download/" + phoneNo + "/avatar." + suffix
	_, err = db.Exec("UPDATE users SET avatar=? WHERE phoneno=?", newFileName, phoneNo)
	if err != nil {
		logger.Error("Update account avatar failed", zap.String("user", phoneNo), zap.String("avatr_url", newFileName), zap.Error(err))
		return nil, err
	}
	ret.AvatarUrl = newFileName
	return ret, nil
}

//{"from":"zh","to":"en","trans_result":[{"src":"\u767e\u5ea6 \u4f60\u597d","dst":"Hello, Baidu"}]}
type TransResp struct {
	From        string `json:"from"`
	To          string `json:"to"`
	TransResult []struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	} `json:"trans_result"`
}

func translateText(FromLang, ToLang, FromText string) (string, error) {
	//文本翻译,翻译源为FromText
	appId := "20170714000064493"
	SecretKey := "1F0H8Oh1YZX2U9pqdIMP"

	queryText := FromText
	queryTextEncoded := url.QueryEscape(queryText)
	srcLang := FromLang
	dstLang := ToLang
	salt := strconv.FormatInt(time.Now().Unix(), 10)
	signStr := appId + queryText + salt + SecretKey
	sign := fmt.Sprintf("%x", md5.Sum([]byte(signStr)))
	translateUrl := "http://api.fanyi.baidu.com/api/trans/vip/translate?q=" + queryTextEncoded + "&from=" + srcLang + "&to=" + dstLang + "&appid=" + appId + "&salt=" + salt + "&sign=" + sign

	fmt.Printf("signStr=[%s], translateUrl=[%s]\n", signStr, translateUrl)
	res, err := http.Get(translateUrl)
	if err != nil {
		log.Fatal(err)
		return "", nil
	}

	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		log.Fatal(err)
		return "", nil
	}
	var transResp TransResp
	err = json.Unmarshal(body, &transResp)
	if err != nil {
		log.Fatal(err)
		return "", nil
	}
	fmt.Printf("translate result: %s, text result: %s\n", string(body), transResp.TransResult[0].Dst)
	return transResp.TransResult[0].Dst, nil
}

func getBaiduToken() string {
	buff, err := ioutil.ReadFile("/tmp/translatechat/token")
	if err != nil {
		log.Fatal(err)
		return ""
	}
	return string(buff)
}
func translate(msg *TransMsgJson) error {
	if msg.Catalog == "text" {
		to, err := translateText(msg.FromLang, msg.ToLang, msg.FromText)
		if err != nil {
			log.Fatal(err)
			return err
		}
		msg.ToText = to
	} else {
		//语音翻译, Catalog == "audio"
		//构造会话目录
		dir := "upload/translate/"
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			log.Fatal(err)
			return err
		}
		//语音生成amr文件到翻译目录
		decoded, err := base64.StdEncoding.DecodeString(msg.FromAudio)
		if err != nil {
			log.Fatal("decode error:", err)
			return err
		}
		nowStr := strconv.FormatInt(time.Now().Unix(), 10)
		audioAmrFile := dir + nowStr + ".amr"

		err = ioutil.WriteFile(audioAmrFile, decoded, 0644)
		if err != nil {
			log.Fatal(err)
			return err
		}
		//语音转文字
		var text string
		text, err = audio2text(audioAmrFile)
		if err != nil {
			log.Fatal(err)
			return err
		}
		msg.FromText = text
		//文字翻译
		to, err := translateText(msg.FromLang, msg.ToLang, msg.FromText)
		if err != nil {
			log.Fatal(err)
			return err
		}
		msg.ToText = to
		//文字转语音
		audioResultMp3File := dir + nowStr + "_result.mp3"
		audioResultAmrFile := dir + nowStr + "_result.amr"
		audioDownloadAmrFile := "download/translate/" + nowStr + "_result.amr"
		err = text2audio(msg.ToText, audioResultMp3File, audioResultAmrFile)
		if err != nil {
			log.Fatal(err)
			return err
		}
		msg.ToAudioUrl = audioDownloadAmrFile
	}
	return nil
}

type Audio2TextResult struct {
	ErrNo  int      `json:"err_no"`
	ErrMsg string   `json:"err_msg"`
	Result []string `json:"result"`
}

func audio2text(audioAmrFile string) (string, error) {
	cuid := "TranslateChat"
	token := getBaiduToken()
	log.Printf("Start audio2text for file %s\n", audioAmrFile)
	//语音到文本
	var file *os.File
	var err error
	file, err = os.Open(audioAmrFile)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	urlAudio2Text := "http://vop.baidu.com/server_api?lan=zh&cuid=" + cuid + "&token=" + token
	var resp *http.Response
	resp, err = http.Post(urlAudio2Text, "audio/amr;rate=16000", file)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	var a2tRet Audio2TextResult
	err = json.Unmarshal(body, &a2tRet)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	if a2tRet.ErrNo != 0 {
		err = fmt.Errorf("Audio2Text failed, %s", a2tRet.ErrMsg)
		fmt.Printf("Audio2Text failed, url: %s, result from server %s, %#v\n", urlAudio2Text, string(body), a2tRet)
		return "", err
	}

	fmt.Printf("Audio2Text result: %s\n", a2tRet.Result[0])
	return a2tRet.Result[0], nil
}

func text2audio(text, mp3File, saveAudioFile string) error {
	cuid := "TranslateChat"
	token := getBaiduToken()
	var err error
	//文本到语音
	message := text
	urlMsg := url.QueryEscape(message)
	urlText2Audio := "http://tsn.baidu.com/text2audio?tex=" + urlMsg + "&lan=zh&cuid=" + cuid + "&ctp=1&tok=" + token
	var res *http.Response
	res, err = http.Get(urlText2Audio)
	if err != nil {
		log.Fatal(err)
		return err
	}

	var body []byte
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer res.Body.Close()

	if res.Header.Get("Content-type") != "audio/mp3" {
		fmt.Printf("text2audio failed: %s\n", string(body))
		return err
	}

	err = ioutil.WriteFile(mp3File, body, 0644)
	if err != nil {
		log.Fatal(err)
		return err
	}

	cmdStr := "lame " + mp3File + " " + saveAudioFile
	_, err = exec.Command("bash", "-c", cmdStr).Output()
	if err != nil {
		log.Fatal(err)
		return err
	}
	if err = os.Remove(mp3File); err != nil {
		log.Fatal(err)
	}
	return nil
}

func doTranslate(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Error("Could't read request body", zap.Error(err))
		return nil, err
	}
	var msg TransMsgJson
	err = json.Unmarshal(body, &msg)
	if err != nil {
		logger.Error("Could't unmarshal body", zap.Error(err))
		return nil, err
	}
	if err = translate(&msg); err != nil {
		log.Fatal(err)
		return nil, err
	}
	return msg, nil
}
func handleUserRegister(w http.ResponseWriter, r *http.Request) {
	resp, err := doUserRegister(w, r)
	HandleResponse(w, r, resp, err)
}
func handleGetValidateCode(w http.ResponseWriter, r *http.Request) {
	resp, err := doGetValidateCode(w, r)
	HandleResponse(w, r, resp, err)
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	resp, err := doLogin(w, r)
	HandleResponse(w, r, resp, err)
}
func handleGetUserInfo(w http.ResponseWriter, r *http.Request) {
	resp, err := doGetUserInfo(w, r)
	HandleResponse(w, r, resp, err)
}

func handleGetSelfInfo(w http.ResponseWriter, r *http.Request) {
	resp, err := doGetSelfInfo(w, r)
	HandleResponse(w, r, resp, err)
}

func handleChangeUserInfo(w http.ResponseWriter, r *http.Request) {
	resp, err := doChangeUserInfo(w, r)
	HandleResponse(w, r, resp, err)
}

func handleGetFriendList(w http.ResponseWriter, r *http.Request) {
	resp, err := doGetFriendList(w, r)
	HandleResponse(w, r, resp, err)
}

func handleAddFriend(w http.ResponseWriter, r *http.Request) {
	resp, err := doAddFriend(w, r)
	HandleResponse(w, r, resp, err)
}
func handleDelFriend(w http.ResponseWriter, r *http.Request) {
	resp, err := doDelFriend(w, r)
	HandleResponse(w, r, resp, err)
}

func handleUploadPhoto(w http.ResponseWriter, r *http.Request) {
	resp, err := doUploadPhoto(w, r)
	HandleResponse(w, r, resp, err)
}

func handleTranslate(w http.ResponseWriter, r *http.Request) {
	resp, err := doTranslate(w, r)
	HandleResponse(w, r, resp, err)
}

func handleTest(w http.ResponseWriter, r *http.Request) {
	HandleResponse(w, r, nil, nil)
}

func startApiListener() {
	//路由配置
	http.HandleFunc("/users/register", handleUserRegister)
	http.HandleFunc("/users/register/get_validate_code", handleGetValidateCode)
	http.HandleFunc("/users/login", handleLogin)
	http.HandleFunc("/users/get_user_info", handleGetUserInfo)
	http.HandleFunc("/users/get_self_info", handleGetSelfInfo)
	http.HandleFunc("/users/change_user_info", handleChangeUserInfo)
	http.HandleFunc("/friends/get_list", handleGetFriendList)
	http.HandleFunc("/friends/add_friend", handleAddFriend)
	http.HandleFunc("/friends/del_friend", handleDelFriend)
	http.HandleFunc("/upload/photo", handleUploadPhoto) //头像上传接口
	http.HandleFunc("/translate", handleTranslate)
	//下载目录
	fsh := http.FileServer(http.Dir("./upload"))
	http.Handle("/download/", http.StripPrefix("/download/", fsh))
	http.HandleFunc("/test", handleTest)
	go func() {
		//err := http.ListenAndServeTLS(":8080", "cert.pem", "key.pem", nil)
		err := http.ListenAndServe(":3389", nil)
		if err != nil {
			logger.Error("Couldn't start Api listener", zap.Error(err))
		}
		logger.Info("Start Api listener on :3389")
	}()
}

func main() {
	ops := configuration.Options{
		LogWithTs: true,
	}

	configuration.Init(ops)

	logger = configuration.GetLogger().Named("volantmq")

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
	//Init Db connection
	db, err = sql.Open("mysql", "root:qmzpwnxo@tcp/TranslateChat")
	if err != nil {
		logger.Error("Could't connect to database TranslateChat!")
		return
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		logger.Error("Could't connect to database TranslateChat!", zap.Error(err))
		return
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
