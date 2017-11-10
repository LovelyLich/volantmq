package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

type ChatMsgJson struct {
	Catalog  string
	Time     string
	FromUser string
	ToUser   string

	FromLang string
	ToLang   string

	FromText  string
	FromAudio string // base64编码的amr文件

	ToText     string
	ToAudioUrl string // 目标amr文件下载地址
}

func getChatMsg() (*ChatMsgJson, error) {
	amrFile := "../tcpBoltDB/test.amr"
	content, err := ioutil.ReadFile(amrFile)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	str := base64.StdEncoding.EncodeToString(content)
	var msg = &ChatMsgJson{
		Catalog:    "audio",
		Time:       strconv.FormatInt(time.Now().Unix(), 10),
		FromLang:   "zh",
		ToLang:     "en",
		FromText:   "",
		FromAudio:  str,
		ToText:     "",
		ToAudioUrl: "",
	}
	return msg, nil
}

func main() {
	//构造Message, 并Post
	url := "http://127.0.0.1:3389/translate"
	msg, err := getChatMsg()
	if err != nil {
		fmt.Println(err)
		return
	}

	var buff []byte
	buff, err = json.Marshal(*msg)
	if err != nil {
		fmt.Println(err)
		return
	}
	var resp *http.Response
	resp, err = http.Post(url, "application/json", bytes.NewReader(buff))
	if err != nil {
		fmt.Println(err)
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("response: %#v\n", string(body))
}
