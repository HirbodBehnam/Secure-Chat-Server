package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/websocket"
	"github.com/miguelsandro/curve25519-go/axlsign"
	"github.com/orcaman/concurrent-map"
	"github.com/rocketlaunchr/dbq"
	sql "github.com/rocketlaunchr/mysql-go"
	"github.com/segmentio/ksuid"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"syscall"
	"time"
)

type UsersDBRow struct {
	Name      string
	Username  string
	Password  string
	PublicKey string `dbq:"public_key"`
	LoggedIn  bool   `dbq:"logged_in"`
}

// Message type:
// 0 -> Simple text message
// 1 -> File message
// 2 -> ...
type UserChatDBRow struct {
	From    string    `dbq:"from_username"`
	Type    byte      `dbq:"message_type"`
	Date    time.Time `dbq:"message_date"`
	Payload string    `dbq:"payload"`
}

var Config struct {
	ServerPort       string `json:"port"`
	FileLocation     string `json:"files"`
	FileSaveDuration int    `json:"file_save_duration"`
	Database         struct {
		Location string `json:"location"`
		Username string `json:"username"`
		Password string `json:"password"`
		DBName   string `json:"db_name"`
	} `json:"database"`
	WSConnection struct {
		Key  string `json:"key"`
		Cert string `json:"certificate"`
	} `json:"ws_connection"`
	RSAKeys struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	} `json:"rsa_keys"`
}
var db *sql.DB
var upgrader = websocket.Upgrader{} // use default options
var clients cmap.ConcurrentMap      // All of the active clients; The key value is the username
var uploadTokens map[string]byte    // These are some IDs for uploading files; Client should send the one for him in order to upload a file; byte value is unused
var RSAKeys struct {
	PublicKey  []byte
	PrivateKey *rsa.PrivateKey
}

func registerClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	// Get the username password and public key
	err := r.ParseForm()
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	key := r.Form.Get("key")
	// check the username and password with database
	ctx := context.Background()
	result, err := dbq.Q(ctx, db, "SELECT * FROM `users` WHERE `username`=? LIMIT 1", dbq.SingleResult, username)
	if err != nil {
		log.Error("cannot access database when a client tried to register:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot connect to database"))
		return
	}
	if result == nil { // This means that username does not exists
		_, _ = w.Write(GenerateStatus(false, "username does not exists"))
		return
	}
	// check if the user was logged in
	if result.(map[string]interface{})["logged_in"].(int8) == 1 {
		_, _ = w.Write(GenerateStatus(false, "already logged in"))
		return
	}
	// check the password
	{ // password is encrypted with RSA key; decrypt it first
		newP, err := base64.StdEncoding.DecodeString(password)
		if err != nil {
			_, _ = w.Write(GenerateStatus(false, "password must be in base64"))
			return
		}
		newP, err = DecryptWithPrivateKey(newP, RSAKeys.PrivateKey)
		if err != nil {
			_, _ = w.Write(GenerateStatus(false, "cannot decrypt the message"))
			return
		}
		password = string(newP)
	}
	err = bcrypt.CompareHashAndPassword([]byte(result.(map[string]interface{})["password"].(string)), []byte(password))
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "incorrect password"))
		return
	}
	// login the user
	_, err = dbq.E(ctx, db, "UPDATE `users` SET `logged_in` = '1' , `public_key` = ? WHERE `username` = ?", nil, key, username)
	if err != nil {
		log.Error("cannot update database when a client tried to register:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot update the database"))
		return
	}
	_, _ = w.Write(GenerateStatus(true, result.(map[string]interface{})["name"].(string)))
}
func logoutClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}
	// Get the username password and signature
	err := r.ParseForm()
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	signature := r.Form.Get("signature")
	// check the username and password with database
	ctx := context.Background()
	result, err := dbq.Q(ctx, db, "SELECT password FROM `users` WHERE `username`=? LIMIT 1", dbq.SingleResult, username)
	if err != nil {
		log.Error("cannot access database when a client tried to logout:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot connect to database"))
		return
	}
	if result == nil { // This means that username does not exists
		_, _ = w.Write(GenerateStatus(false, "username does not exists"))
		return
	}
	// check if the user was logged in
	if result.(map[string]interface{})["logged_in"].(int) == 0 {
		_, _ = w.Write(GenerateStatus(false, "not logged in"))
		return
	}
	// decrypt the password
	{
		newP, err := DecryptWithPrivateKey([]byte(password), RSAKeys.PrivateKey)
		if err != nil {
			_, _ = w.Write(GenerateStatus(false, "cannot decrypt the message"))
			return
		}
		password = string(newP)
	}
	// Verify the signature
	pubKey, err := base64.StdEncoding.DecodeString(result.(map[string]interface{})["public_key"].(string))
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "cannot get public key from database"))
		return
	}
	if len(pubKey) != 32 {
		_, _ = w.Write(GenerateStatus(false, "short public key"))
		return
	}
	signedMessage, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "invalid signed message format"))
		return
	}
	if len(signedMessage) != 64 {
		_, _ = w.Write(GenerateStatus(false, "short signature"))
		return
	}
	if axlsign.Verify(pubKey, []byte(password), signedMessage) == 0 {
		_, _ = w.Write(GenerateStatus(false, "invalid signature"))
		return
	}
	// check the password
	err = bcrypt.CompareHashAndPassword([]byte(result.(map[string]interface{})["password"].(string)), []byte(password))
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "incorrect password"))
		return
	}
	// logout the user
	_, err = dbq.E(ctx, db, "UPDATE `users` SET `logged_in` = '0' , `public_key` = '0' WHERE `username` = ?", nil, username)
	if err != nil {
		log.Error("cannot update database when a client tried to logout:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot update the database"))
		return
	}
	_, _ = w.Write(GenerateStatus(true, ""))
}
func registerUpdater(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	var username string
	{ // Check the username and password
		var helloMessage HelloStruct
		err = c.ReadJSON(&helloMessage) // At really first the client should send the server it's username and password
		if err != nil {                 // Invalid json file
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "invalid hello message"})
			return
		}
		// Now check the username and password
		ctx := context.Background()
		result, err := dbq.Q(ctx, db, "SELECT * FROM `users` WHERE `username`=? LIMIT 1", dbq.SingleResult, helloMessage.Username)
		if err != nil { // Invalid json file
			log.Error("cannot access database when a client tried to register updater:", err.Error())
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "cannot fetch data from database: " + err.Error()})
			return
		}
		if result == nil {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "invalid username or password"})
			return
		}
		// Verify the signature
		pubKey, err := base64.StdEncoding.DecodeString(result.(map[string]interface{})["public_key"].(string))
		if err != nil {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "cannot get public key from database"})
			return
		}
		if len(pubKey) != 32 {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "short public key"})
			return
		}
		signedMessage, err := base64.StdEncoding.DecodeString(helloMessage.Verify)
		if err != nil {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "invalid signed message format"})
			return
		}
		if len(signedMessage) != 64 {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "short signature"})
			return
		}
		if axlsign.Verify(pubKey, []byte(helloMessage.Password), signedMessage) == 0 {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "invalid signature"})
			return
		}
		// verify password
		result = result.(map[string]interface{})["password"]
		err = bcrypt.CompareHashAndPassword([]byte(result.(string)), []byte(helloMessage.Password))
		if err != nil {
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "invalid password"})
			return
		}
		// Update the connection list
		if wsClient, exists := clients.Get(helloMessage.Username); exists {
			_ = wsClient.(*websocket.Conn).Close() // Close older connections; This must not happen
		}

		username = helloMessage.Username
		_ = c.WriteJSON(StatusStruct{OK: true, Message: ""})
	}

	for { // fetch all of the old entries from database
		// TODO: can we use an json array to send a lot of data at once?
		ctx := context.Background()
		result, err := dbq.Q(ctx, db, "SELECT * FROM "+username+" ORDER BY id LIMIT 1", dbq.SingleResult)
		if err != nil {
			log.Error("cannot access database when a server tried to fetch updates of a user:", err.Error())
			_ = c.WriteJSON(StatusStruct{OK: false, Message: "server cannot access database"})
			return
		}
		if result == nil { // All rows are sent to user
			break
		} else {
			update := result.(map[string]interface{})
			var toSend = ClientUpdateTypeStruct{Type: byte(update["message_type"].(int8))}
			toSend.Payload.Message = update["payload"].(string)
			toSend.Payload.Date = *update["message_date"].(*time.Time)
			toSend.Payload.From = update["from_username"].(string)
			err = c.WriteJSON(toSend)
			if err != nil {
				return
			}
			// remove the entry from database
			_, err = dbq.E(ctx, db, "DELETE FROM `"+username+"` WHERE `id` = "+strconv.FormatInt(int64(update["id"].(int32)), 10), nil)
			if err != nil {
				log.Error("cannot delete entry from database:", err)
			}
		}
	}

	clients.Set(username, c) // set the websocket

	for {
		_, message, err := c.ReadMessage() // Get the message
		if err != nil {
			log.Debug("cannot read websocket:", err)
			break
		}
		// Parse the message
		var data ReceiveMessageStruct
		var date = time.Now()
		err = json.Unmarshal(message, &data)
		if err != nil {
			_ = c.WriteJSON(MessageStatusStruct{OK: false, ID: "", Message: "invalid message struct"})
			continue
		}

		// check file upload request
		if data.Type == 2 {
			id := ksuid.New()
			_ = c.WriteJSON(MessageStatusStruct{OK: true, ID: data.ID, Message: id.String()})
			uploadTokens[id.String()] = 0
			os.Mkdir("files/"+id.String(), 0666)
			continue
		}

		// deliver the message on another thread
		go func(msg ReceiveMessageStruct, sentDate time.Time) {
			var err error
			var toSend = ClientUpdateTypeStruct{Type: msg.Type}
			toSend.Payload.From = username
			toSend.Payload.Date = sentDate
			toSend.Payload.Message = msg.Payload.Message

			// Check if the user is currently online
			// if it's online, directly send it via ws
			ws, online := clients.Get(msg.Payload.To)
			if online { //Directly send the message to them
				err = ws.(*websocket.Conn).WriteJSON(toSend)
				if err == nil { // if message delivering via websocket fails, store it in database
					_ = c.WriteJSON(MessageStatusStruct{OK: true, ID: data.ID, Message: "sent"})
					return // Message successfully delivered
				}
			}

			// if the user is not online, store the message in database
			user := []interface{}{
				dbq.Struct(UserChatDBRow{toSend.Payload.From, toSend.Type, toSend.Payload.Date, toSend.Payload.Message}),
			}
			stmt := dbq.INSERT(msg.Payload.To, []string{"from_username", "message_type", "message_date", "payload"}, len(user))
			ctx := context.Background()
			_, err = dbq.E(ctx, db, stmt, nil, user)
			if err != nil {
				log.Error("cannot deliver message to user:", err, "msg:", toSend)
				_ = c.WriteJSON(MessageStatusStruct{OK: false, ID: data.ID, Message: "database error"})
				return
			}
			_ = c.WriteJSON(MessageStatusStruct{OK: true, ID: data.ID, Message: "sent"})
		}(data, date)
	}
}
func changePassword(w http.ResponseWriter, r *http.Request) {
	// The url must be like https://localhost/users/changePassword?username=user&old=abcd&new=abcd
	// Both of the passwords must be RSA encrypted
	var username, oldPassword, newPassword string
	// get parameters
	username, err := GetParameter(r, "username")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	oldPassword, err = GetParameter(r, "old")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	newPassword, err = GetParameter(r, "new")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	// get old password
	ctx := context.Background()
	result, err := dbq.Q(ctx, db, "SELECT password FROM `users` WHERE `username`=? LIMIT 1", dbq.SingleResult, username)
	if err != nil {
		log.Error("cannot access database when a client tried to change it's password:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot connect to database"))
		return
	}
	if result == nil { // This means that username does not exists
		_, _ = w.Write(GenerateStatus(false, "username does not exists"))
		return
	}
	// decrypt passwords
	oldP, err := DecryptWithPrivateKey([]byte(oldPassword), RSAKeys.PrivateKey)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "cannot decrypt the message"))
		return
	}
	newP, err := DecryptWithPrivateKey([]byte(newPassword), RSAKeys.PrivateKey)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "cannot decrypt the message"))
		return
	}
	// compare the passwords
	err = bcrypt.CompareHashAndPassword([]byte(result.(map[string]interface{})["password"].(string)), oldP)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "incorrect password"))
		return
	}
	// set the new password
	newP, _ = bcrypt.GenerateFromPassword(newP, 10)
	_, err = dbq.E(ctx, db, "UPDATE `users` SET `password` = '"+string(newP)+"' WHERE `username` = '"+username+"'", nil)
	if err != nil {
		log.Error("cannot update database when a client tried to change it's password:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot update the password"))
		return
	}
	_, _ = w.Write(GenerateStatus(true, ""))
}
func changeName(w http.ResponseWriter, r *http.Request) {
	// The url must be like https://localhost/users/changePassword?username=user&password=abcd&name=hirbod
	// Both passwords must be RSA encrypted
	var username, name, password string
	// get parameters
	username, err := GetParameter(r, "username")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	password, err = GetParameter(r, "password")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	name, err = GetParameter(r, "name")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	// get password
	ctx := context.Background()
	result, err := dbq.Q(ctx, db, "SELECT password FROM `users` WHERE `username`=? LIMIT 1", dbq.SingleResult, username)
	if err != nil {
		log.Error("cannot access database when a client tried to change it's password:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot connect to database"))
		return
	}
	if result == nil { // This means that username does not exists
		_, _ = w.Write(GenerateStatus(false, "username does not exists"))
		return
	}
	// decrypt the password
	decryptedPassword, err := DecryptWithPrivateKey([]byte(password), RSAKeys.PrivateKey)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "cannot decrypt the message"))
		return
	}
	// check the password
	err = bcrypt.CompareHashAndPassword([]byte(result.(map[string]interface{})["password"].(string)), decryptedPassword)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "incorrect password"))
		return
	}
	// set the name
	_, err = dbq.E(ctx, db, "UPDATE `users` SET `name` = '"+name+"' WHERE `username` = '"+username+"'", nil)
	if err != nil {
		log.Error("cannot access database when a client tried to change it's password:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot update the password"))
		return
	}
	_, _ = w.Write(GenerateStatus(true, ""))
}
func getUserData(w http.ResponseWriter, r *http.Request) {
	// The url must be like https://localhost/users/getData?username=user
	username, err := GetParameter(r, "username")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
	}
	// get data from sql
	ctx := context.Background()
	result, err := dbq.Q(ctx, db, "SELECT * FROM `users` WHERE `username`=? LIMIT 1", dbq.SingleResult, username)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "cannot connect to database"))
		return
	}
	if result == nil { // This means that username does not exists
		_, _ = w.Write(GenerateStatus(false, "username does not exists"))
		return
	}

	res := result.(map[string]interface{})
	var toSend UserDataStruct
	toSend.Username = username
	toSend.PublicKey = res["public_key"].(string)
	toSend.Name = res["name"].(string)

	jString, _ := json.Marshal(toSend)
	_, _ = w.Write(jString)
}
func getPublicKey(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write(RSAKeys.PublicKey) // Just give the public key to user
}
func upload(w http.ResponseWriter, r *http.Request) {
	// upload is multipart form
	if r.Method != "POST" {
		return
	}
	// all files has a token; These are temporary values to prevent flooding
	token := r.Header.Get("token")
	if _, exists := uploadTokens[token]; !exists {
		_, _ = w.Write(GenerateStatus(false, "invalid token"))
		return
	}
	delete(uploadTokens, token) // do not allow other uploads with this token :D (strict policy huh?)
	// if the token is ok, get the file
	err := r.ParseMultipartForm(32 << 12)
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, "multipart parse error: "+err.Error()))
		log.Error("Cannot parse the multipart form of a user when he was uploading:", err.Error())
		return
	}
	file, handler, err := r.FormFile("document")
	if err != nil {
		_, _ = w.Write(GenerateStatus(false, err.Error()))
		return
	}
	defer file.Close()
	f, err := os.OpenFile(path.Join(Config.FileLocation, token, handler.Filename), os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Error("cannot create a file when a user tried to upload it's file:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot create file"))
		return
	}
	defer f.Close()
	_, err = io.Copy(f, file)
	if err != nil {
		log.Error("cannot copy the file when a user tried to upload it's file:", err.Error())
		_, _ = w.Write(GenerateStatus(false, "cannot create file"))
		return
	}
	_, _ = w.Write(GenerateStatus(true, token))
}
func downloadFile(w http.ResponseWriter, r *http.Request) {
	// get token
	token, err := GetParameter(r, "token")
	if token == "" || err != nil {
		http.Error(w, string(GenerateStatus(false, "missing token")), 403)
		return
	}
	// search the files
	if _, err := os.Stat(path.Join(Config.FileLocation, token) + "/"); os.IsNotExist(err) {
		http.Error(w, string(GenerateStatus(false, "invalid token")), 404)
		return
	}
	info, err := ioutil.ReadDir(path.Join(Config.FileLocation, token) + "/")
	if err != nil {
		log.Error("cannot access files when a user tried to download a file:", err.Error())
		http.Error(w, string(GenerateStatus(false, "cannot access files")), 500)
		return
	}
	// read the file https://mrwaggel.be/post/golang-transmit-files-over-a-nethttp-server-to-clients/
	file, err := os.Open(info[0].Name())
	if err != nil {
		log.Error("cannot access the file when a user tried to download it's file:", err.Error())
		http.Error(w, string(GenerateStatus(false, err.Error())), 500)
		return
	}
	defer file.Close()
	// get some info about the file
	FileHeader := make([]byte, 512)
	_, _ = file.Read(FileHeader)
	FileContentType := http.DetectContentType(FileHeader)
	// set the headers
	w.Header().Set("Content-Disposition", "attachment; filename="+info[0].Name())
	w.Header().Set("Content-Type", FileContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(info[0].Size(), 10))
	// send the file
	// we read 512 bytes from the file already, so we reset the offset back to 0
	file.Seek(0, 0)
	_, _ = io.Copy(w, file) //'Copy' the file to the client
}

func main() {
	log.SetLevel(log.TraceLevel) // TODO: add log level
	var configName = "config.json"
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config, c",
				Usage:       "Load configuration from `FILE`",
				DefaultText: "config.json",
				Value:       "config.json",
				Destination: &configName,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "run",
				Usage: "Runs the server",
				Action: func(c *cli.Context) error {
					// Parse the json config file
					err := ParseConfig(configName)
					if err != nil {
						return err
					}
					// Try to open database
					db, err = sql.Open("mysql", Config.Database.Username+":"+Config.Database.Password+"@tcp("+Config.Database.Location+")/"+Config.Database.DBName)
					if err != nil {
						return errors.New("Cannot read private key: " + err.Error())
					}
					// Read the public and private key
					RSAKeys.PublicKey, err = ioutil.ReadFile(Config.RSAKeys.PrivateKey) // Store it at public key, parse it, then overwrite it
					if err != nil {
						return errors.New("Cannot parse public key: " + err.Error())
					}
					RSAKeys.PrivateKey, err = BytesToPrivateKey(RSAKeys.PublicKey) // This is ok. For now the private key is in public key!
					if err != nil {
						return errors.New("Cannot read public key: " + err.Error())
					}
					RSAKeys.PublicKey, err = ioutil.ReadFile(Config.RSAKeys.PublicKey) //Now read the public key
					// Setup clients
					clients = cmap.New()
					// Setup file stuff
					uploadTokens = make(map[string]byte)
					if _, err := os.Stat(Config.FileLocation); os.IsNotExist(err) {
						err = os.Mkdir(Config.FileLocation, os.ModePerm)
						if err != nil {
							return err
						}
					}
					go func() {
						maxDiff := time.Minute * time.Duration(Config.FileSaveDuration)
						for {
							time.Sleep(time.Minute)
							log.Trace("removing unused tokens")
							for k := range uploadTokens { // remove unused tokens
								id, _ := ksuid.Parse(k)
								if time.Now().Add(time.Minute * 10).Before(id.Time()) {
									delete(uploadTokens, k)
									log.Debug("Deleted unused token", k)
								}
							}
							// remove files
							files, err := ioutil.ReadDir(Config.FileLocation)
							if err != nil {
								log.Error("Cannot get directories for file cleanup")
								continue
							}
							for _, f := range files {
								if f.IsDir() {
									if f.ModTime().Add(maxDiff).After(time.Now()) {
										log.Debug("Removing old file", f.Name())
										err = os.RemoveAll(f.Name())
										if err != nil {
											log.Error("Cannot get directories for file cleanup")
										}
									}
								}
							}
						}
					}()
					// Start the web server
					http.HandleFunc("/chat/registerUpdater", registerUpdater)
					http.HandleFunc("/users/changePassword", changePassword)
					http.HandleFunc("/users/changeName", changeName)
					http.HandleFunc("/users/getData", getUserData)
					http.HandleFunc("/users/registerClient", registerClient)
					http.HandleFunc("/users/logout", logoutClient)
					http.HandleFunc("/publicKey", getPublicKey)
					http.HandleFunc("/upload", upload)
					http.HandleFunc("/download", downloadFile)
					return http.ListenAndServeTLS(Config.ServerPort, Config.WSConnection.Cert, Config.WSConnection.Key, nil)
				},
			},
			{
				Name:    "add",
				Aliases: []string{"a"},
				Usage:   "Add a new user to server",
				Action: func(c *cli.Context) error {
					//Parse the json config file
					err := ParseConfig(configName)
					if err != nil {
						return err
					}
					//Try to open database
					log.Info("Connecting to database...")
					db, err = sql.Open("mysql", Config.Database.Username+":"+Config.Database.Password+"@tcp("+Config.Database.Location+")/"+Config.Database.DBName)
					if err != nil {
						return err
					}
					defer db.Close()
					log.Info("Connected to database!")
					//Get the username and password
					var name, username, password string
					scanner := bufio.NewScanner(os.Stdin)
					fmt.Print("Enter the name of this user: ")
					scanner.Scan()
					name = scanner.Text()
					fmt.Print("Enter a username for this user (must be unique): ")
					scanner.Scan()
					username = scanner.Text()
					{ // Get the passwords and verify them
						fmt.Print("Enter a password: ")
						bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
						if err != nil {
							return err
						}
						password = string(bytePassword)
						fmt.Println()
						fmt.Print("Retype the password: ")
						bytePassword, err = terminal.ReadPassword(int(syscall.Stdin))
						if err != nil {
							return err
						}
						if password != string(bytePassword) {
							return errors.New("the passwords does not match")
						}
						bytePassword, err = bcrypt.GenerateFromPassword([]byte(password), 10)
						if err != nil {
							return err
						}
						password = string(bytePassword)
					}
					fmt.Println()
					log.Info("Executing sql query")
					ctx := context.Background()
					// Check if the user exists
					result := dbq.MustQ(ctx, db, "SELECT * FROM `users` WHERE `username`=\""+username+"\"", dbq.SingleResult)
					if result != nil {
						return errors.New("this username is taken")
					}
					// Try to inset the user into database (add it to users table)
					user := []interface{}{
						dbq.Struct(UsersDBRow{name, username, password, "", false}),
					}
					stmt := dbq.INSERT("users", []string{"name", "username", "password", "public_key", "logged_in"}, len(user))
					dbq.MustE(ctx, db, stmt, nil, user)
					// Create a new table for user
					_, err = db.Exec("CREATE TABLE `chat`.`" + username + "` ( `id` INT NOT NULL AUTO_INCREMENT , `from_username` TINYTEXT NOT NULL , `message_type` TINYINT NOT NULL , `message_date` DATETIME NOT NULL , `payload` TEXT NOT NULL , PRIMARY KEY (`id`)) ENGINE = InnoDB;")
					log.Info("User successfully added to database!")
					return err
				},
			},
			{
				Name:  "generate",
				Usage: "Generates RSA keys",
				Action: func(c *cli.Context) error {
					// Parse key length
					bits := 4096 //default
					var err error
					if c.NArg() > 0 {
						bits, err = strconv.Atoi(c.Args().First())
						if err != nil {
							return errors.New("invalid key length")
						}
					}
					// Check if keys already exist
					if _, err := os.Stat("public.pem"); !os.IsNotExist(err) {
						res := askForConfirmation("\"public.pem\" file already exists. Overwrite it?")
						if !res {
							return errors.New("canceled")
						}
					} else if _, err := os.Stat("private.pem"); !os.IsNotExist(err) {
						res := askForConfirmation("\"private.pem\" file already exists. Overwrite it?")
						if !res {
							return errors.New("canceled")
						}
					}
					// Generate keys and save it
					log.Info("Starting to generate keys...")
					private, public := GenerateKeyPair(bits)
					err = ioutil.WriteFile("public.pem", PublicKeyToBytes(public), 0644)
					if err != nil {
						return err
					}
					err = ioutil.WriteFile("private.pem", PrivateKeyToBytes(private), 0644)
					if err != nil {
						return err
					}
					log.Info("Keys saved to public.pem and private.pem")
					return nil
				},
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println()
		log.Fatal(err)
	}

}

func ParseConfig(name string) error {
	confF, err := ioutil.ReadFile(name)
	if err != nil {
		return errors.New("Cannot read the config file. (io Error) " + err.Error())
	}
	err = json.Unmarshal(confF, &Config)
	if err != nil {
		return errors.New("Cannot read the config file. (Parse Error) " + err.Error())
	}
	return nil
}
func GetParameter(r *http.Request, parameterName string) (string, error) {
	keys, ok := r.URL.Query()[parameterName]
	if !ok || len(keys[0]) < 1 {
		return "", errors.New(parameterName + " does not exists")
	}
	return keys[0], nil
}
