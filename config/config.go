/*
 * Copyright @ 2020 - present Blackvisor Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"bufio"
	"flag"
	"log"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/netclave/identity-provider/identity"

	"github.com/netclave/common/storage"
)

var DataStorageCredentials map[string]string
var StorageType string

var IdentityStorageCredentials map[string]string
var IdentityStorageType string
var IdentityProviderType string

var Fail2BanDataStorageCredentials map[string]string
var Fail2BanStorageType string
var Fail2BanTTL int64

var TwilioAccount = ""
var TwilioSecret = ""
var TwilioPhone = ""

var SupportEmail = ""
var SMTPHost = ""
var SMTPUsername = ""
var SMTPPassword = ""
var SMTPPort = ""

var ListenHTTPAddressForOpeners = "localhost:9090"
var ListenHTTPAddress = "localhost:8080"
var ListenGRPCAddress = "localhost:6668"

var GeneratorsPolicy = ""

var TokenTTL = time.Duration(300)
var SendConfirmationCode = false

func Init() error {
	flag.String("configFile", "/opt/config.json", "Provide full path to your config json file")

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	filename := viper.GetString("configFile") // retrieve value from viper

	file, err := os.Open(filename)

	viper.SetConfigType("json")

	if err != nil {
		log.Println(err.Error())
	} else {
		err = viper.ReadConfig(bufio.NewReader(file))

		if err != nil {
			log.Println(err.Error())
			return err
		}
	}

	viper.SetDefault("host.httpaddress", "localhost:8080")
	viper.SetDefault("host.httpaddressinternal", "localhost:9090")
	viper.SetDefault("host.grpcaddress", "localhost:6668")

	viper.SetDefault("datastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "0",
		"password": "",
	})
	viper.SetDefault("datastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("identitysource.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "1",
		"password": "",
	})
	viper.SetDefault("identitysource.type", identity.DATA_STORAGE_PROVIDER)
	viper.SetDefault("identitysource.datastoragetype", storage.REDIS_STORAGE)

	viper.SetDefault("fail2bandatastorage.credentials", map[string]string{
		"host":     "localhost:6379",
		"db":       "5",
		"password": "",
	})
	viper.SetDefault("fail2bandatastorage.type", storage.REDIS_STORAGE)

	viper.SetDefault("fail2banttl", int64(300000))

	viper.SetDefault("smtp.supportemail", "")
	viper.SetDefault("smtp.smtphost", "")
	viper.SetDefault("smtp.smtpusername", "")
	viper.SetDefault("smtp.smtppassword", "")
	viper.SetDefault("smtp.smtpport", "")

	viper.SetDefault("twilio.account", "")
	viper.SetDefault("twilio.secret", "")
	viper.SetDefault("twilio.phone", "")

	viper.SetDefault("generatorspolicy", "2fa")
	viper.SetDefault("sendconfirmationcode", false)

	hostConfig := viper.Sub("host")

	ListenHTTPAddress = hostConfig.GetString("httpaddress")
	ListenHTTPAddressForOpeners = hostConfig.GetString("httpaddressinternal")
	ListenGRPCAddress = hostConfig.GetString("grpcaddress")

	log.Println(ListenHTTPAddress)
	log.Println(ListenHTTPAddressForOpeners)
	log.Println(ListenGRPCAddress)

	datastorageConfig := viper.Sub("datastorage")

	DataStorageCredentials = datastorageConfig.GetStringMapString("credentials")
	StorageType = datastorageConfig.GetString("type")

	identitySourceConfig := viper.Sub("identitysource")

	IdentityStorageCredentials = identitySourceConfig.GetStringMapString("credentials")
	IdentityProviderType = identitySourceConfig.GetString("type")
	IdentityStorageType = identitySourceConfig.GetString("datastoragetype")

	log.Println(IdentityStorageType)

	fail2banDatastorageConfig := viper.Sub("fail2bandatastorage")

	Fail2BanDataStorageCredentials = fail2banDatastorageConfig.GetStringMapString("credentials")
	Fail2BanStorageType = fail2banDatastorageConfig.GetString("type")

	Fail2BanTTL = viper.GetInt64("fail2banttl")

	smtpConfig := viper.Sub("smtp")

	SupportEmail = smtpConfig.GetString("supportemail")
	SMTPHost = smtpConfig.GetString("smtphost")
	SMTPUsername = smtpConfig.GetString("smtpusername")
	SMTPPassword = smtpConfig.GetString("smtppassword")
	SMTPPort = smtpConfig.GetString("smtpport")

	twilioConfig := viper.Sub("twilio")

	TwilioAccount = twilioConfig.GetString("account")
	TwilioSecret = twilioConfig.GetString("secret")
	TwilioPhone = twilioConfig.GetString("phone")

	GeneratorsPolicy = viper.GetString("generatorspolicy")
	SendConfirmationCode = viper.GetBool("sendconfirmationcode")

	return nil
}
