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

package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/netclave/common/jsonutils"
	"github.com/netclave/common/networkutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/identity-provider/component"
	"github.com/netclave/identity-provider/config"
	"github.com/netclave/identity-provider/identityutils"
)

type IPPortProtocols struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	Protocols string `json:"protocols"`
}

func ListOpenerIPs(w http.ResponseWriter, r *http.Request) {
	fail2banDataStorage := component.CreateFail2BanDataStorage()

	fail2BanData := &utils.Fail2BanData{
		DataStorage:   fail2banDataStorage,
		RemoteAddress: networkutils.GetRemoteAddress(r),
		TTL:           config.Fail2BanTTL,
	}

	request, err := jsonutils.ParseRequest(r)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot parse request", err.Error(), w, fail2BanData)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	_, clientID, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err.Error(), w, fail2BanData)
		return
	}

	publicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	dataStorage := component.CreateDataStorage()

	keys, err := dataStorage.GetKeys(component.USER_TO_OPENER_PORTS, "*/"+clientID+"/*")

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get keys", err.Error(), w, fail2BanData)
		return
	}

	result := []IPPortProtocols{}

	for _, key := range keys {
		protocols, err := dataStorage.GetFullKey(key)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot get protocols", err.Error(), w, fail2BanData)
			return
		}

		fmt.Println(key)

		tokens := strings.Split(key, "/")
		userID := tokens[1]
		port := tokens[3]

		ips, err := identityutils.GetActiveIpsForIdentityID(userID, false)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot get ips for user", err.Error(), w, fail2BanData)
			return
		}

		for _, ip := range ips {
			data := IPPortProtocols{
				IP:        ip,
				Port:      port,
				Protocols: protocols,
			}

			result = append(result, data)
		}
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(result, component.ComponentIdentificatorID,
		component.ComponentPrivateKey, component.ComponentPublicKey, publicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}
