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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/jsonutils"
	"github.com/netclave/common/networkutils"
	"github.com/netclave/common/utils"
	"github.com/netclave/identity-provider/component"
	"github.com/netclave/identity-provider/config"
	"github.com/netclave/identity-provider/identityutils"
)

type EchangePublicKeysViaQRForm struct {
	WalletID           string `json:"walletID"`
	IdentityProviderID string `json:"identityProviderID"`
	Signature          string `json:"signature"`
}

type TokenForm struct {
	WalletIDToTokenMap map[string]string   `json:"walletIdToTokenMap"`
	LocalIps           []string            `json:"localIps"`
	RemoteIps          map[string][]string `json:"remoteIps"`
}

func (e *EchangePublicKeysViaQRForm) InputValidation() error {
	if len(e.WalletID) == 0 {
		return errors.New("Missing walletID")
	}
	if len(e.IdentityProviderID) == 0 {
		return errors.New("Missing identityProviderID")
	}
	if len(e.Signature) == 0 {
		return errors.New("Missing signature")
	}

	return nil
}

func verifyQR(walletID, identityProviderID, signature string) error {
	cryptoStorage := component.CreateCryptoStorage()

	walletPublicKeyPem, err := cryptoStorage.RetrievePublicKey(walletID)
	if err != nil {
		return err
	}

	walletPublicKey, err := cryptoutils.ParseRSAPublicKey(walletPublicKeyPem)
	if err != nil {
		return err
	}

	verified, err := cryptoutils.Verify(walletID+","+identityProviderID, signature, walletPublicKey)

	if err != nil {
		return err
	}

	if !verified {
		return errors.New("Not verified")
	}

	return nil
}

func ExchangePublicKeysViaQR(w http.ResponseWriter, r *http.Request) {
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

	response, generatorID, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err.Error(), w, fail2BanData)
		return
	}

	form := &EchangePublicKeysViaQRForm{}

	err = json.Unmarshal([]byte(response), form)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not decode form", err.Error(), w, fail2BanData)
		return
	}

	err = form.InputValidation()

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Request missing args", err.Error(), w, fail2BanData)
		return
	}

	walletID := form.WalletID
	identityProviderID := form.IdentityProviderID
	signature := form.Signature
	componentIdentityProviderID := component.ComponentIdentificatorID

	err = verifyQR(walletID, identityProviderID, signature)

	if err != nil {
		log.Println(err)
		jsonutils.EncodeResponse("400", err.Error(), nil, w, fail2BanData)
		return
	}

	if identityProviderID != componentIdentityProviderID {
		log.Println("Wrong identity provider id")
		jsonutils.EncodeResponse("400", "Wrong identity provider id", nil, w, fail2BanData)
		return
	}

	generatorIdentificator := &cryptoutils.Identificator{}
	generatorIdentificator.IdentificatorID = generatorID
	generatorIdentificator.IdentificatorType = "generator"

	walletIdentificator := &cryptoutils.Identificator{}
	walletIdentificator.IdentificatorID = walletID
	walletIdentificator.IdentificatorType = "wallet"

	err = cryptoStorage.AddIdentificatorToIdentificator(generatorIdentificator, walletIdentificator)
	if err != nil {
		log.Println(err)
		jsonutils.EncodeResponse("400", "Cannot add IdentificatorToIdentificator", err.Error(), w, fail2BanData)
		return
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(walletIdentificator, generatorIdentificator)
	if err != nil {
		log.Println(err)
		jsonutils.EncodeResponse("400", "Cannot add IdentificatorToIdentificator", err.Error(), w, fail2BanData)
		return
	}

	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	generatorPublicKey, err := cryptoStorage.RetrievePublicKey(generatorID)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Generator public key cannot be retrieved", err.Error(), w, fail2BanData)
		return
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(walletID+","+identityProviderID, identityProviderID,
		privateKeyPEM, publicKeyPEM, generatorPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt request", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

func saveRemoteIP(ip string, id string) error {
	dataStorage := component.CreateDataStorage()

	return dataStorage.SetKey(component.IP_TABLE, id+"/"+ip, ip, config.TokenTTL*time.Second)
}

func saveLocalIP(ip string, id string) error {
	dataStorage := component.CreateDataStorage()

	cleanedIP := strings.ReplaceAll(ip, "https://", "")
	cleanedIP = strings.ReplaceAll(cleanedIP, "http://", "")

	return dataStorage.SetKey(component.IP_TABLE_LOCAL, id+"/"+cleanedIP, cleanedIP, config.TokenTTL*time.Second)
}

func saveTokensForWallet(ip string, walletIDToTokenMap map[string]string, walletIDGlobal string) error {
	err := saveRemoteIP(ip, walletIDGlobal)

	if err != nil {
		return err
	}

	dataStorage := component.CreateDataStorage()

	for walletID, token := range walletIDToTokenMap {
		err = dataStorage.SetKey(component.TOKENS, walletID+"/"+walletIDGlobal+"/"+token, token, config.TokenTTL*time.Second)
		if err != nil {
			log.Println(err.Error())
			return err
		}
	}

	return nil
}

func SaveTokens(w http.ResponseWriter, r *http.Request) {
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

	decryptedRequest, generatorID, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err.Error(), w, fail2BanData)
		return
	}

	log.Println("Saving tokens for: " + generatorID)

	ipPort := networkutils.GetRemoteAddress(r)

	//log.Printf(ipPort)

	ipPortSplit := strings.Split(ipPort, ":")

	ip := ""

	for i := 0; i < len(ipPortSplit)-1; i++ {
		ip = ip + ipPortSplit[i]

		if i < len(ipPortSplit)-2 {
			ip = ip + ":"
		}
	}

	wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.IdentityProviderIdentificator, cryptoutils.IDENTIFICATOR_TYPE_WALLET)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get generators", err.Error(), w, fail2BanData)
		return
	}

	tokenForm := &TokenForm{}
	err = json.Unmarshal([]byte(decryptedRequest), tokenForm)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot unmarshal request", err.Error(), w, fail2BanData)
		return
	}

	walletIDToTokenMap := tokenForm.WalletIDToTokenMap
	localIps := tokenForm.LocalIps
	remoteIps := tokenForm.RemoteIps

	_, isWallet := wallets[generatorID]

	if isWallet == true {
		if config.GeneratorsPolicy == "2fa" {
			jsonutils.EncodeResponse("400", "Wallets are not permitted with this policy", "Wallets are not permitted with this policy", w, fail2BanData)
			return
		}

		err = saveTokensForWallet(ip, walletIDToTokenMap, generatorID)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Can not write tokens to data storage", err.Error(), w, fail2BanData)
			return
		} else {
			walletPublicKey, err := cryptoStorage.RetrievePublicKey(generatorID)
			if err != nil {
				log.Println(err.Error())
				jsonutils.EncodeResponse("400", "Wallet public key cannot be retrieved", err.Error(), w, fail2BanData)
				return
			}

			identityProviderID := component.ComponentIdentificatorID
			privateKeyPEM := component.ComponentPrivateKey
			publicKeyPEM := component.ComponentPublicKey

			signedResponse, err := jsonutils.SignAndEncryptResponse(map[string]string{}, identityProviderID,
				privateKeyPEM, publicKeyPEM, walletPublicKey, false)

			if err != nil {
				log.Println(err.Error())
				jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
				return
			}

			jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
			return
		}
	}

	log.Println("Storing ip: " + ip)

	saveRemoteIP(ip, generatorID)

	for walletID, ips := range remoteIps {
		for _, ip := range ips {
			log.Println("Remote ip: " + walletID + " " + ip)

			saveRemoteIP(ip, walletID)
		}
	}

	for _, ip := range localIps {
		log.Println("Local ip: " + generatorID + " " + ip)

		saveLocalIP(ip, generatorID)
	}

	dataStorage := component.CreateDataStorage()

	for walletID, token := range walletIDToTokenMap {
		err = dataStorage.SetKey(component.TOKENS, generatorID+"/"+walletID+"/"+token, token, config.TokenTTL*time.Second)
		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot write token to datastorage", err.Error(), w, fail2BanData)
			return
		}

		err = dataStorage.SetKey(component.TOKENS, walletID+"/"+generatorID+"/"+token, token, config.TokenTTL*time.Second)
		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot write token to datastorage", err.Error(), w, fail2BanData)
			return
		}
	}

	generatorPublicKey, err := cryptoStorage.RetrievePublicKey(generatorID)
	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Generator public key cannot be retrieved", err.Error(), w, fail2BanData)
		return
	}

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	signedResponse, err := jsonutils.SignAndEncryptResponse(map[string]string{}, identityProviderID,
		privateKeyPEM, publicKeyPEM, generatorPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

func ListPublicKeysForIdentificator(w http.ResponseWriter, r *http.Request) {
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

	//fmt.Println("ClientID: " + clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err.Error(), w, fail2BanData)
		return
	}

	identificators, err := cryptoStorage.GetIdentificators()

	if err != nil {
		jsonutils.EncodeResponse("400", "Cannot get identificators", err.Error(), w, fail2BanData)
		return
	}

	identificator, ok := identificators[clientID]

	if ok == false {
		jsonutils.EncodeResponse("400", "No such identificator", "No such identificator", w, fail2BanData)
		return
	}

	clientPublicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	generators, err := cryptoStorage.GetIdentificatorToIdentificatorMap(identificator, cryptoutils.IDENTIFICATOR_TYPE_GENERATOR)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get generators", err.Error(), w, fail2BanData)
		return
	}

	openers, err := cryptoStorage.GetIdentificatorToIdentificatorMap(identificator, cryptoutils.IDENTIFICATOR_TYPE_OPENER)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get openers", err.Error(), w, fail2BanData)
		return
	}

	wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(identificator, cryptoutils.IDENTIFICATOR_TYPE_WALLET)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get wallets", err.Error(), w, fail2BanData)
		return
	}

	sharedIdentificators := map[string]*cryptoutils.Identificator{}

	for id, generator := range generators {
		sharedIdentificators[id] = generator
	}

	for id, opener := range openers {
		sharedIdentificators[id] = opener
	}

	for id, wallet := range wallets {
		sharedIdentificators[id] = wallet
	}

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	data := map[string]string{}

	for id, sharedIdentificator := range sharedIdentificators {
		publicKey, err := cryptoStorage.RetrievePublicKey(id)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
			return
		}

		data[id] = sharedIdentificator.IdentificatorID + "," + sharedIdentificator.IdentificatorType + "," + publicKey
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(data, identityProviderID,
		privateKeyPEM, publicKeyPEM, clientPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

func ListCapabilities(w http.ResponseWriter, r *http.Request) {
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

	//fmt.Println("ClientID: " + clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot verify or decrypt request", err.Error(), w, fail2BanData)
		return
	}

	clientPublicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	response := map[string]string{}

	response["generatorspolicy"] = config.GeneratorsPolicy

	signedResponse, err := jsonutils.SignAndEncryptResponse(response, identityProviderID,
		privateKeyPEM, publicKeyPEM, clientPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

func ListGeneratorIPs(w http.ResponseWriter, r *http.Request) {
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

	clientPublicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	localIps, err := identityutils.GetActiveIpsForWallet(clientID, true)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get local ips", err.Error(), w, fail2BanData)
		return
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(localIps, component.ComponentIdentificatorID,
		component.ComponentPrivateKey, component.ComponentPublicKey, clientPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

func ListServicesForWallet(w http.ResponseWriter, r *http.Request) {
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

	clientPublicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	userID, err := cryptoStorage.GetIdentityIDForIdentificator(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	services, err := ListServicesForUserInternal(userID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get services for user", err.Error(), w, fail2BanData)
		return
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(services, component.ComponentIdentificatorID,
		component.ComponentPrivateKey, component.ComponentPublicKey, clientPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

type WalletsAndServices struct {
	PublicKeys map[string]string
	Services   map[string][]string
}

func GetWalletsAndServices(w http.ResponseWriter, r *http.Request) {
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

	clientPublicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.IdentityProviderIdentificator, cryptoutils.IDENTIFICATOR_TYPE_WALLET)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get wallets", err.Error(), w, fail2BanData)
		return
	}

	publicKeys := map[string]string{}
	services := map[string][]string{}

	for _, walletIdentificator := range wallets {
		userID, err := cryptoStorage.GetIdentityIDForIdentificator(walletIdentificator.IdentificatorID)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot get user ID", err.Error(), w, fail2BanData)
			return
		}

		walletPublicKey, err := cryptoStorage.RetrievePublicKey(walletIdentificator.IdentificatorID)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot get public key for wallet", err.Error(), w, fail2BanData)
			return
		}

		servicesTemp, err := ListServicesForUserInternal(userID)

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot list service for user", err.Error(), w, fail2BanData)
			return
		}

		services[walletIdentificator.IdentificatorID] = servicesTemp
		publicKeys[walletIdentificator.IdentificatorID] = walletPublicKey
	}

	result := WalletsAndServices{
		PublicKeys: publicKeys,
		Services:   services,
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(result, component.ComponentIdentificatorID,
		component.ComponentPrivateKey, component.ComponentPublicKey, clientPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}

func GetActiveTokens(w http.ResponseWriter, r *http.Request) {
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

	clientPublicKey, err := cryptoStorage.RetrievePublicKey(clientID)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get public key", err.Error(), w, fail2BanData)
		return
	}

	wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.IdentityProviderIdentificator, cryptoutils.IDENTIFICATOR_TYPE_WALLET)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot get wallets", err.Error(), w, fail2BanData)
		return
	}

	activeTokens := map[string][]string{}

	dataStorage := component.CreateDataStorage()

	for _, wallet := range wallets {
		keys, err := dataStorage.GetKeys(component.TOKENS, wallet.IdentificatorID+"/*")

		if err != nil {
			log.Println(err.Error())
			jsonutils.EncodeResponse("400", "Cannot get tokens", err.Error(), w, fail2BanData)
			return
		}

		for _, key := range keys {
			keyTokens := strings.Split(key, "/")
			token := keyTokens[3]

			_, ok := activeTokens[wallet.IdentificatorID]

			if ok == false {
				activeTokens[wallet.IdentificatorID] = []string{}
			}

			activeTokens[wallet.IdentificatorID] = append(activeTokens[wallet.IdentificatorID], token)

		}
	}

	signedResponse, err := jsonutils.SignAndEncryptResponse(activeTokens, component.ComponentIdentificatorID,
		component.ComponentPrivateKey, component.ComponentPublicKey, clientPublicKey, false)

	if err != nil {
		log.Println(err.Error())
		jsonutils.EncodeResponse("400", "Cannot encrypt response", err.Error(), w, fail2BanData)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w, fail2BanData)
}
