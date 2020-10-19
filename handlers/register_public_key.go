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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/jsonutils"
	"github.com/netclave/common/notification"
	"github.com/netclave/identity-provider/component"
	"github.com/netclave/identity-provider/config"
)

func EncodeToString(max int) (string, error) {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if n != max {
		return "", err
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b), nil
}

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

func GenerateConfirmationCode(size int) (string, error) {
	return EncodeToString(size)
}

type RegisterPublicKeyForm struct {
	Identificator string `json:"identificator"`
}

func (e *RegisterPublicKeyForm) InputValidation() error {
	if len(e.Identificator) == 0 {
		return errors.New("Missing identificator")
	}

	return nil
}

func RegisterPublicKey(w http.ResponseWriter, r *http.Request) {

	request, err := jsonutils.ParseRequest(r)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not read body", err.Error(), w)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	response, id, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not verify request", err.Error(), w)
		return
	}

	form := &RegisterPublicKeyForm{}

	err = json.Unmarshal([]byte(response), form)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Request missing args", err.Error(), w)
		return
	}

	err = form.InputValidation()

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Request missing args", err.Error(), w)
		return
	}

	identityProvider, err := component.CreateIdentityProvider()

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Error creating identity provider", err.Error(), w)
		return
	}

	result, err := identityProvider.GetIdentityByEmailOrPhone(form.Identificator)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Error while getting identificator", err.Error(), w)
		return
	}

	if len(result) <= 0 {
		fmt.Println("Can not find identificator in identity provider")
		jsonutils.EncodeResponse("400", "Can not find identificator", "", w)
		return
	}

	identityID := result[0].ID

	previousIdentityID, err := cryptoStorage.GetIdentityIDForIdentificator(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get previous ldap id for identificator", err.Error(), w)
		return
	}

	if previousIdentityID != "" && previousIdentityID != identityID {
		fmt.Println("Identificator already bound to different ldap id")
		jsonutils.EncodeResponse("400", "Identificator already bound to different ldap id", "Identificator already bound to different ldap id", w)
		return
	}

	confirmationCode, err := GenerateConfirmationCode(8)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not generate confirmation code", err.Error(), w)
		return
	}

	fmt.Println(confirmationCode)

	dataStorage := component.CreateDataStorage()

	err = dataStorage.SetKey(cryptoutils.IDENTIFICATOR_CONFIRMATION_CODE,
		id, confirmationCode, 300*time.Second)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not store confirmation code", err.Error(), w)
		return
	}

	if request.PublicKey == "" {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "No public key", err.Error(), w)
		return
	}

	err = cryptoStorage.StoreTempPublicKey(id, request.PublicKey)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not store temp public key", err.Error(), w)
		return
	}

	err = cryptoStorage.SetTempIdentityIDForIdentificator(id, identityID)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not store ldap id for identificator", err.Error(), w)
		return
	}

	if config.SendConfirmationCode == true {
		if notification.IsEmail(form.Identificator) == true {
			fmt.Println("Sending email")

			_, err := notification.SendSMTPEmail(form.Identificator, "Confirmation code", confirmationCode, config.SupportEmail,
				config.SMTPHost, config.SMTPPort, config.SMTPUsername, config.SMTPPassword)

			if err != nil {
				fmt.Println(err.Error())
				jsonutils.EncodeResponse("400", "Can not send email", err.Error(), w)
				return
			}
		} else {
			fmt.Println("Sending sms")

			_, err := notification.SendSMS(form.Identificator, confirmationCode, config.TwilioAccount, config.TwilioSecret, config.TwilioPhone)

			if err != nil {
				fmt.Println(err.Error())
				jsonutils.EncodeResponse("400", "Can not send sms", err.Error(), w)
				return
			}
		}
	}

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	signedResponse, err := jsonutils.SignAndEncryptResponse("SMS with confirmation code sent", identityProviderID,
		privateKeyPEM, publicKeyPEM, request.PublicKey, false)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not encrypt request", err.Error(), w)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w)
}

type ConfirmPublicKeyForm struct {
	ConfirmationCode  string `json:"confirmationCode"`
	IdentificatorType string `json:"identificatorType"`
	IdentificatorName string `json:"identificatorName"`
}

func (e *ConfirmPublicKeyForm) InputValidation() error {
	if len(e.ConfirmationCode) == 0 {
		return errors.New("Missing confirmation key")
	}

	if len(e.IdentificatorType) == 0 {
		return errors.New("Missing identificator type")
	}

	if e.IdentificatorType != cryptoutils.IDENTIFICATOR_TYPE_WALLET &&
		e.IdentificatorType != cryptoutils.IDENTIFICATOR_TYPE_GENERATOR &&
		e.IdentificatorType != cryptoutils.IDENTIFICATOR_TYPE_OPENER &&
		e.IdentificatorType != cryptoutils.IDENTIFICATOR_TYPE_PROXY {
		return errors.New("Wrong identificator type")
	}

	return nil
}

func ConfirmPublicKey(w http.ResponseWriter, r *http.Request) {
	request, err := jsonutils.ParseRequest(r)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not read body", err.Error(), w)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	response, id, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not verify request", err.Error(), w)
		return
	}

	identityID, err := cryptoStorage.GetTempIdentityIDForIdentificator(id)

	if err != nil || identityID == "" {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get ldap id", err.Error(), w)
		return
	}

	form := &ConfirmPublicKeyForm{}

	err = json.Unmarshal([]byte(response), form)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not decode form", err.Error(), w)
		return
	}

	err = form.InputValidation()

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Request missing args", err.Error(), w)
		return
	}

	confirmationCode := form.ConfirmationCode

	dataStorage := component.CreateDataStorage()

	codeInDb, err := dataStorage.GetKey(cryptoutils.IDENTIFICATOR_CONFIRMATION_CODE,
		id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Request missing args", err.Error(), w)
		return
	}

	if confirmationCode != codeInDb {
		fmt.Println("Code no match")
		jsonutils.EncodeResponse("400", "Code no match", "Code no match", w)
		return
	}

	publicKey, err := cryptoStorage.RetrieveTempPublicKey(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get temp public key", err.Error(), w)
		return
	}

	err = cryptoStorage.StorePublicKey(id, publicKey)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get store public key", err.Error(), w)
		return
	}

	_, err = cryptoStorage.DeleteTempPublicKey(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete temp public key", err.Error(), w)
		return
	}

	err = cryptoStorage.SetIdentityIDForIdentificator(id, identityID)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not store ldap id for identificator", err.Error(), w)
		return
	}

	err = cryptoStorage.AddIdentificatorToIdentityID(id, identityID)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not store identificator for ldap id", err.Error(), w)
		return
	}

	_, err = cryptoStorage.DelTempIdentityIDForIdentificator(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete temp ldap id for identificator", err.Error(), w)
		return
	}

	identificator := &cryptoutils.Identificator{}
	identificator.IdentificatorID = id
	identificator.IdentificatorType = form.IdentificatorType
	identificator.IdentificatorName = form.IdentificatorName

	err = cryptoStorage.AddIdentificator(identificator)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not add identificator", err.Error(), w)
		return
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(identificator, component.IdentityProviderIdentificator)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not connect identity provider identificator to identificator", err.Error(), w)
		return
	}

	err = cryptoStorage.AddIdentificatorToIdentificator(component.IdentityProviderIdentificator, identificator)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not connect identificator to identity provider identificator", err.Error(), w)
		return
	}

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	signedResponse, err := jsonutils.SignAndEncryptResponse("Identificator confirmed", identityProviderID,
		privateKeyPEM, publicKeyPEM, publicKey, false)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not encrypt request", err.Error(), w)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w)
}

type DeletePublicKeyForm struct {
}

func (e *DeletePublicKeyForm) InputValidation() error {
	return nil
}

func DeletePublicKey(w http.ResponseWriter, r *http.Request) {
	request, err := jsonutils.ParseRequest(r)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not read body", err.Error(), w)
		return
	}

	cryptoStorage := component.CreateCryptoStorage()

	_, id, err := jsonutils.VerifyAndDecrypt(request, component.ComponentPrivateKey, cryptoStorage)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not verify request", err.Error(), w)
		return
	}

	identificators, err := cryptoStorage.GetIdentificators()

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get identificators", err.Error(), w)
		return
	}

	identificator := identificators[id]

	generators, err := cryptoStorage.GetIdentificatorToIdentificatorMap(identificator, cryptoutils.IDENTIFICATOR_TYPE_GENERATOR)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get generators", err.Error(), w)
		return
	}

	for key := range generators {
		generator := identificators[key]
		err = cryptoStorage.DelIdentificatorToIdentificator(identificator, generator)

		if err != nil {
			fmt.Println(err.Error())
			jsonutils.EncodeResponse("400", "Can not delete relation", err.Error(), w)
			return
		}

		err = cryptoStorage.DelIdentificatorToIdentificator(generator, identificator)

		if err != nil {
			fmt.Println(err.Error())
			jsonutils.EncodeResponse("400", "Can not delete relation", err.Error(), w)
			return
		}
	}

	err = cryptoStorage.DelIdentificatorToIdentificator(identificator, component.IdentityProviderIdentificator)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete relation", err.Error(), w)
		return
	}

	err = cryptoStorage.DelIdentificatorToIdentificator(component.IdentityProviderIdentificator, identificator)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete relation", err.Error(), w)
		return
	}

	identityID, err := cryptoStorage.GetIdentityIDForIdentificator(id)

	if err != nil || identityID == "" {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not get ldap id", err.Error(), w)
		return
	}

	err = cryptoStorage.DelIdentificatorFromIdentityID(id, identityID)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete identificator for ldap", err.Error(), w)
		return
	}

	_, err = cryptoStorage.DelIdentityIDForIdentificator(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete ldap id", err.Error(), w)
		return
	}

	publicKey, err := cryptoStorage.RetrievePublicKey(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can no retrieve delete public key", err.Error(), w)
		return
	}

	_, err = cryptoStorage.DeletePublicKey(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete public key id", err.Error(), w)
		return
	}

	err = cryptoStorage.DeleteIdentificator(id)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not delete identificator", err.Error(), w)
		return
	}

	identityProviderID := component.ComponentIdentificatorID
	privateKeyPEM := component.ComponentPrivateKey
	publicKeyPEM := component.ComponentPublicKey

	signedResponse, err := jsonutils.SignAndEncryptResponse("Identificator deleted", identityProviderID,
		privateKeyPEM, publicKeyPEM, publicKey, false)

	if err != nil {
		fmt.Println(err.Error())
		jsonutils.EncodeResponse("400", "Can not encrypt request", err.Error(), w)
		return
	}

	jsonutils.EncodeResponse("200", "OK", signedResponse, w)
}
