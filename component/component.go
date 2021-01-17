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

package component

import (
	"errors"
	"fmt"

	"github.com/netclave/identity-provider/identity"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/common/storage"
	"github.com/netclave/common/utils"
	"github.com/netclave/identity-provider/config"
)

var COMPONENT_IDENTIFICATOR_ID = "component_identity_provider"
var COMPONENT_REAL_ID = "componentrealid_identity_provider"

var ComponentIdentificatorID = ""
var ComponentPublicKey = ""
var ComponentPrivateKey = ""

var IdentityProviderIdentificator = &cryptoutils.Identificator{}

func LoadComponent() error {
	err := config.Init()

	if err != nil {
		return err
	}

	err = InitDataStorage()

	if err != nil {
		return err
	}

	err = InitFail2BanDataStorage()

	if err != nil {
		return err
	}

	if config.IdentityProviderType == identity.DATA_STORAGE_PROVIDER {
		err = InitIdentityStorage()

		if err != nil {
			return err
		}
	}

	cryptoStorage := CreateCryptoStorage()

	dataStorage := CreateDataStorage()

	privateKeyPem, err := cryptoStorage.RetrievePrivateKey(COMPONENT_IDENTIFICATOR_ID)
	if err != nil || privateKeyPem == "" {
		pair, err := cryptoutils.GenerateKeyPair()

		if err != nil {
			fmt.Println("Generate key pair error")
			return err
		}

		publicKeyPEM, err := cryptoutils.EncodePublicKeyPEM(pair)

		if err != nil {
			fmt.Println("Error encoding public key")
			return err
		}

		privateKeyPEM, err := cryptoutils.EncodePrivateKeyPEM(pair)

		if err != nil {
			fmt.Println("Error encoding private key")
			return err
		}

		err = cryptoStorage.StorePublicKey(COMPONENT_IDENTIFICATOR_ID, publicKeyPEM)
		if err != nil {
			fmt.Println("Error storing public key")
			return err
		}

		err = cryptoStorage.StorePrivateKey(COMPONENT_IDENTIFICATOR_ID, privateKeyPEM)

		if err != nil {
			fmt.Println("Error storing private key")
			return err
		}

		uuid, err := utils.GenerateUUID()

		fmt.Println("Generated UUID: " + uuid)

		if err != nil || uuid == "" {
			fmt.Println("Error generating uuid")
			return err
		}

		err = dataStorage.SetKey(COMPONENT_REAL_ID, "", uuid, 0)

		if err != nil {
			fmt.Println("Error setting key")
			return err
		}

		IdentityProviderIdentificator = &cryptoutils.Identificator{}
		IdentityProviderIdentificator.IdentificatorID = uuid
		IdentityProviderIdentificator.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER

		err = cryptoStorage.AddIdentificator(IdentityProviderIdentificator)

		if err != nil {
			fmt.Println("Error adding identificator")
			return err
		}
	}

	ComponentIdentificatorID, err = dataStorage.GetKey(COMPONENT_REAL_ID, "")

	if err != nil || ComponentIdentificatorID == "" {
		fmt.Println("Error getting UUID")
		return err
	}

	ComponentPublicKey, err = cryptoStorage.RetrievePublicKey(COMPONENT_IDENTIFICATOR_ID)

	if err != nil || ComponentPublicKey == "" {
		fmt.Println("Error getting public key")
		return err
	}

	ComponentPrivateKey, err = cryptoStorage.RetrievePrivateKey(COMPONENT_IDENTIFICATOR_ID)

	if err != nil || ComponentPrivateKey == "" {
		fmt.Println("Error getting private key")
		return err
	}

	IdentityProviderIdentificator = &cryptoutils.Identificator{}
	IdentityProviderIdentificator.IdentificatorID = ComponentIdentificatorID
	IdentityProviderIdentificator.IdentificatorType = cryptoutils.IDENTIFICATOR_TYPE_IDENTITY_PROVIDER

	return nil
}

func CreateDataStorage() *storage.GenericStorage {
	storage := &storage.GenericStorage{
		Credentials: config.DataStorageCredentials,
		StorageType: config.StorageType,
	}

	return storage
}

func InitDataStorage() error {
	storage := &storage.GenericStorage{
		Credentials: config.DataStorageCredentials,
		StorageType: config.StorageType,
	}

	return storage.Init()
}

func CreateFail2BanDataStorage() *storage.GenericStorage {
	storage := &storage.GenericStorage{
		Credentials: config.Fail2BanDataStorageCredentials,
		StorageType: config.Fail2BanStorageType,
	}

	return storage
}

func InitFail2BanDataStorage() error {
	storage := &storage.GenericStorage{
		Credentials: config.Fail2BanDataStorageCredentials,
		StorageType: config.Fail2BanStorageType,
	}

	return storage.Init()
}

func CreateCryptoStorage() *cryptoutils.CryptoStorage {
	cryptoStorage := &cryptoutils.CryptoStorage{
		Credentials: config.DataStorageCredentials,
		StorageType: config.StorageType,
	}

	return cryptoStorage
}

func InitIdentityStorage() error {
	storage := &storage.GenericStorage{
		Credentials: config.IdentityStorageCredentials,
		StorageType: config.IdentityStorageType,
	}

	return storage.Init()
}

func CreateIdentityProvider() (identity.Provider, error) {
	switch config.IdentityProviderType {
	case identity.IN_MEMORY_PROVIDER:
		provider := &identity.InMemoryProvider{
			Data: map[string]*identity.IdentityData{},
		}

		return provider, nil
	case identity.DATA_STORAGE_PROVIDER:
		storage := &storage.GenericStorage{
			Credentials: config.IdentityStorageCredentials,
			StorageType: config.IdentityStorageType,
		}

		provider := &identity.DataStorageProvider{
			Storage: storage,
		}

		return provider, nil
	default:
		return nil, errors.New("No such identity provider type")
	}
}
