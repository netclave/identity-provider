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

package identity

import (
	"github.com/netclave/common/storage"
)

var IDENTITIES = "identities"

type DataStorageProvider struct {
	Storage *storage.GenericStorage
}

func (dsp *DataStorageProvider) GetIdentityByEmailOrPhone(emailOrPhone string) ([]*IdentityData, error) {
	result := []*IdentityData{}

	var objects map[string]*IdentityData

	err := dsp.Storage.GetMap(IDENTITIES, "", &objects)

	if err != nil {
		return nil, err
	}

	for _, identity := range objects {
		if identity.Email == emailOrPhone || identity.Phone == emailOrPhone {
			result = append(result, identity)
		}
	}

	return result, nil
}

func (dsp *DataStorageProvider) GetIdentityByID(identityID string) (*IdentityData, error) {
	identity := &IdentityData{}

	err := dsp.Storage.GetFromMap(IDENTITIES, "", identityID, identity)

	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (dsp *DataStorageProvider) ListIdentities() ([]*IdentityData, error) {
	result := []*IdentityData{}

	var objects map[string]*IdentityData

	err := dsp.Storage.GetMap(IDENTITIES, "", &objects)

	if err != nil {
		return nil, err
	}

	for _, value := range objects {
		result = append(result, value)
	}

	return result, nil
}

func (dsp *DataStorageProvider) AddIdentity(data *IdentityData) error {
	return dsp.Storage.AddToMap(IDENTITIES, "", data.ID, data)
}

func (dsp *DataStorageProvider) DelIdentity(identityID string) error {
	return dsp.Storage.DelFromMap(IDENTITIES, "", identityID)
}
