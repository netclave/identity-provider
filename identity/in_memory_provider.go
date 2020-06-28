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

import "errors"

type InMemoryProvider struct {
	Data map[string]*IdentityData
}

func (imp *InMemoryProvider) GetIdentityByEmailOrPhone(emailOrPhone string) ([]*IdentityData, error) {
	result := []*IdentityData{}

	for _, value := range imp.Data {
		if value.Email == emailOrPhone || value.Phone == emailOrPhone {
			result = append(result, value)
		}
	}

	return result, nil
}

func (imp *InMemoryProvider) GetIdentityByID(identityID string) (*IdentityData, error) {
	value, ok := imp.Data[identityID]

	if ok == false {
		return nil, errors.New("No such identity id")
	}

	return value, nil
}

func (imp *InMemoryProvider) ListIdentities() ([]*IdentityData, error) {
	result := []*IdentityData{}

	for _, value := range imp.Data {
		result = append(result, value)
	}

	return result, nil
}

func (imp *InMemoryProvider) AddIdentity(data *IdentityData) error {
	imp.Data[data.ID] = data

	return nil
}

func (imp *InMemoryProvider) DelIdentity(identityID string) error {
	delete(imp.Data, identityID)

	return nil
}
