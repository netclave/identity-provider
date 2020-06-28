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

type IdentityData struct {
	ID    string
	Phone string
	Email string
	Type  string
}

var IN_MEMORY_PROVIDER = "in_memory"
var DATA_STORAGE_PROVIDER = "data_storage"

type Provider interface {
	GetIdentityByEmailOrPhone(emailOrPhone string) ([]*IdentityData, error)
	GetIdentityByID(identityID string) (*IdentityData, error)
	ListIdentities() ([]*IdentityData, error)
	AddIdentity(data *IdentityData) error
	DelIdentity(identityID string) error
}
