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

package identityutils

import (
	"fmt"
	"strings"

	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/identity-provider/component"
)

func GetActiveIpsForIdentityID(userID string, local bool) ([]string, error) {
	result := []string{}
	cached := map[string]bool{}

	cryptoStorage := component.CreateCryptoStorage()

	wallets, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.IdentityProviderIdentificator, cryptoutils.IDENTIFICATOR_TYPE_WALLET)

	identificatorsIDs, err := cryptoStorage.GetIdentificatorsByIdentityID(userID)

	if err != nil {
		return nil, err
	}

	dataStorage := component.CreateDataStorage()

	for identificatorID := range identificatorsIDs {
		_, ok := wallets[identificatorID]

		if ok == false {
			continue
		}

		keys, err := dataStorage.GetKeys(component.TOKENS, identificatorID+"/*")

		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			fmt.Println(key)
			tokens := strings.Split(key, "/")

			generatorID := tokens[2]

			suffix := component.IP_TABLE

			if local == true {
				suffix = component.IP_TABLE_LOCAL
			}

			ipKeys, err := dataStorage.GetKeys(suffix, generatorID+"/*")

			if err != nil {
				return nil, err
			}

			for _, ipKey := range ipKeys {
				ipTokens := strings.Split(ipKey, "/")
				ip := ipTokens[2]

				_, ok := cached[ip]

				if ok == false {
					cached[ip] = true
					result = append(result, ip)
				}

				//fmt.Println("ip: " + ip)
			}
		}

		suffix := component.IP_TABLE

		if local == true {
			suffix = component.IP_TABLE_LOCAL
		}

		ipKeys, err := dataStorage.GetKeys(suffix, identificatorID+"/*")

		if err != nil {
			return nil, err
		}

		for _, ipKey := range ipKeys {
			ipTokens := strings.Split(ipKey, "/")
			ip := ipTokens[2]

			_, ok := cached[ip]

			if ok == false {
				cached[ip] = true
				result = append(result, ip)
			}

			//fmt.Println("ip: " + ip)
		}
	}

	return result, nil
}

func GetActiveIpsForWallet(walletID string, local bool) (map[string][]string, error) {
	result := map[string][]string{}
	cached := map[string]map[string]bool{}

	dataStorage := component.CreateDataStorage()

	keys, err := dataStorage.GetKeys(component.TOKENS, walletID+"/*")

	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		//fmt.Println(key)
		tokens := strings.Split(key, "/")

		generatorID := tokens[2]

		_, ok := result[generatorID]

		if ok == false {
			result[generatorID] = []string{}
			cached[generatorID] = map[string]bool{}
		}

		suffix := component.IP_TABLE

		if local == true {
			suffix = component.IP_TABLE_LOCAL
		}

		ipKeys, err := dataStorage.GetKeys(suffix, generatorID+"/*")

		if err != nil {
			return nil, err
		}

		for _, ipKey := range ipKeys {
			ipTokens := strings.Split(ipKey, "/")
			ip := ipTokens[2]

			_, ok := cached[generatorID][ip]

			if ok == false {
				cached[generatorID][ip] = true
				result[generatorID] = append(result[generatorID], ip)
			}

			//fmt.Println("ip: " + ip)
		}
	}

	return result, nil
}
