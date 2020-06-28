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
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	api "github.com/netclave/apis/identity-provider/api"
	"github.com/netclave/common/cryptoutils"
	"github.com/netclave/identity-provider/component"
	"github.com/netclave/identity-provider/identity"
	"github.com/netclave/identity-provider/identityutils"
)

// Server represents the gRPC server
type GrpcServer struct {
}

func (s *GrpcServer) ListOpeners(ctx context.Context, in *api.ListOpenersRequest) (*api.ListOpenersResponse, error) {
	cryptoStorage := component.CreateCryptoStorage()

	openers, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.IdentityProviderIdentificator, cryptoutils.IDENTIFICATOR_TYPE_OPENER)

	if err != nil {
		log.Println(err.Error())
		return &api.ListOpenersResponse{}, err
	}

	log.Println(len(openers))

	protoOpeners := []*api.Opener{}

	for _, identificator := range openers {
		log.Println(identificator.IdentificatorName)
		if identificator.IdentificatorType == cryptoutils.IDENTIFICATOR_TYPE_OPENER {
			opener := &api.Opener{
				OpenerId: identificator.IdentificatorID,
				Name:     identificator.IdentificatorName,
			}

			protoOpeners = append(protoOpeners, opener)
		}
	}

	return &api.ListOpenersResponse{Openers: protoOpeners}, nil
}

func (s *GrpcServer) PutUser(ctx context.Context, in *api.PutUserRequest) (*api.PutUserResponse, error) {
	identityProvider, err := component.CreateIdentityProvider()

	if err != nil {
		return &api.PutUserResponse{}, err
	}

	identity := &identity.IdentityData{
		Email: in.User.Email,
		Phone: in.User.Phone,
		ID:    in.User.UserId,
		Type:  in.User.Type,
	}

	err = identityProvider.AddIdentity(identity)

	if err != nil {
		return &api.PutUserResponse{}, err
	}

	return &api.PutUserResponse{}, nil
}

func (s *GrpcServer) DelUser(ctx context.Context, in *api.DelUserRequest) (*api.DelUserResponse, error) {
	identityProvider, err := component.CreateIdentityProvider()

	if err != nil {
		return &api.DelUserResponse{}, err
	}

	err = identityProvider.DelIdentity(in.UserId)

	if err != nil {
		return &api.DelUserResponse{}, err
	}

	return &api.DelUserResponse{}, nil
}

func (s *GrpcServer) GetUser(ctx context.Context, in *api.GetUserRequest) (*api.GetUserResponse, error) {
	identityProvider, err := component.CreateIdentityProvider()

	if err != nil {
		return &api.GetUserResponse{}, err
	}

	identity, err := identityProvider.GetIdentityByID(in.UserId)

	if err != nil {
		return &api.GetUserResponse{}, err
	}

	user := &api.User{
		Email:  identity.Email,
		Phone:  identity.Phone,
		UserId: identity.ID,
		Type:   identity.Type,
	}

	return &api.GetUserResponse{
		User: user,
	}, nil
}

func (s *GrpcServer) ListUsers(ctx context.Context, in *api.ListUsersRequest) (*api.ListUsersResponse, error) {
	identityProvider, err := component.CreateIdentityProvider()

	if err != nil {
		return &api.ListUsersResponse{}, err
	}

	users, err := identityProvider.ListIdentities()

	if err != nil {
		return &api.ListUsersResponse{}, err
	}

	result := []*api.User{}

	for _, user := range users {
		protoUser := &api.User{
			UserId: user.ID,
			Email:  user.Email,
			Phone:  user.Phone,
		}

		result = append(result, protoUser)
	}

	return &api.ListUsersResponse{
		Users: result,
	}, nil
}

func (s *GrpcServer) AddPortForUserAndOpener(ctx context.Context, in *api.AddPortForUserAndOpenerRequest) (*api.AddPortForUserAndOpenerResponse, error) {
	userID := in.UserId
	openerID := in.OpenerId
	port := in.Port
	protocols := in.Protocols

	dataStorage := component.CreateDataStorage()

	err := dataStorage.SetKey(component.USER_TO_OPENER_PORTS, userID+"/"+openerID+"/"+port, protocols, 0)

	if err != nil {
		return &api.AddPortForUserAndOpenerResponse{}, err
	}

	return &api.AddPortForUserAndOpenerResponse{}, nil
}

func (s *GrpcServer) DelPortForUserAndOpener(ctx context.Context, in *api.DelPortForUserAndOpenerRequest) (*api.DelPortForUserAndOpenerResponse, error) {
	userID := in.UserId
	openerID := in.OpenerId
	port := in.Port

	dataStorage := component.CreateDataStorage()

	_, err := dataStorage.DelKey(component.USER_TO_OPENER_PORTS, userID+"/"+openerID+"/"+port)

	if err != nil {
		return &api.DelPortForUserAndOpenerResponse{}, err
	}

	return &api.DelPortForUserAndOpenerResponse{}, nil
}

func (s *GrpcServer) ListPortsForUser(ctx context.Context, in *api.ListPortsForUserRequest) (*api.ListPortsForUserResponse, error) {
	userID := in.UserId

	result := []*api.OpenerAndPort{}

	cryptoStorage := component.CreateCryptoStorage()

	openers, err := cryptoStorage.GetIdentificatorToIdentificatorMap(component.IdentityProviderIdentificator, cryptoutils.IDENTIFICATOR_TYPE_OPENER)

	if err != nil {
		log.Println(err.Error())
		return &api.ListPortsForUserResponse{}, err
	}

	dataStorage := component.CreateDataStorage()

	keys, err := dataStorage.GetKeys(component.USER_TO_OPENER_PORTS, userID+"/*")

	if err != nil {
		return &api.ListPortsForUserResponse{}, err
	}

	for _, key := range keys {
		value, err := dataStorage.GetFullKey(key)

		if err != nil {
			return &api.ListPortsForUserResponse{}, err
		}

		tokens := strings.Split(key, "/")
		identificatorID := tokens[2]
		port := tokens[3]

		opener, ok := openers[identificatorID]

		if ok == false {
			log.Println("No such opener")
			return &api.ListPortsForUserResponse{}, errors.New("No such opener")
		}

		identificatorName := opener.IdentificatorName

		protoOpenerAndPort := &api.OpenerAndPort{
			OpenerId:   identificatorID,
			OpenerName: identificatorName,
			Port:       port,
			Protocols:  value,
		}

		result = append(result, protoOpenerAndPort)
	}

	return &api.ListPortsForUserResponse{
		Result: result,
	}, nil
}

func (s *GrpcServer) ListPortsForOpener(ctx context.Context, in *api.ListPortsForOpenerRequest) (*api.ListPortsForOpenerResponse, error) {
	openerID := in.OpenerId

	result := []*api.UserAndPort{}

	identityProvider, err := component.CreateIdentityProvider()

	if err != nil {
		return &api.ListPortsForOpenerResponse{}, err
	}

	identities, err := identityProvider.ListIdentities()

	if err != nil {
		return &api.ListPortsForOpenerResponse{}, err
	}

	users := map[string]*identity.IdentityData{}

	for _, identity := range identities {
		users[identity.ID] = identity
	}

	dataStorage := component.CreateDataStorage()

	keys, err := dataStorage.GetKeys(component.USER_TO_OPENER_PORTS, "*/"+openerID+"/*")

	if err != nil {
		return &api.ListPortsForOpenerResponse{}, err
	}

	for _, key := range keys {
		value, err := dataStorage.GetFullKey(key)

		if err != nil {
			return &api.ListPortsForOpenerResponse{}, err
		}

		fmt.Println(key)

		tokens := strings.Split(key, "/")
		userID := tokens[1]
		port := tokens[3]

		user, ok := users[userID]

		if ok == false {
			log.Println("No such user")
			continue
			//return &api.ListPortsForOpenerResponse{}, errors.New("No such user")
		}

		email := user.Email
		phone := user.Phone

		userAndPort := &api.UserAndPort{
			UserId:    userID,
			Email:     email,
			Phone:     phone,
			Port:      port,
			Protocols: value,
		}

		result = append(result, userAndPort)
	}

	return &api.ListPortsForOpenerResponse{
		Result: result,
	}, nil
}

func (s *GrpcServer) ListActiveIpsForUser(ctx context.Context, in *api.ListActiveIpsForUserRequest) (*api.ListActiveIpsForUserResponse, error) {
	userID := in.UserId
	local := in.Local

	localBool := false

	if local == "true" {
		localBool = true
	}

	result, err := identityutils.GetActiveIpsForIdentityID(userID, localBool)

	if err != nil {
		return &api.ListActiveIpsForUserResponse{}, err
	}

	return &api.ListActiveIpsForUserResponse{
		Result: result,
	}, nil
}

func (s *GrpcServer) AddServiceToUser(ctx context.Context, in *api.AddServiceToUserRequest) (*api.AddServiceToUserResponse, error) {
	userID := in.UserId
	service := in.Service

	dataStorage := component.CreateDataStorage()

	err := dataStorage.SetKey(component.USER_TO_SERVICE, userID+"/"+service, service, 0)

	if err != nil {
		return &api.AddServiceToUserResponse{}, err
	}

	err = dataStorage.SetKey(component.SERVICE_TO_USER, service+"/"+userID, userID, 0)

	if err != nil {
		return &api.AddServiceToUserResponse{}, err
	}

	return &api.AddServiceToUserResponse{}, nil
}

func ListServicesForUserInternal(userID string) ([]string, error) {
	dataStorage := component.CreateDataStorage()

	keys, err := dataStorage.GetKeys(component.USER_TO_SERVICE, userID+"/*")

	if err != nil {
		return nil, err
	}

	services := []string{}

	for _, key := range keys {
		tokens := strings.Split(key, "/")
		services = append(services, tokens[2])
	}

	return services, nil
}

func (s *GrpcServer) ListServicesForUser(ctx context.Context, in *api.ListServicesForUserRequest) (*api.ListServicesForUserResponse, error) {
	userID := in.UserId

	services, err := ListServicesForUserInternal(userID)

	if err != nil {
		return &api.ListServicesForUserResponse{}, err
	}

	return &api.ListServicesForUserResponse{
		Services: services,
	}, nil
}

func (s *GrpcServer) DelServiceToUser(ctx context.Context, in *api.DelServiceToUserRequest) (*api.DelServiceToUserResponse, error) {
	userID := in.UserId
	service := in.Service

	dataStorage := component.CreateDataStorage()

	_, err := dataStorage.DelKey(component.USER_TO_SERVICE, userID+"/"+service)

	if err != nil {
		return &api.DelServiceToUserResponse{}, err
	}

	_, err = dataStorage.DelKey(component.SERVICE_TO_USER, service+"/"+userID)

	if err != nil {
		return &api.DelServiceToUserResponse{}, err
	}

	return &api.DelServiceToUserResponse{}, nil
}
