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

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	api "github.com/netclave/apis/identity-provider/api"

	"google.golang.org/grpc"
)

func listOpeners(conn *grpc.ClientConn) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListOpenersRequest{}

	response, err := client.ListOpeners(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, opener := range response.Openers {
		log.Println(opener.Name + " ---- " + opener.OpenerId)
	}
}

func putUser(conn *grpc.ClientConn, email, phone, userID, userType string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user := &api.User{
		Email:  email,
		Phone:  phone,
		UserId: userID,
		Type:   userType,
	}

	in := &api.PutUserRequest{
		User: user,
	}

	_, err := client.PutUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}
}

func delUser(conn *grpc.ClientConn, userID string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.DelUserRequest{
		UserId: userID,
	}

	_, err := client.DelUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}
}

func getUser(conn *grpc.ClientConn, userID string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.GetUserRequest{
		UserId: userID,
	}

	response, err := client.GetUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	log.Println("Email: " + response.User.Email)
	log.Println("Phone: " + response.User.Phone)
	log.Println("Id: " + response.User.UserId)
	log.Println("Type: " + response.User.Type)
}

func listUsers(conn *grpc.ClientConn) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListUsersRequest{}

	response, err := client.ListUsers(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, user := range response.Users {
		log.Println(user.UserId + " ---- " + user.Email + " ----- " + user.Phone)
	}
}

func addPortForUserAndOpener(conn *grpc.ClientConn, userID, openerID, port, protocols string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.AddPortForUserAndOpenerRequest{
		UserId:    userID,
		OpenerId:  openerID,
		Port:      port,
		Protocols: protocols,
	}

	_, err := client.AddPortForUserAndOpener(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}
}

func delPortForUserAndOpener(conn *grpc.ClientConn, userID, openerID, port string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.DelPortForUserAndOpenerRequest{
		UserId:   userID,
		OpenerId: openerID,
		Port:     port,
	}

	_, err := client.DelPortForUserAndOpener(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}
}

func listPortsForUser(conn *grpc.ClientConn, userID string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListPortsForUserRequest{
		UserId: userID,
	}

	response, err := client.ListPortsForUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, openerAndPort := range response.Result {
		fmt.Println(openerAndPort.OpenerName + " " + openerAndPort.OpenerId + " " + openerAndPort.Port + " " + openerAndPort.Protocols)
	}
}

func listPortsForOpener(conn *grpc.ClientConn, openerID string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListPortsForOpenerRequest{
		OpenerId: openerID,
	}

	response, err := client.ListPortsForOpener(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, userAndPort := range response.Result {
		fmt.Println(userAndPort.UserId + " " + userAndPort.Email + " " + userAndPort.Phone + " " + userAndPort.Port + " " + userAndPort.Protocols)
	}
}

func listActiveIpsForUser(conn *grpc.ClientConn, userID, local string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListActiveIpsForUserRequest{
		UserId: userID,
		Local:  local,
	}

	response, err := client.ListActiveIpsForUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, ip := range response.Result {
		fmt.Println(ip)
	}
}

func addServiceToUser(conn *grpc.ClientConn, userID, service string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.AddServiceToUserRequest{
		UserId:  userID,
		Service: service,
	}

	_, err := client.AddServiceToUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}
}

func listServicesForUser(conn *grpc.ClientConn, userID string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.ListServicesForUserRequest{
		UserId: userID,
	}

	response, err := client.ListServicesForUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}

	for _, service := range response.Services {
		fmt.Println(service)
	}
}

func delServiceToUser(conn *grpc.ClientConn, userID, service string) {
	client := api.NewIdentityProviderAdminClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	in := &api.DelServiceToUserRequest{
		UserId:  userID,
		Service: service,
	}

	_, err := client.DelServiceToUser(ctx, in)

	if err != nil {
		log.Println(err.Error())
		return
	}
}

func main() {
	if len(os.Args) == 1 || len(os.Args) == 2 {
		log.Println("client url listOpeners")
		log.Println("client url putUser email phone userID type")
		log.Println("client url delUser userID")
		log.Println("client url getUser userID")
		log.Println("client url listUsers")
		log.Println("client url addPortForUserAndOpener userID openerID port protocols")
		log.Println("client url delPortForUserAndOpener userID openerID port")
		log.Println("client url listPortsForUser userID")
		log.Println("client url listPortsForOpener openerID")
		log.Println("client url listActiveIpsForUser userID local")
		log.Println("client url addServiceToUser userID service")
		log.Println("client url listServicesForUser userID")
		log.Println("client url delServiceToUser userID service")

		return
	}

	var conn *grpc.ClientConn

	conn, err := grpc.Dial(os.Args[1], grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	defer conn.Close()

	switch os.Args[2] {
	case "listOpeners":
		{
			listOpeners(conn)
		}
	case "putUser":
		{
			putUser(conn, os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		}
	case "delUser":
		{
			delUser(conn, os.Args[3])
		}
	case "getUser":
		{
			getUser(conn, os.Args[3])
		}
	case "listUsers":
		{
			listUsers(conn)
		}
	case "addPortForUserAndOpener":
		{
			addPortForUserAndOpener(conn, os.Args[3], os.Args[4], os.Args[5], os.Args[6])
		}
	case "delPortForUserAndOpener":
		{
			delPortForUserAndOpener(conn, os.Args[3], os.Args[4], os.Args[5])
		}
	case "listPortsForUser":
		{
			listPortsForUser(conn, os.Args[3])
		}
	case "listPortsForOpener":
		{
			listPortsForOpener(conn, os.Args[3])
		}
	case "listActiveIpsForUser":
		{
			listActiveIpsForUser(conn, os.Args[3], os.Args[4])
		}
	case "addServiceToUser":
		{
			addServiceToUser(conn, os.Args[3], os.Args[4])
		}
	case "listServicesForUser":
		{
			listServicesForUser(conn, os.Args[3])
		}
	case "delServiceToUser":
		{
			delServiceToUser(conn, os.Args[3], os.Args[4])
		}
	default:
		{
			log.Println("You have to choose program")
		}
	}
}
