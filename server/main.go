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
	"fmt"
	"log"
	"math"
	"net"
	"net/http"

	api "github.com/netclave/apis/identity-provider/api"
	"github.com/netclave/identity-provider/component"
	"github.com/netclave/identity-provider/config"
	"github.com/netclave/identity-provider/handlers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func startGRPCServer(address string) error {
	// create a listener on TCP port
	lis, err := net.Listen("tcp", address)

	if err != nil {
		log.Println(err.Error())
		return err
	}

	// create a server instance
	s := handlers.GrpcServer{}

	ServerMaxReceiveMessageSize := math.MaxInt32

	opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(ServerMaxReceiveMessageSize)}
	// create a gRPC server object
	grpcServer := grpc.NewServer(opts...)

	// attach the Ping service to the server
	api.RegisterIdentityProviderAdminServer(grpcServer, &s)

	// start the server
	log.Printf("starting HTTP/2 gRPC server on %s", address)
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %s", err)
	}

	return nil
}

func main() {
	err := component.LoadComponent()
	if err != nil {
		log.Println(err.Error())
		return
	}

	go func() {
		http.HandleFunc("/listOpenerIPs", handlers.ListOpenerIPs)
		http.HandleFunc("/getWalletsAndServices", handlers.GetWalletsAndServices)
		http.HandleFunc("/getActiveTokens", handlers.GetActiveTokens)

		if err := http.ListenAndServe(config.ListenHTTPAddressForOpeners, nil); err != nil {
			panic(err)
		}
	}()

	go func() {
		log.Println("Starting grpc server")
		err = startGRPCServer(config.ListenGRPCAddress)
	}()

	http.HandleFunc("/listGeneratorIPs", handlers.ListGeneratorIPs)
	http.HandleFunc("/getPublicKey", handlers.GetPublicKey)
	http.HandleFunc("/registerPublicKey", handlers.RegisterPublicKey)
	http.HandleFunc("/confirmPublicKey", handlers.ConfirmPublicKey)
	http.HandleFunc("/deletePublicKey", handlers.DeletePublicKey)
	http.HandleFunc("/exchangePublicKeys", handlers.ExchangePublicKeysViaQR)
	http.HandleFunc("/saveTokens", handlers.SaveTokens)
	http.HandleFunc("/listPublicKeysForIdentificator", handlers.ListPublicKeysForIdentificator)
	http.HandleFunc("/listServicesForWallet", handlers.ListServicesForWallet)

	if err := http.ListenAndServe(config.ListenHTTPAddress, nil); err != nil {
		panic(err)
	}
}
