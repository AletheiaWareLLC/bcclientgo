/*
 * Copyright 2019 Aletheia Ware LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "alias":
			// Open Alias Channel
			aliases, err := aliasgo.OpenAliasChannel()
			if err != nil {
				log.Println(err)
				return
			}
			if len(os.Args) > 2 {
				log.Println(os.Args[2])
				publicKey, err := aliasgo.GetPublicKey(aliases, os.Args[2])
				if err != nil {
					log.Println(err)
					return
				}
				publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(publicKey)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println(base64.RawURLEncoding.EncodeToString(publicKeyBytes))
			} else {
				node, err := bcgo.GetNode()
				if err != nil {
					log.Println(err)
					return
				}
				alias, err := aliasgo.GetAlias(aliases, &node.Key.PublicKey)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Registered as", alias)
			}
		case "block":
			if len(os.Args) > 3 {
				channel := os.Args[2]
				hash, err := base64.RawURLEncoding.DecodeString(os.Args[3])
				if err != nil {
					log.Println(err)
					return
				}
				c, err := bcgo.OpenChannel(channel)
				if err != nil {
					log.Println(err)
					return
				}
				block, err := c.GetBlock(hash)
				if err != nil {
					log.Println(err)
					return
				}

				bcgo.PrintBlock(hash, block)
			} else {
				log.Println("Usage: block <channel-name> <block-hash>")
			}
		case "head":
			if len(os.Args) > 2 {
				c, err := bcgo.OpenChannel(os.Args[2])
				if err != nil {
					log.Println(err)
					return
				}
				head, err := c.GetHead()
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Head:", base64.RawURLEncoding.EncodeToString(head))
			} else {
				log.Println("Usage: head <channel-name>")
			}
		case "init":
			if err := bcgo.AddPeer(aliasgo.ALIAS, bcgo.BC_HOST); err != nil {
				log.Println(err)
				return
			}
			// Open Alias Channel
			aliases, err := aliasgo.OpenAliasChannel()
			if err != nil {
				log.Println(err)
				return
			}
			node, err := bcgo.GetNode()
			if err != nil {
				log.Println(err)
				return
			}
			alias, err := aliasgo.RegisterAlias(aliases, node.Alias, node.Key)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(alias)
			publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&node.Key.PublicKey)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(base64.RawURLEncoding.EncodeToString(publicKeyBytes))
			log.Println("Initialized")
		case "node":
			node, err := bcgo.GetNode()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(node.Alias)
			publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&node.Key.PublicKey)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(base64.RawURLEncoding.EncodeToString(publicKeyBytes))
		case "record":
			if len(os.Args) > 3 {
				channel := os.Args[2]
				c, err := bcgo.OpenChannel(channel)
				if err != nil {
					log.Println(err)
					return
				}
				hash, err := base64.RawURLEncoding.DecodeString(os.Args[3])
				if err != nil {
					log.Println(err)
					return
				}
				block, err := c.GetBlock(hash)
				if err != nil {
					log.Println(err)
					return
				}
				bcgo.PrintBlock(hash, block)
			} else {
				log.Println("Usage: record <channel-name> <record-hash>")
			}
		case "sync":
			if len(os.Args) > 2 {
				channel, err := bcgo.OpenChannel(os.Args[2])
				if err != nil {
					log.Println(err)
					return
				}
				log.Println(channel.Sync())
			} else {
				log.Println("Usage: sync <channel-name>")
			}
		case "import-keys":
			if len(os.Args) >= 4 {
				alias := os.Args[2]
				response, err := http.Get(bcgo.BC_WEBSITE + "/keys?alias=" + alias)
				if err != nil {
					log.Println(err)
					return
				}
				data, err := ioutil.ReadAll(response.Body)
				if err != nil {
					log.Println(err)
					return
				}
				keyShare := &bcgo.KeyShare{}
				if err = proto.Unmarshal(data, keyShare); err != nil {
					log.Println(err)
					return
				}
				if keyShare.Alias != alias {
					log.Println("Incorrect KeyShare Alias")
					return
				}
				// Decode Access Code
				accessCode, err := base64.RawURLEncoding.DecodeString(os.Args[3])
				if err != nil {
					log.Println(err)
					return
				}
				// Parse Public Key
				/*
					publicKey, err := bcgo.ParseRSAPublicKey(keyShare.PublicKey, keyShare.PublicFormat)
					if err != nil {
						log.Println(err)
						return
					}
				*/
				// Decrypt Private Key
				decryptedPrivateKey, err := bcgo.DecryptAESGCM(accessCode, keyShare.PrivateKey)
				if err != nil {
					log.Println(err)
					return
				}
				// Parse Private Key
				privateKey, err := bcgo.ParseRSAPrivateKey(decryptedPrivateKey, keyShare.PrivateFormat)
				if err != nil {
					log.Println(err)
					return
				}
				// Decrypt Password
				decryptedPassword, err := bcgo.DecryptAESGCM(accessCode, keyShare.Password)
				if err != nil {
					log.Println(err)
					return
				}
				// Get KeyStore
				keystore, err := bcgo.GetKeyStore()
				if err != nil {
					log.Println(err)
					return
				}
				// Write Private Key
				if err := bcgo.WriteRSAPrivateKey(privateKey, keystore, alias, decryptedPassword); err != nil {
					log.Println(err)
					return
				}
				log.Println("Keys imported")
			} else {
				log.Println("import-keys <alias> <access-code>")
			}
		case "export-keys":
			if len(os.Args) >= 3 {
				alias := os.Args[2]
				keystore, err := bcgo.GetKeyStore()
				if err != nil {
					log.Println(err)
					return
				}
				password, err := bcgo.GetPassword()
				if err != nil {
					log.Println(err)
					return
				}
				privateKey, err := bcgo.GetRSAPrivateKey(keystore, alias, password)
				if err != nil {
					log.Println(err)
					return
				}

				// Generate a random access code
				accessCode, err := bcgo.GenerateRandomKey()
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Access Code:", base64.RawURLEncoding.EncodeToString(accessCode))

				data, err := x509.MarshalPKCS8PrivateKey(privateKey)
				if err != nil {
					log.Println(err)
					return
				}
				encryptedPrivateKeyBytes, err := bcgo.EncryptAESGCM(accessCode, data)
				if err != nil {
					log.Println(err)
					return
				}
				publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&privateKey.PublicKey)
				if err != nil {
					log.Println(err)
					return
				}
				encryptedPassword, err := bcgo.EncryptAESGCM(accessCode, password)
				if err != nil {
					log.Println(err)
					return
				}
				response, err := http.PostForm(bcgo.BC_WEBSITE+"/keys", url.Values{
					"alias":            {alias},
					"publicKey":        {base64.RawURLEncoding.EncodeToString(publicKeyBytes)},
					"publicKeyFormat":  {"PKIX"},
					"privateKey":       {base64.RawURLEncoding.EncodeToString(encryptedPrivateKeyBytes)},
					"privateKeyFormat": {"PKCS8"},
					"password":         {base64.RawURLEncoding.EncodeToString(encryptedPassword)},
				})
				if err != nil {
					log.Println(err)
					return
				}
				switch response.StatusCode {
				case http.StatusOK:
					log.Println("Keys exported")
				default:
					log.Println("Export status:", response.Status)
				}
			} else {
				log.Println("export-keys <alias>")
			}
		case "keystore":
			keystore, err := bcgo.GetKeyStore()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("KeyStore:", keystore)
		case "peers":
			if len(os.Args) > 2 {
				channel := os.Args[2]
				peers, err := bcgo.GetPeers(channel)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Peers:", channel, peers)
			}
		case "add-peer":
			if len(os.Args) > 3 {
				channel := os.Args[2]
				peer := os.Args[3]
				err := bcgo.AddPeer(channel, peer)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Added Peer:", channel, peer)
			}
		case "cache":
			cache, err := bcgo.GetCache()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Cache:", cache)
		case "random":
			log.Println(bcgo.GenerateRandomKey())
		default:
			bcgo.GetAndPrintURL(bcgo.BC_WEBSITE)
		}
	} else {
		bcgo.GetAndPrintURL(bcgo.BC_WEBSITE)
	}
}
