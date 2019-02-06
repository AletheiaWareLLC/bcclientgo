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
			node, err := bcgo.GetNode()
			if err != nil {
				log.Println(err)
				return
			}
			publicKey, err := bcgo.RSAPublicKeyToBytes(&node.Key.PublicKey)
			if err != nil {
				log.Println(err)
				return
			}
			// Open Alias Channel
			aliases, err := aliasgo.OpenAliasChannel()
			if err != nil {
				log.Println(err)
				return
			}
			alias, err := aliasgo.GetAlias(aliases, &node.Key.PublicKey)
			if err != nil {
				log.Println(err)
				a := &aliasgo.Alias{
					Alias:        node.Alias,
					PublicKey:    publicKey,
					PublicFormat: bcgo.PublicKeyFormat_PKIX,
				}
				data, err := proto.Marshal(a)
				if err != nil {
					log.Println(err)
					return
				}

				signatureAlgorithm := bcgo.SignatureAlgorithm_SHA512WITHRSA_PSS

				signature, err := bcgo.CreateSignature(node.Key, bcgo.Hash(data), signatureAlgorithm)
				if err != nil {
					log.Println(err)
					return
				}

				response, err := http.PostForm(bcgo.BC_WEBSITE+"/alias", url.Values{
					"alias":              {node.Alias},
					"publicKey":          {base64.RawURLEncoding.EncodeToString(publicKey)},
					"publicKeyFormat":    {"PKIX"},
					"signature":          {base64.RawURLEncoding.EncodeToString(signature)},
					"signatureAlgorithm": {signatureAlgorithm.String()},
				})
				if err != nil {
					log.Println(err)
					return
				}
				log.Println(response)
				if err := aliases.Sync(); err != nil {
					log.Println(err)
					return
				}
				alias, err = aliasgo.GetAlias(aliases, &node.Key.PublicKey)
				if err != nil {
					log.Println(err)
					return
				}
			}
			log.Println("Registered as", alias)
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
				block, err := bcgo.ReadBlockFile(c.Cache, hash)
				if err != nil {
					log.Println(err)
					block, err = bcgo.GetBlock(&bcgo.Reference{
						ChannelName: channel,
						BlockHash:   hash,
					})
					if err != nil {
						log.Println(err)
						return
					}
					err = bcgo.WriteBlockFile(c.Cache, hash, block)
					if err != nil {
						log.Println(err)
						return
					}
				}

				bcgo.PrintBlock(hash, block)
			} else {
				log.Println("Usage: block <channel-name> <block-hash>")
			}
		case "head":
			if len(os.Args) > 2 {
				reference, err := bcgo.GetHead(os.Args[2])
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Timestamp:", reference.Timestamp)
				log.Println("ChannelName:", reference.ChannelName)
				log.Println("BlockHash:", base64.RawURLEncoding.EncodeToString(reference.BlockHash))
			} else {
				log.Println("Usage: head <channel-name>")
			}
		case "node":
			node, err := bcgo.GetNode()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(node.Alias)
		case "record":
			if len(os.Args) > 3 {
				channel := os.Args[2]
				hash, err := base64.RawURLEncoding.DecodeString(os.Args[3])
				if err != nil {
					log.Println(err)
					return
				}
				block, err := bcgo.GetBlock(&bcgo.Reference{
					ChannelName: channel,
					RecordHash:  hash,
				})
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
				encryptedData, err := bcgo.EncryptAESGCM(accessCode, data)
				if err != nil {
					log.Println(err)
					return
				}
				publicKey, err := bcgo.RSAPublicKeyToBytes(&privateKey.PublicKey)
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
					"publicKey":        {base64.RawURLEncoding.EncodeToString(publicKey)},
					"publicKeyFormat":  {"PKIX"},
					"privateKey":       {base64.RawURLEncoding.EncodeToString(encryptedData)},
					"privateKeyFormat": {"PKCS8"},
					"password":         {base64.RawURLEncoding.EncodeToString(encryptedPassword)},
				})
				if err != nil {
					log.Println(err)
					return
				}
				log.Println(response)
			} else {
				log.Println("export-keys <alias>")
			}
		}
	} else {
		response, err := http.Get(bcgo.BC_WEBSITE)
		if err != nil {
			log.Println(err)
			return
		}
		log.Println(response)
	}
}
