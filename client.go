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
	"encoding/base64"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"log"
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
				log.Println("Usage: alias [alias]")
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
				log.Println("Usage: block [channel-name] [block-hash]")
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
				log.Println("Usage: head [channel-name]")
			}
		case "init":
			if err := bcgo.AddPeer(bcgo.GetBCHost()); err != nil {
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
			alias, err := aliasgo.RegisterAlias(aliases, bcgo.GetBCWebsite(), node.Alias, node.Key)
			if err != nil {
				// TODO if alias can't be registered with server, mine locally
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
				block, err := c.GetRemoteBlock(&bcgo.Reference{
					ChannelName: c.Name,
					RecordHash:  hash,
				})
				if err != nil {
					log.Println(err)
					return
				}
				bcgo.PrintBlock(hash, block)
			} else {
				log.Println("Usage: record [channel-name] [record-hash]")
			}
		case "sync":
			if len(os.Args) > 2 {
				channel, err := bcgo.OpenChannel(os.Args[2])
				if err != nil {
					log.Println(err)
					return
				}
				if err := channel.Sync(); err != nil {
					log.Println(err)
					return
				}
				log.Println("Channel synced")
			} else {
				log.Println("Usage: sync [channel-name]")
			}
		case "cast":
			if len(os.Args) > 2 {
				channel, err := bcgo.OpenChannel(os.Args[2])
				if err != nil {
					log.Println(err)
					return
				}
				if err := channel.Cast(channel.HeadHash, channel.HeadBlock); err != nil {
					log.Println(err)
					return
				}
				log.Println("Head casted")
				// TODO if peer doesn't have entire chain, cast it
			} else {
				log.Println("Usage: cast [channel-name]")
			}
		case "purge":
			cache, err := bcgo.GetCache()
			if err != nil {
				log.Println(err)
				return
			}
			if err := os.RemoveAll(cache); err != nil {
				log.Println(err)
				return
			}
			log.Println("Cache purged")
		case "import-keys":
			if len(os.Args) >= 4 {
				alias := os.Args[2]
				accessCode := os.Args[3]
				// Get KeyStore
				keystore, err := bcgo.GetKeyStore()
				if err != nil {
					log.Println(err)
					return
				}
				if err := bcgo.ImportKeys(bcgo.GetBCWebsite(), keystore, alias, accessCode); err != nil {
					log.Println(err)
					return
				}
			} else {
				log.Println("import-keys [alias] [access-code]")
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
				accessCode, err := bcgo.ExportKeys(bcgo.GetBCWebsite(), keystore, alias, password)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Access Code:", accessCode)
			} else {
				log.Println("export-keys [alias]")
			}
		case "keystore":
			keystore, err := bcgo.GetKeyStore()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("KeyStore:", keystore)
		case "peers":
			peers, err := bcgo.GetPeers()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Peers:", peers)
		case "add-peer":
			if len(os.Args) > 2 {
				peer := os.Args[2]
				err := bcgo.AddPeer(peer)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Added Peer:", peer)
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
			log.Println("Cannot handle", os.Args[1])
		}
	} else {
		log.Println("BC Usage:")
		log.Println("\tbc")
		log.Println("\tbc init - initializes environment, generates key pair, and registers alias")

		log.Println("\tbc sync [channel] - synchronizes cache for the given channel")
		log.Println("\tbc head [channel] - display head of given channel")
		log.Println("\tbc block [channel] [hash] - display block with given hash on given channel")
		log.Println("\tbc record [channel] [hash] - display record with given hash on given channel")

		log.Println("\tbc alias [alias] - display public key for alias")
		log.Println("\tbc node - display registered alias and public key")

		log.Println("\tbc import-keys [alias] [access-code] - imports the alias and keypair from BC server")
		log.Println("\tbc export-keys [alias] - generates a new access code and exports the alias and keypair to BC server")

		log.Println("\tbc peers - display list of peers")
		log.Println("\tbc add-peer [host] - adds the given host to the list of peers")
		log.Println("\tbc keystore - display location of keystore")
		log.Println("\tbc cache - display location of cache")
		log.Println("\tbc purge - deletes cache")

		log.Println("\tbc random - generate a random number")
	}
}
