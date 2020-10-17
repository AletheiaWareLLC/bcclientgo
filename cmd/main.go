/*
 * Copyright 2020 Aletheia Ware LLC
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
	"flag"
	"fmt"
	"github.com/AletheiaWareLLC/bcclientgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/cryptogo"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var peer = flag.String("peer", "", "BC peer")

func main() {
	// Parse command line flags
	flag.Parse()

	// Set log flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	client := bcclientgo.NewBCClient(bcgo.SplitRemoveEmpty(*peer, ",")...)

	args := flag.Args()

	if len(args) > 0 {
		switch args[0] {
		case "init":
			PrintLegalese(os.Stdout)
			node, err := client.Init(&bcgo.PrintingMiningListener{Output: os.Stdout})
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Initialized")
			if err := bcclientgo.PrintNode(os.Stdout, node); err != nil {
				log.Println(err)
				return
			}
		case "node":
			node, err := client.GetNode()
			if err != nil {
				log.Println(err)
				return
			}
			if err := bcclientgo.PrintNode(os.Stdout, node); err != nil {
				log.Println(err)
				return
			}
		case "alias":
			if len(args) > 1 {
				key, err := client.Alias(args[1])
				if err != nil {
					log.Println(err)
					return
				}
				log.Println(key)
			} else {
				log.Println("Usage: alias [alias]")
			}
		case "read":
			if len(args) > 1 {
				var blockHash, recordHash []byte
				err := client.Read(args[1], blockHash, recordHash, os.Stdout)
				if err != nil {
					log.Println(err)
					return
				}
			} else {
				log.Println("Usage: read [channel-name]")
			}
		case "read-key":
			if len(args) > 1 {
				var blockHash, recordHash []byte
				err := client.ReadKey(args[1], blockHash, recordHash, os.Stdout)
				if err != nil {
					log.Println(err)
					return
				}
			} else {
				log.Println("Usage: read-key [channel-name]")
			}
		case "read-payload":
			if len(args) > 1 {
				var blockHash, recordHash []byte
				err := client.ReadPayload(args[1], blockHash, recordHash, os.Stdout)
				if err != nil {
					log.Println(err)
					return
				}
			} else {
				log.Println("Usage: read-payload [channel-name]")
			}
		case "write":
			if len(args) > 1 {
				var acl []string
				if len(args) > 2 {
					acl = args[2:]
				}
				size, err := client.Write(args[1], acl, os.Stdin)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Wrote", bcgo.BinarySizeToString(uint64(size)))
			} else {
				log.Println("Usage: write [channel-name] [access...]")
			}
		case "mine":
			if len(args) > 2 {
				threshold, err := strconv.Atoi(args[2])
				if err != nil {
					log.Println(err)
					return
				}
				hash, err := client.Mine(args[1], uint64(threshold), &bcgo.PrintingMiningListener{Output: os.Stdout})
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Mined", base64.RawURLEncoding.EncodeToString(hash))
			} else {
				log.Println("Usage: mine [channel-name] [threshold]")
			}
		case "head":
			if len(args) > 1 {
				head, err := client.Head(args[1])
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Head:", base64.RawURLEncoding.EncodeToString(head))
			} else {
				log.Println("Usage: head [channel-name]")
			}
		case "block":
			if len(args) > 2 {
				hash, err := base64.RawURLEncoding.DecodeString(args[2])
				if err != nil {
					log.Println(err)
					return
				}
				block, err := client.Block(args[1], hash)
				if err != nil {
					log.Println(err)
					return
				}
				bcgo.PrintBlock(os.Stdout, "", hash, block)
			} else {
				log.Println("Usage: block [channel-name] [block-hash]")
			}
		case "record":
			if len(args) > 2 {
				hash, err := base64.RawURLEncoding.DecodeString(args[2])
				if err != nil {
					log.Println(err)
					return
				}
				record, err := client.Record(args[1], hash)
				if err != nil {
					log.Println(err)
					return
				}
				bcgo.PrintRecord(os.Stdout, "", hash, record)
			} else {
				log.Println("Usage: record [channel-name] [record-hash]")
			}
		case "pull":
			if len(args) > 1 {
				if err := client.Pull(args[1]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Channel pulled")
			} else {
				log.Println("Usage: pull [channel-name]")
			}
		case "push":
			if len(args) > 1 {
				if err := client.Push(args[1]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Channel pushed")
			} else {
				log.Println("Usage: push [channel-name]")
			}
		case "cache":
			rootDir, err := client.GetRoot()
			if err != nil {
				log.Println(err)
			}
			dir, err := bcgo.GetCacheDirectory(rootDir)
			if err != nil {
				log.Println(err)
				return
			}
			dir, err = filepath.Abs(dir)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Cache:", dir)
		case "purge":
			if err := client.Purge(); err != nil {
				log.Println(err)
				return
			}
			log.Println("Cache purged")
		case "keystore":
			rootDir, err := client.GetRoot()
			if err != nil {
				log.Println(err)
			}
			keystore, err := bcgo.GetKeyDirectory(rootDir)
			if err != nil {
				log.Println(err)
				return
			}
			keystore, err = filepath.Abs(keystore)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("KeyStore:", keystore)
		case "peers":
			peers, err := client.GetPeers()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Peers:", strings.Join(peers, ", "))
		case "add-peer":
			if len(args) > 1 {
				rootDir, err := client.GetRoot()
				if err != nil {
					log.Println(err)
				}
				if err := bcgo.AddPeer(rootDir, args[1]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Peer added")
			} else {
				log.Println("Usage: add-peer [peer]")
			}
		case "import-keys":
			if len(args) > 2 {
				p := bcgo.GetBCWebsite()
				if *peer != "" {
					ps := bcgo.SplitRemoveEmpty(*peer, ",")
					if len(ps) > 0 {
						p = ps[0]
					}
				}
				if err := client.ImportKeys(p, args[1], args[2]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Keys imported")
			} else {
				log.Println("Usage: import-keys [alias] [access-code]")
			}
		case "export-keys":
			if len(args) > 1 {
				p := bcgo.GetBCWebsite()
				if *peer != "" {
					ps := bcgo.SplitRemoveEmpty(*peer, ",")
					if len(ps) > 0 {
						p = ps[0]
					}
				}
				// Get Password
				password, err := cryptogo.GetPassword()
				if err != nil {
					log.Println(err)
					return
				}
				accessCode, err := client.ExportKeys(p, args[1], password)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Keys exported")
				log.Println("Access Code:", accessCode)
			} else {
				log.Println("Usage: export-keys [alias]")
			}
		case "random":
			random, err := cryptogo.GenerateRandomKey()
			if err != nil {
				log.Println(err)
				return
			}
			log.Println(random)
		default:
			log.Println("Cannot handle", args[0])
		}
	} else {
		PrintUsage(os.Stdout)
	}
}

func PrintUsage(output io.Writer) {
	fmt.Fprintln(output, "BC Usage:")
	fmt.Fprintf(output, "\t%s - display usage\n", os.Args[0])
	fmt.Fprintf(output, "\t%s init - initializes environment, generates key pair, and registers alias\n", os.Args[0])
	fmt.Fprintln(output)
	fmt.Fprintf(output, "\t%s node - display registered alias and public key\n", os.Args[0])
	fmt.Fprintf(output, "\t%s alias [alias] - display public key for given alias\n", os.Args[0])
	fmt.Fprintln(output)
	// TODO fmt.Fprintf(output, "\t%s keys - display all available keys\n", os.Args[0])
	fmt.Fprintf(output, "\t%s import-keys [alias] [access-code] - imports the alias and keypair from BC server\n", os.Args[0])
	fmt.Fprintf(output, "\t%s export-keys [alias] - generates a new access code and exports the alias and keypair to BC server\n", os.Args[0])
	fmt.Fprintln(output)
	fmt.Fprintf(output, "\t%s push [channel] - pushes the channel to peers\n", os.Args[0])
	fmt.Fprintf(output, "\t%s pull [channel] - pulls the channel from peers\n", os.Args[0])
	fmt.Fprintf(output, "\t%s head [channel] - display head of given channel\n", os.Args[0])
	fmt.Fprintf(output, "\t%s block [channel] [block-hash] - display block with given hash\n", os.Args[0])
	fmt.Fprintf(output, "\t%s record [channel] [record-hash] - display record with given hash\n", os.Args[0])
	fmt.Fprintln(output)
	fmt.Fprintf(output, "\t%s read [channel] [block-hash] [record-hash]- reads entries the given channel and writes to stdout\n", os.Args[0])
	fmt.Fprintf(output, "\t%s read-key [channel] [block-hash] [record-hash]- reads keys the given channel and writes to stdout\n", os.Args[0])
	fmt.Fprintf(output, "\t%s read-payload [channel] [block-hash] [record-hash]- reads payloads the given channel and writes to stdout\n", os.Args[0])
	fmt.Fprintf(output, "\t%s write [channel] [access...] - reads data from stdin and writes it to cache for the given channel and grants access to the given aliases\n", os.Args[0])
	fmt.Fprintf(output, "\t%s mine [channel] [threshold] - mines the given channel to the given threshold\n", os.Args[0])
	fmt.Fprintln(output)
	fmt.Fprintf(output, "\t%s peers - display list of peers\n", os.Args[0])
	fmt.Fprintf(output, "\t%s add-peer [peer] - adds the given peer to the list of peers\n", os.Args[0])
	fmt.Fprintf(output, "\t%s keystore - display location of keystore\n", os.Args[0])
	fmt.Fprintf(output, "\t%s cache - display location of cache\n", os.Args[0])
	fmt.Fprintf(output, "\t%s purge - deletes contents of cache\n", os.Args[0])
	fmt.Fprintln(output)
	fmt.Fprintf(output, "\t%s random - generate a random number\n", os.Args[0])
}

func PrintLegalese(output io.Writer) {
	fmt.Fprintln(output, "BC Legalese:")
	fmt.Fprintln(output, "BC is made available by Aletheia Ware LLC [https://aletheiaware.com] under the Terms of Service [https://aletheiaware.com/terms-of-service.html] and Privacy Policy [https://aletheiaware.com/privacy-policy.html].")
	fmt.Fprintln(output, "By continuing to use this software you agree to the Terms of Service, and Privacy Policy.")
}
