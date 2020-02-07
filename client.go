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
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
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

type Client struct {
	Root    string
	Peers   []string
	Cache   bcgo.Cache
	Network bcgo.Network
}

func (c *Client) Init(listener bcgo.MiningListener) (*bcgo.Node, error) {
	// Create Node
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return nil, err
	}

	// Register Alias
	if err := aliasgo.Register(node, listener); err != nil {
		return nil, err
	}

	return node, nil
}

func (c *Client) Alias(alias string) (string, error) {
	// Open Alias Channel
	aliases := aliasgo.OpenAliasChannel()
	if err := aliases.LoadCachedHead(c.Cache); err != nil {
		log.Println(err)
	}
	if err := aliases.Pull(c.Cache, c.Network); err != nil {
		log.Println(err)
	}
	// Get Public Key for Alias
	publicKey, err := aliasgo.GetPublicKey(aliases, c.Cache, c.Network, alias)
	if err != nil {
		return "", err
	}
	publicKeyBytes, err := cryptogo.RSAPublicKeyToPKIXBytes(publicKey)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(publicKeyBytes), nil
}

func (c *Client) Head(channel string) ([]byte, error) {
	ch := &bcgo.Channel{
		Name: channel,
	}
	if err := ch.LoadHead(c.Cache, c.Network); err != nil {
		return nil, err
	}
	return ch.Head, nil
}

func (c *Client) Block(channel string, hash []byte) (*bcgo.Block, error) {
	block, err := bcgo.GetBlock(channel, c.Cache, c.Network, hash)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (c *Client) Record(channel string, hash []byte) (*bcgo.Record, error) {
	block, err := bcgo.GetBlockContainingRecord(channel, c.Cache, c.Network, hash)
	if err != nil {
		return nil, err
	}
	for _, entry := range block.Entry {
		if bytes.Equal(entry.RecordHash, hash) {
			return entry.Record, nil
		}
	}
	return nil, errors.New("Could not get block containing record")
}

func (c *Client) Read(channel string, blockHash, recordHash []byte, output io.Writer) error {
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(c.Cache, c.Network); err != nil {
		log.Println(err)
	}

	if blockHash == nil {
		blockHash = ch.Head
	}

	return bcgo.Read(channel, blockHash, nil, c.Cache, c.Network, node.Alias, node.Key, recordHash, func(entry *bcgo.BlockEntry, key, payload []byte) error {
		bcgo.PrintBlockEntry(output, "", entry)
		return nil
	})
}

func (c *Client) ReadKey(channel string, blockHash, recordHash []byte, output io.Writer) error {
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(c.Cache, c.Network); err != nil {
		log.Println(err)
	}

	if blockHash == nil {
		blockHash = ch.Head
	}

	return bcgo.ReadKey(channel, blockHash, nil, c.Cache, c.Network, node.Alias, node.Key, recordHash, func(key []byte) error {
		output.Write(key)
		return nil
	})
}

func (c *Client) ReadPayload(channel string, blockHash, recordHash []byte, output io.Writer) error {
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(c.Cache, c.Network); err != nil {
		log.Println(err)
	}

	if blockHash == nil {
		blockHash = ch.Head
	}

	return bcgo.Read(channel, blockHash, nil, c.Cache, c.Network, node.Alias, node.Key, recordHash, func(entry *bcgo.BlockEntry, key, payload []byte) error {
		output.Write(payload)
		return nil
	})
}

func (c *Client) Write(channel string, accesses []string, input io.Reader) (int, error) {
	var acl map[string]*rsa.PublicKey

	if len(accesses) > 0 {
		// Open Alias Channel
		aliases := aliasgo.OpenAliasChannel()
		if err := aliases.LoadCachedHead(c.Cache); err != nil {
			log.Println(err)
		}
		if err := aliases.Pull(c.Cache, c.Network); err != nil {
			log.Println(err)
		}
		acl = aliasgo.GetPublicKeys(aliases, c.Cache, c.Network, accesses)
	}

	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return 0, err
	}

	size, err := bcgo.CreateRecords(node.Alias, node.Key, acl, nil, input, func(key []byte, record *bcgo.Record) error {
		_, err := bcgo.WriteRecord(channel, c.Cache, record)
		return err
	})
	if err != nil {
		return 0, err
	}

	return size, nil
}

func (c *Client) Mine(channel string, threshold uint64, listener bcgo.MiningListener) ([]byte, error) {
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return nil, err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(c.Cache, c.Network); err != nil {
		log.Println(err)
	}

	hash, _, err := node.Mine(ch, threshold, listener)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func (c *Client) Pull(channel string) error {
	ch := &bcgo.Channel{
		Name: channel,
	}
	return ch.Pull(c.Cache, c.Network)
}

func (c *Client) Push(channel string) error {
	ch := &bcgo.Channel{
		Name: channel,
	}
	if err := ch.LoadHead(c.Cache, nil); err != nil {
		return err
	}
	return ch.Push(c.Cache, c.Network)
}

func (c *Client) Purge() error {
	// Get cache directory
	dir, err := bcgo.GetCacheDirectory(c.Root)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (c *Client) ImportKeys(peer, alias, accessCode string) error {
	// Get KeyStore
	keystore, err := bcgo.GetKeyDirectory(c.Root)
	if err != nil {
		return err
	}
	return cryptogo.ImportKeys(peer, keystore, alias, accessCode)
}

func (c *Client) ExportKeys(peer, alias string) (string, error) {
	// Get KeyStore
	keystore, err := bcgo.GetKeyDirectory(c.Root)
	if err != nil {
		return "", err
	}
	// Get Password
	password, err := cryptogo.GetPassword()
	if err != nil {
		return "", err
	}
	return cryptogo.ExportKeys(peer, keystore, alias, password)
}

func (c *Client) Handle(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "init":
			PrintLegalese(os.Stdout)
			node, err := c.Init(&bcgo.PrintingMiningListener{Output: os.Stdout})
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Initialized")
			if err := PrintNode(os.Stdout, node); err != nil {
				log.Println(err)
				return
			}
		case "node":
			node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
			if err != nil {
				log.Println(err)
				return
			}
			if err := PrintNode(os.Stdout, node); err != nil {
				log.Println(err)
				return
			}
		case "alias":
			if len(args) > 1 {
				key, err := c.Alias(args[1])
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
				err := c.Read(args[1], blockHash, recordHash, os.Stdout)
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
				err := c.ReadKey(args[1], blockHash, recordHash, os.Stdout)
				if err != nil {
					log.Println(err)
					return
				}
			} else {
				log.Println("Usage: read [channel-name]")
			}
		case "read-payload":
			if len(args) > 1 {
				var blockHash, recordHash []byte
				err := c.ReadPayload(args[1], blockHash, recordHash, os.Stdout)
				if err != nil {
					log.Println(err)
					return
				}
			} else {
				log.Println("Usage: read [channel-name]")
			}
		case "write":
			if len(args) > 1 {
				var acl []string
				if len(args) > 2 {
					acl = args[2:]
				}
				size, err := c.Write(args[1], acl, os.Stdin)
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
				hash, err := c.Mine(args[1], uint64(threshold), &bcgo.PrintingMiningListener{Output: os.Stdout})
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
				head, err := c.Head(args[1])
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
				block, err := c.Block(args[1], hash)
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
				record, err := c.Record(args[1], hash)
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
				if err := c.Pull(args[1]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Channel pulled")
			} else {
				log.Println("Usage: pull [channel-name]")
			}
		case "push":
			if len(args) > 1 {
				if err := c.Push(args[1]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Channel pushed")
			} else {
				log.Println("Usage: push [channel-name]")
			}
		case "cache":
			dir, err := bcgo.GetCacheDirectory(c.Root)
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
			if err := c.Purge(); err != nil {
				log.Println(err)
				return
			}
			log.Println("Cache purged")
		case "keystore":
			keystore, err := bcgo.GetKeyDirectory(c.Root)
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
			log.Println("Peers:", strings.Join(c.Peers, ", "))
		case "add-peer":
			if len(args) > 1 {
				if err := bcgo.AddPeer(c.Root, args[1]); err != nil {
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
				if err := c.ImportKeys(p, args[1], args[2]); err != nil {
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
				accessCode, err := c.ExportKeys(p, args[1])
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

func PrintNode(output io.Writer, node *bcgo.Node) error {
	fmt.Fprintln(output, node.Alias)
	publicKeyBytes, err := cryptogo.RSAPublicKeyToPKIXBytes(&node.Key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, base64.RawURLEncoding.EncodeToString(publicKeyBytes))
	return nil
}

func main() {
	// Parse command line flags
	flag.Parse()

	// Set log flags
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load config files (if any)
	err := bcgo.LoadConfig()
	if err != nil {
		log.Fatal("Could not load config:", err)
	}

	// Get root directory
	rootDir, err := bcgo.GetRootDirectory()
	if err != nil {
		log.Fatal("Could not get root directory:", err)
	}

	// Get cache directory
	cacheDir, err := bcgo.GetCacheDirectory(rootDir)
	if err != nil {
		log.Fatal("Could not get cache directory:", err)
	}

	// Create file cache
	cache, err := bcgo.NewFileCache(cacheDir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	var peers []string
	if *peer == "" {
		// Get peers
		peers, err = bcgo.GetPeers(rootDir)
		if err != nil {
			log.Fatal("Could not get network peers:", err)
		}
		if len(peers) == 0 {
			peers = append(peers, bcgo.GetBCHost())
		}
	} else {
		peers = bcgo.SplitRemoveEmpty(*peer, ",")
	}

	// Create network of peers
	network := &bcgo.TcpNetwork{Peers: peers}

	client := &Client{
		Root:    rootDir,
		Peers:   peers,
		Cache:   cache,
		Network: network,
	}

	client.Handle(flag.Args())
}
