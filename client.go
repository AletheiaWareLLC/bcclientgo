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
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/financego"
	"io"
	"log"
	"os"
	"strconv"
)

type Client struct {
	Root    string
	Cache   bcgo.Cache
	Network bcgo.Network
}

func (c *Client) Init() (*bcgo.Node, error) {
	// Add BC host to peers
	if err := bcgo.AddPeer(c.Root, bcgo.GetBCHost()); err != nil {
		return nil, err
	}

	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return nil, err
	}

	// Open Alias Channel
	aliases := aliasgo.OpenAndLoadAliasChannel(c.Cache, c.Network)
	if err := aliasgo.UniqueAlias(aliases, c.Cache, node.Network, node.Alias); err != nil {
		return nil, err
	}
	if err := aliasgo.RegisterAlias(bcgo.GetBCWebsite(), node.Alias, node.Key); err != nil {
		// TODO if alias can't be registered with server, mine locally
		log.Println("Could not register alias: ", err)
		return nil, err
	}
	return node, nil
}

func (c *Client) Alias(alias string) (string, error) {
	// Open Alias Channel
	aliases := aliasgo.OpenAndLoadAliasChannel(c.Cache, c.Network)
	// Get Public Key for Alias
	publicKey, err := aliasgo.GetPublicKey(aliases, c.Cache, c.Network, alias)
	if err != nil {
		return "", err
	}
	publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(publicKey)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(publicKeyBytes), nil
}

func (c *Client) Head(channel string) ([]byte, error) {
	ch := &bcgo.PoWChannel{
		Name: channel,
	}
	if err := bcgo.LoadHead(ch, c.Cache, c.Network); err != nil {
		return nil, err
	}
	return ch.GetHead(), nil
}

func (c *Client) Block(channel string, hash []byte) (*bcgo.Block, error) {
	block, err := bcgo.GetBlock(channel, c.Cache, c.Network, hash)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (c *Client) Record(channel string, hash []byte) (*bcgo.Record, error) {
	block, err := c.Network.GetBlock(&bcgo.Reference{
		ChannelName: channel,
		RecordHash:  hash,
	})
	if err != nil {
		return nil, err
	}
	for _, entry := range block.Entry {
		if bytes.Equal(entry.RecordHash, hash) {
			return entry.Record, nil
		}
	}
	return nil, errors.New("Could not find record in block received from network")
}

func (c *Client) Mine(channel string, threshold uint64, accesses []string, input io.Reader, listener bcgo.MiningListener) (int, []byte, error) {
	ch := &bcgo.PoWChannel{
		Name:      channel,
		Threshold: threshold,
	}

	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return 0, nil, err
	}

	acl := make(map[string]*rsa.PublicKey)
	if len(accesses) > 0 {
		// Open Alias Channel
		aliases := aliasgo.OpenAndLoadAliasChannel(c.Cache, c.Network)
		for _, a := range accesses {
			publicKey, err := aliasgo.GetPublicKey(aliases, c.Cache, node.Network, a)
			if err != nil {
				return 0, nil, err
			}
			acl[a] = publicKey
		}
	}

	size, err := bcgo.CreateRecords(node.Alias, node.Key, acl, nil, input, func(key []byte, record *bcgo.Record) error {
		_, err := bcgo.WriteRecord(ch.GetName(), c.Cache, record)
		return err
	})
	if err != nil {
		return 0, nil, err
	}

	hash, _, err := node.Mine(ch, listener)
	if err != nil {
		return 0, nil, err
	}
	return size, hash, nil
}

func (c *Client) Pull(channel string) error {
	ch := &bcgo.PoWChannel{
		Name: channel,
	}
	return bcgo.Pull(ch, c.Cache, c.Network)
}

func (c *Client) Push(channel string) error {
	ch := &bcgo.PoWChannel{
		Name: channel,
	}
	return bcgo.Push(ch, c.Cache, c.Network)
}

func (c *Client) Purge() error {
	// Get cache directory
	dir, err := bcgo.GetCacheDirectory(c.Root)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (c *Client) ImportKeys(alias, accessCode string) error {
	// Get KeyStore
	keystore, err := bcgo.GetKeyDirectory(c.Root)
	if err != nil {
		return err
	}
	return bcgo.ImportKeys(bcgo.GetBCWebsite(), keystore, alias, accessCode)
}

func (c *Client) ExportKeys(alias string) (string, error) {
	// Get KeyStore
	keystore, err := bcgo.GetKeyDirectory(c.Root)
	if err != nil {
		return "", err
	}
	// Get Password
	password, err := bcgo.GetPassword()
	if err != nil {
		return "", err
	}
	return bcgo.ExportKeys(bcgo.GetBCWebsite(), keystore, alias, password)
}

func (c *Client) Registration(callback func(*financego.Customer) error) error {
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return err
	}
	customers := financego.OpenAndLoadCustomerChannel(c.Cache, c.Network)
	return financego.GetCustomerAsync(customers, c.Cache, node.Alias, node.Key, node.Alias, callback)
}

func (c *Client) Subscription(callback func(*financego.Subscription) error) error {
	node, err := bcgo.GetNode(c.Root, c.Cache, c.Network)
	if err != nil {
		return err
	}
	subscriptions := financego.OpenAndLoadSubscriptionChannel(c.Cache, c.Network)
	return financego.GetSubscriptionAsync(subscriptions, c.Cache, node.Alias, node.Key, node.Alias, callback)
}

func (c *Client) Handle(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "init":
			node, err := c.Init()
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
		case "mine":
			if len(args) > 2 {
				threshold, err := strconv.Atoi(args[2])
				if err != nil {
					log.Println(err)
					return
				}
				var acl []string
				if len(args) > 3 {
					acl = args[3:]
				}
				size, hash, err := c.Mine(args[1], uint64(threshold), acl, os.Stdin, &bcgo.PrintingMiningListener{os.Stdout})
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Payload", bcgo.SizeToString(uint64(size)))
				log.Println("Mined", base64.RawURLEncoding.EncodeToString(hash))
			} else {
				log.Println("Usage: mine [channel-name] [threshold] [access...]")
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
			log.Println("KeyStore:", keystore)
		case "peers":
			peers, err := bcgo.GetPeers(c.Root)
			if err != nil {
				log.Println(err)
				return
			}
			log.Println("Peers:", peers)
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
				if err := c.ImportKeys(args[1], args[2]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Keys imported")
			} else {
				log.Println("Usage: import-keys [alias] [access-code]")
			}
		case "export-keys":
			if len(args) > 1 {
				accessCode, err := c.ExportKeys(args[1])
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Keys exported")
				log.Println("Access Code:", accessCode)
			} else {
				log.Println("Usage: export-keys [alias]")
			}
		case "registration":
			/* TODO add support for merchant
			merchant := ""
			if len(args) > 1 {
				merchant = args[1]
			}*/
			count := 0
			if err := c.Registration(func(c *financego.Customer) error {
				log.Println(c)
				count++
				return nil
			}); err != nil {
				log.Println(err)
				return
			}
			log.Println(count, "results")
		case "subscription":
			/* TODO add support for merchant
			merchant := ""
			if len(args) > 1 {
				merchant = args[1]
			}*/
			count := 0
			if err := c.Subscription(func(s *financego.Subscription) error {
				log.Println(s)
				count++
				return nil
			}); err != nil {
				log.Println(err)
				return
			}
			log.Println(count, "results")
		case "random":
			log.Println(bcgo.GenerateRandomKey())
		default:
			log.Println("Cannot handle", args[0])
		}
	} else {
		PrintUsage(os.Stdout)
	}
}

func PrintUsage(output io.Writer) {
	fmt.Fprintln(output, "BC Usage:")
	fmt.Fprintln(output, "\tbc - print usage")
	fmt.Fprintln(output, "\tbc init - initializes environment, generates key pair, and registers alias")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc node - print registered alias and public key")
	fmt.Fprintln(output, "\tbc alias [alias] - print public key for alias")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc import-keys [alias] [access-code] - imports the alias and keypair from BC server")
	fmt.Fprintln(output, "\tbc export-keys [alias] - generates a new access code and exports the alias and keypair to BC server")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc registration [merchant] - print registration information between this alias and the given merchant")
	fmt.Fprintln(output, "\tbc subscription [merchant] - print subscription information between this alias and the given merchant")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc push [channel] - pushes the channel to peers")
	fmt.Fprintln(output, "\tbc pull [channel] - pulles the channel from peers")
	fmt.Fprintln(output, "\tbc head [channel] - print head of given channel")
	fmt.Fprintln(output, "\tbc block [channel] [hash] - print block with given hash")
	fmt.Fprintln(output, "\tbc record [channel] [hash] - print record with given hash")
	fmt.Fprintln(output)
	// TODO split into a) write to cache, b) mine channel - fmt.Fprintln(output, "\tbc write [channel] [access...] - reads data from stdin and writes it to the given channel and grants access to the given aliases")
	fmt.Fprintln(output, "\tbc mine [channel] [threshold] [access...] - reads data from stdin and mines it to the given threshold in the blockchain with the given channel and grants access to the given aliases")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc peers - print list of peers")
	fmt.Fprintln(output, "\tbc add-peer [host] - adds the given host to the list of peers")
	fmt.Fprintln(output, "\tbc keystore - print location of keystore")
	fmt.Fprintln(output, "\tbc cache - print location of cache")
	fmt.Fprintln(output, "\tbc purge - deletes cache")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc random - generate a random number")
}

func PrintNode(output io.Writer, node *bcgo.Node) error {
	fmt.Fprintln(output, node.Alias)
	publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&node.Key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Fprintln(output, base64.RawURLEncoding.EncodeToString(publicKeyBytes))
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Get root directory
	root, err := bcgo.GetRootDirectory()
	if err != nil {
		log.Fatal("Could not get root directory:", err)
	}

	// Get cache directory
	dir, err := bcgo.GetCacheDirectory(root)
	if err != nil {
		log.Fatal("Could not get cache directory:", err)
	}

	// Create file cache
	cache, err := bcgo.NewFileCache(dir)
	if err != nil {
		log.Fatal("Could not create file cache:", err)
	}

	// Get peers
	peers, err := bcgo.GetPeers(root)
	if err != nil {
		log.Fatal("Could not get network peers:", err)
	}

	// Create network of peers
	network := &bcgo.TcpNetwork{peers}

	client := &Client{
		Root:    root,
		Cache:   cache,
		Network: network,
	}

	client.Handle(os.Args[1:])
}
