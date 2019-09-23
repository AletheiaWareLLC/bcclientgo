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
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
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

func (c *Client) Init(listener bcgo.MiningListener) (*bcgo.Node, error) {
	// Add BC host to peers
	if err := bcgo.AddPeer(c.Root, bcgo.GetBCHost()); err != nil {
		return nil, err
	}

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
	if err := bcgo.LoadHead(aliases, c.Cache, c.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(aliases, c.Cache, c.Network); err != nil {
		log.Println(err)
	}
	// Get Public Key for Alias
	publicKey, err := aliases.GetPublicKey(c.Cache, c.Network, alias)
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

func (c *Client) Write(channel string, accesses []string, input io.Reader) (int, error) {
	// Open Alias Channel
	aliases := aliasgo.OpenAliasChannel()
	if err := bcgo.LoadHead(aliases, c.Cache, c.Network); err != nil {
		log.Println(err)
	} else if err := bcgo.Pull(aliases, c.Cache, c.Network); err != nil {
		log.Println(err)
	}
	acl := aliases.GetPublicKeys(c.Cache, c.Network, accesses)

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

	ch := &bcgo.PoWChannel{
		Name:      channel,
		Threshold: threshold,
	}

	if err := bcgo.LoadHead(ch, c.Cache, c.Network); err != nil {
		log.Println(err)
	}

	hash, _, err := node.Mine(ch, listener)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func (c *Client) Pull(channel string, network bcgo.Network) error {
	ch := &bcgo.PoWChannel{
		Name: channel,
	}
	return bcgo.Pull(ch, c.Cache, network)
}

func (c *Client) Push(channel string, network bcgo.Network) error {
	ch := &bcgo.PoWChannel{
		Name: channel,
	}
	if err := bcgo.LoadHead(ch, c.Cache, nil); err != nil {
		return err
	}
	return bcgo.Push(ch, c.Cache, network)
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
	return bcgo.ImportKeys(peer, keystore, alias, accessCode)
}

func (c *Client) ExportKeys(peer, alias string) (string, error) {
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
	return bcgo.ExportKeys(peer, keystore, alias, password)
}

func (c *Client) Handle(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "init":
			PrintLegalese(os.Stdout)
			node, err := c.Init(&bcgo.PrintingMiningListener{os.Stdout})
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
		case "write":
			if len(args) > 2 {
				var acl []string
				if len(args) > 2 {
					acl = args[2:]
				}
				size, err := c.Write(args[1], acl, os.Stdin)
				if err != nil {
					log.Println(err)
					return
				}
				log.Println("Wrote", bcgo.SizeToString(uint64(size)))
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
				hash, err := c.Mine(args[1], uint64(threshold), &bcgo.PrintingMiningListener{os.Stdout})
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
				network := c.Network
				if len(args) > 2 {
					network = &bcgo.TcpNetwork{args[2:]}
				}
				if err := c.Pull(args[1], network); err != nil {
					log.Println(err)
					return
				}
				log.Println("Channel pulled")
			} else {
				log.Println("Usage: pull [channel-name]")
			}
		case "push":
			if len(args) > 1 {
				network := c.Network
				if len(args) > 2 {
					network = &bcgo.TcpNetwork{args[2:]}
				}
				if err := c.Push(args[1], network); err != nil {
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
				peer := bcgo.GetBCWebsite()
				if len(args) > 3 {
					peer = args[3]
				}
				if err := c.ImportKeys(peer, args[1], args[2]); err != nil {
					log.Println(err)
					return
				}
				log.Println("Keys imported")
			} else {
				log.Println("Usage: import-keys [alias] [access-code]")
			}
		case "export-keys":
			if len(args) > 1 {
				peer := bcgo.GetBCWebsite()
				if len(args) > 2 {
					peer = args[2]
				}
				accessCode, err := c.ExportKeys(peer, args[1])
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
	fmt.Fprintln(output, "\tbc - display usage")
	fmt.Fprintln(output, "\tbc init - initializes environment, generates key pair, and registers alias")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc node - display registered alias and public key")
	fmt.Fprintln(output, "\tbc alias [alias] - display public key for given alias")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc import-keys [alias] [access-code] - imports the alias and keypair from BC server")
	fmt.Fprintln(output, "\tbc import-keys [alias] [access-code] [peer] - imports the alias and keypair from the given peer")
	fmt.Fprintln(output, "\tbc export-keys [alias] - generates a new access code and exports the alias and keypair to BC server")
	fmt.Fprintln(output, "\tbc export-keys [alias] [peer] - generates a new access code and exports the alias and keypair to the given peer")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc push [channel] - pushes the channel to peers")
	fmt.Fprintln(output, "\tbc push [channel] [peer] - pushes the channel to the given peer")
	fmt.Fprintln(output, "\tbc pull [channel] - pulles the channel from peers")
	fmt.Fprintln(output, "\tbc pull [channel] [peer] - pulles the channel from the given peer")
	fmt.Fprintln(output, "\tbc head [channel] - display head of given channel")
	fmt.Fprintln(output, "\tbc block [channel] [hash] - display block with given hash")
	fmt.Fprintln(output, "\tbc record [channel] [hash] - display record with given hash")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc write [channel] [access...] - reads data from stdin and writes it to cache for the given channel and grants access to the given aliases")
	fmt.Fprintln(output, "\tbc mine [channel] [threshold] - mines the given channel to the given threshold")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc peers - display list of peers")
	fmt.Fprintln(output, "\tbc add-peer [peer] - adds the given peer to the list of peers")
	fmt.Fprintln(output, "\tbc keystore - display location of keystore")
	fmt.Fprintln(output, "\tbc cache - display location of cache")
	fmt.Fprintln(output, "\tbc purge - deletes contents of cache")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "\tbc random - generate a random number")
}

func PrintLegalese(output io.Writer) {
	fmt.Fprintln(output, "BC Legalese:")
	fmt.Fprintln(output, "BC is made available by Aletheia Ware LLC [https://aletheiaware.com] under the Terms of Service [https://aletheiaware.com/terms-of-service.html] and Privacy Policy [https://aletheiaware.com/privacy-policy.html].")
	fmt.Fprintln(output, "By continuing to use this software you agree to the Terms of Service, and Privacy Policy.")
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
