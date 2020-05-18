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

package bcclientgo

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/cryptogo"
	"io"
	"log"
	"os"
)

type Client struct {
	root    string
	peers   []string
	cache   bcgo.Cache
	network bcgo.Network
	node    *bcgo.Node
}

func (c *Client) Root() (string, error) {
	if c.root == "" {
		rootDir, err := bcgo.GetRootDirectory()
		if err != nil {
			return "", errors.New(fmt.Sprintf("Could not get root directory: %s\n", err.Error()))
		}
		if err := bcgo.ReadConfig(rootDir); err != nil {
			log.Println("Error reading config:", err)
		}
		c.root = rootDir
	}
	return c.root, nil
}

func (c *Client) DefaultPeers() ([]string, error) {
	rootDir, err := c.Root()
	if err != nil {
		return nil, err
	}
	return bcgo.GetPeers(rootDir)
}

func (c *Client) Peers() ([]string, error) {
	return c.peers, nil
}

func (c *Client) Cache() (bcgo.Cache, error) {
	if c.cache == nil {
		rootDir, err := c.Root()
		if err != nil {
			return nil, err
		}
		cacheDir, err := bcgo.GetCacheDirectory(rootDir)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Could not get cache directory: %s\n", err.Error()))
		}
		cache, err := bcgo.NewFileCache(cacheDir)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Could not create file cache: %s\n", err.Error()))
		}
		c.cache = cache
	}
	return c.cache, nil
}

func (c *Client) Network() (bcgo.Network, error) {
	if c.network == nil {
		peers, err := c.Peers()
		if err != nil {
			return nil, err
		}
		c.network = bcgo.NewTCPNetwork(peers...)
	}
	return c.network, nil
}

func (c *Client) Node() (*bcgo.Node, error) {
	if c.node == nil {
		rootDir, err := c.Root()
		if err != nil {
			return nil, err
		}
		cache, err := c.Cache()
		if err != nil {
			return nil, err
		}
		network, err := c.Network()
		if err != nil {
			return nil, err
		}
		node, err := bcgo.GetNode(rootDir, cache, network)
		if err != nil {
			return nil, err
		}
		c.node = node
	}
	return c.node, nil
}

func (c *Client) SetRoot(root string) {
	c.root = root
}

func (c *Client) SetPeers(peers ...string) {
	c.peers = peers
}

func (c *Client) SetCache(cache bcgo.Cache) {
	c.cache = cache
}

func (c *Client) SetNetwork(network bcgo.Network) {
	c.network = network
}

func (c *Client) SetNode(node *bcgo.Node) {
	c.node = node
}

func (c *Client) Init(listener bcgo.MiningListener) (*bcgo.Node, error) {
	// Create Node
	node, err := c.Node()
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
	cache, err := c.Cache()
	if err != nil {
		return "", err
	}
	network, err := c.Network()
	if err != nil {
		return "", err
	}
	// Open Alias Channel
	aliases := aliasgo.OpenAliasChannel()
	if err := aliases.LoadCachedHead(cache); err != nil {
		log.Println(err)
	}
	if err := aliases.Pull(cache, network); err != nil {
		log.Println(err)
	}
	// Get Public Key for Alias
	publicKey, err := aliasgo.GetPublicKey(aliases, cache, network, alias)
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
	cache, err := c.Cache()
	if err != nil {
		return nil, err
	}
	network, err := c.Network()
	if err != nil {
		return nil, err
	}
	ch := &bcgo.Channel{
		Name: channel,
	}
	if err := ch.LoadHead(cache, network); err != nil {
		return nil, err
	}
	return ch.Head, nil
}

func (c *Client) Block(channel string, hash []byte) (*bcgo.Block, error) {
	cache, err := c.Cache()
	if err != nil {
		return nil, err
	}
	network, err := c.Network()
	if err != nil {
		return nil, err
	}
	block, err := bcgo.GetBlock(channel, cache, network, hash)
	if err != nil {
		return nil, err
	}
	return block, nil
}

func (c *Client) Record(channel string, hash []byte) (*bcgo.Record, error) {
	cache, err := c.Cache()
	if err != nil {
		return nil, err
	}
	network, err := c.Network()
	if err != nil {
		return nil, err
	}
	block, err := bcgo.GetBlockContainingRecord(channel, cache, network, hash)
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
	cache, err := c.Cache()
	if err != nil {
		return err
	}
	network, err := c.Network()
	if err != nil {
		return err
	}
	node, err := c.Node()
	if err != nil {
		return err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(cache, network); err != nil {
		log.Println(err)
	}

	if blockHash == nil {
		blockHash = ch.Head
	}

	return bcgo.Read(channel, blockHash, nil, cache, network, node.Alias, node.Key, recordHash, func(entry *bcgo.BlockEntry, key, payload []byte) error {
		bcgo.PrintBlockEntry(output, "", entry)
		return nil
	})
}

func (c *Client) ReadKey(channel string, blockHash, recordHash []byte, output io.Writer) error {
	cache, err := c.Cache()
	if err != nil {
		return err
	}
	network, err := c.Network()
	if err != nil {
		return err
	}
	node, err := c.Node()
	if err != nil {
		return err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(cache, network); err != nil {
		log.Println(err)
	}

	if blockHash == nil {
		blockHash = ch.Head
	}

	return bcgo.ReadKey(channel, blockHash, nil, cache, network, node.Alias, node.Key, recordHash, func(key []byte) error {
		output.Write(key)
		return nil
	})
}

func (c *Client) ReadPayload(channel string, blockHash, recordHash []byte, output io.Writer) error {
	cache, err := c.Cache()
	if err != nil {
		return err
	}
	network, err := c.Network()
	if err != nil {
		return err
	}
	node, err := c.Node()
	if err != nil {
		return err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(cache, network); err != nil {
		log.Println(err)
	}

	if blockHash == nil {
		blockHash = ch.Head
	}

	return bcgo.Read(channel, blockHash, nil, cache, network, node.Alias, node.Key, recordHash, func(entry *bcgo.BlockEntry, key, payload []byte) error {
		output.Write(payload)
		return nil
	})
}

func (c *Client) Write(channel string, accesses []string, input io.Reader) (int, error) {
	cache, err := c.Cache()
	if err != nil {
		return 0, err
	}
	network, err := c.Network()
	if err != nil {
		return 0, err
	}
	var acl map[string]*rsa.PublicKey

	if len(accesses) > 0 {
		// Open Alias Channel
		aliases := aliasgo.OpenAliasChannel()
		if err := aliases.LoadCachedHead(cache); err != nil {
			log.Println(err)
		}
		if err := aliases.Pull(cache, network); err != nil {
			log.Println(err)
		}
		acl = aliasgo.GetPublicKeys(aliases, cache, network, accesses)
	}

	node, err := c.Node()
	if err != nil {
		return 0, err
	}

	size, err := bcgo.CreateRecords(node.Alias, node.Key, acl, nil, input, func(key []byte, record *bcgo.Record) error {
		_, err := bcgo.WriteRecord(channel, cache, record)
		return err
	})
	if err != nil {
		return 0, err
	}

	return size, nil
}

func (c *Client) Mine(channel string, threshold uint64, listener bcgo.MiningListener) ([]byte, error) {
	cache, err := c.Cache()
	if err != nil {
		return nil, err
	}
	network, err := c.Network()
	if err != nil {
		return nil, err
	}
	node, err := c.Node()
	if err != nil {
		return nil, err
	}

	ch := &bcgo.Channel{
		Name: channel,
	}

	if err := ch.LoadHead(cache, network); err != nil {
		log.Println(err)
	}

	hash, _, err := node.Mine(ch, threshold, listener)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func (c *Client) Pull(channel string) error {
	cache, err := c.Cache()
	if err != nil {
		return err
	}
	network, err := c.Network()
	if err != nil {
		return err
	}
	ch := &bcgo.Channel{
		Name: channel,
	}
	return ch.Pull(cache, network)
}

func (c *Client) Push(channel string) error {
	cache, err := c.Cache()
	if err != nil {
		return err
	}
	network, err := c.Network()
	if err != nil {
		return err
	}
	ch := &bcgo.Channel{
		Name: channel,
	}
	if err := ch.LoadHead(cache, nil); err != nil {
		return err
	}
	return ch.Push(cache, network)
}

func (c *Client) Purge() error {
	rootDir, err := c.Root()
	if err != nil {
		return err
	}
	// Get cache directory
	dir, err := bcgo.GetCacheDirectory(rootDir)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (c *Client) ImportKeys(peer, alias, accessCode string) error {
	rootDir, err := c.Root()
	if err != nil {
		return err
	}
	// Get KeyStore
	keystore, err := bcgo.GetKeyDirectory(rootDir)
	if err != nil {
		return err
	}
	return cryptogo.ImportKeys(peer, keystore, alias, accessCode)
}

func (c *Client) ExportKeys(peer, alias string) (string, error) {
	rootDir, err := c.Root()
	if err != nil {
		return "", err
	}
	// Get KeyStore
	keystore, err := bcgo.GetKeyDirectory(rootDir)
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
