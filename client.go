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
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/cryptogo"
	"io"
	"log"
	"os"
)

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
