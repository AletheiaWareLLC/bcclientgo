/*
 * Copyright 2021 Aletheia Ware LLC
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

package test

import (
	"aletheiaware.com/bcclientgo"
	"aletheiaware.com/bcgo"
	"aletheiaware.com/cryptogo"
	"io"
	"testing"
)

func NewMockBCClient(t *testing.T) bcclientgo.BCClient {
	t.Helper()
	return &MockBCClient{}
}

type MockBCClient struct {
	MockRoot                                    string
	MockPeers                                   []string
	MockCache                                   bcgo.Cache
	MockNetwork                                 bcgo.Network
	MockNode                                    bcgo.Node
	MockListener                                bcgo.MiningListener
	MockAlias                                   string
	MockPeer                                    string
	MockSignedIn                                bool
	MockPublicKeyBytes                          []byte
	MockPublicKeyFormat                         cryptogo.PublicKeyFormat
	MockChannel                                 string
	MockHeadHash, MockBlockHash, MockRecordHash []byte
	MockBlockCallback                           func([]byte, *bcgo.Block) error
	MockBlockCallbackResults                    []*MockBlockCallbackResult
	MockBlock                                   *bcgo.Block
	MockRecord                                  *bcgo.Record
	MockWriter                                  io.Writer
	MockAccesses                                []string
	MockReader                                  io.Reader
	MockWriteCount                              int
	MockThreshold                               uint64
	MockPassword                                []byte
	MockAccessCode                              string

	MockRootError, MockCacheError, MockNetworkError, MockNodeError, MockInitError, MockPublicKeyError                                      error
	MockHeadError, MockChainError, MockBlockError, MockRecordError, MockPushError, MockPullError                                           error
	MockPurgeError, MockImportError, MockExportError, MockReadError, MockReadKeyError, MockReadPayloadError, MockWriteError, MockMineError error
}

func (c *MockBCClient) Root() (string, error) {
	return c.MockRoot, c.MockRootError
}

func (c *MockBCClient) Peers() []string {
	return c.MockPeers
}

func (c *MockBCClient) Cache() (bcgo.Cache, error) {
	return c.MockCache, c.MockCacheError
}

func (c *MockBCClient) Network() (bcgo.Network, error) {
	return c.MockNetwork, c.MockNetworkError
}

func (c *MockBCClient) Node() (bcgo.Node, error) {
	return c.MockNode, c.MockNodeError
}

func (c *MockBCClient) Init(listener bcgo.MiningListener) (bcgo.Node, error) {
	c.MockListener = listener
	return c.MockNode, c.MockNodeError
}

func (c *MockBCClient) IsSignedIn() bool {
	return c.MockSignedIn
}

func (c *MockBCClient) PublicKey(alias string) ([]byte, cryptogo.PublicKeyFormat, error) {
	c.MockAlias = alias
	return c.MockPublicKeyBytes, c.MockPublicKeyFormat, c.MockPublicKeyError
}

func (c *MockBCClient) Head(channel string) ([]byte, error) {
	c.MockChannel = channel
	return c.MockHeadHash, c.MockHeadError
}

func (c *MockBCClient) Chain(channel string, callback func([]byte, *bcgo.Block) error) error {
	c.MockChannel = channel
	c.MockBlockCallback = callback
	for _, r := range c.MockBlockCallbackResults {
		callback(r.Hash, r.Block)
	}
	return c.MockChainError
}

func (c *MockBCClient) Block(channel string, hash []byte) (*bcgo.Block, error) {
	c.MockChannel = channel
	c.MockBlockHash = hash
	return c.MockBlock, c.MockBlockError
}

func (c *MockBCClient) Record(channel string, hash []byte) (*bcgo.Record, error) {
	c.MockChannel = channel
	c.MockRecordHash = hash
	return c.MockRecord, c.MockRecordError
}

func (c *MockBCClient) Read(channel string, blockHash []byte, recordHash []byte, output io.Writer) error {
	c.MockChannel = channel
	c.MockBlockHash = blockHash
	c.MockRecordHash = recordHash
	c.MockWriter = output
	return c.MockReadError
}

func (c *MockBCClient) ReadKey(channel string, blockHash []byte, recordHash []byte, output io.Writer) error {
	c.MockChannel = channel
	c.MockBlockHash = blockHash
	c.MockRecordHash = recordHash
	c.MockWriter = output
	return c.MockReadKeyError
}

func (c *MockBCClient) ReadPayload(channel string, blockHash []byte, recordHash []byte, output io.Writer) error {
	c.MockChannel = channel
	c.MockBlockHash = blockHash
	c.MockRecordHash = recordHash
	c.MockWriter = output
	return c.MockReadPayloadError
}

func (c *MockBCClient) Write(channel string, accesses []string, input io.Reader) (int, error) {
	c.MockChannel = channel
	c.MockAccesses = accesses
	c.MockReader = input
	return c.MockWriteCount, c.MockWriteError
}

func (c *MockBCClient) Mine(channel string, threshold uint64, listener bcgo.MiningListener) ([]byte, error) {
	c.MockChannel = channel
	c.MockThreshold = threshold
	c.MockListener = listener
	return c.MockBlockHash, c.MockMineError
}

func (c *MockBCClient) Pull(channel string) error {
	c.MockChannel = channel
	return c.MockPullError
}

func (c *MockBCClient) Push(channel string) error {
	c.MockChannel = channel
	return c.MockPushError
}

func (c *MockBCClient) Purge() error {
	return c.MockPurgeError
}

func (c *MockBCClient) ImportKeys(peer, alias, accessCode string) error {
	c.MockPeer = peer
	c.MockAlias = alias
	c.MockAccessCode = accessCode
	return c.MockImportError
}

func (c *MockBCClient) ExportKeys(peer, alias string, password []byte) (string, error) {
	c.MockPeer = peer
	c.MockAlias = alias
	c.MockPassword = password
	return c.MockAccessCode, c.MockExportError
}

func (c *MockBCClient) SetRoot(root string) {
	c.MockRoot = root
}

func (c *MockBCClient) SetPeers(peers ...string) {
	c.MockPeers = peers
}

func (c *MockBCClient) SetCache(cache bcgo.Cache) {
	c.MockCache = cache
}

func (c *MockBCClient) SetNetwork(network bcgo.Network) {
	c.MockNetwork = network
}

func (c *MockBCClient) SetNode(node bcgo.Node) {
	c.MockNode = node
}

type MockBlockCallbackResult struct {
	Hash  []byte
	Block *bcgo.Block
}
