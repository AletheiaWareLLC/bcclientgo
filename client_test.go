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

package bcclientgo_test

import (
	"aletheiaware.com/aliasgo"
	"aletheiaware.com/bcclientgo"
	"aletheiaware.com/bcgo"
	"aletheiaware.com/bcgo/account"
	"aletheiaware.com/bcgo/cache"
	"aletheiaware.com/bcgo/network"
	"aletheiaware.com/cryptogo"
	"aletheiaware.com/testinggo"
	"bytes"
	"encoding/base64"
	"os"
	"testing"
	"time"
)

// TODO split/move
func makeAlias(t *testing.T, cache bcgo.Cache, alias string) bcgo.Account {
	t.Helper()

	account, err := account.GenerateRSA(alias)
	testinggo.AssertNoError(t, err)

	record, err := aliasgo.CreateSignedAliasRecord(account)
	testinggo.AssertNoError(t, err)

	recordHash, err := cryptogo.HashProtobuf(record)
	testinggo.AssertNoError(t, err)

	block := &bcgo.Block{
		Timestamp: 1,
		Entry: []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     record,
				RecordHash: recordHash,
			},
		},
	}

	blockHash, err := cryptogo.HashProtobuf(block)
	testinggo.AssertNoError(t, err)

	err = cache.PutHead(aliasgo.ALIAS, &bcgo.Reference{
		Timestamp:   1,
		ChannelName: aliasgo.ALIAS,
		BlockHash:   blockHash,
	})
	testinggo.AssertNoError(t, err)

	err = cache.PutBlock(blockHash, block)
	testinggo.AssertNoError(t, err)

	return account
}

func setAlias(t *testing.T, dir string) {
	t.Helper()
	alias := "Alice"
	password := "Password1234"
	os.Setenv("ALIAS", alias)
	os.Setenv("PASSWORD", password)
	keyDir, err := bcgo.KeyDirectory(dir)
	if err != nil {
		t.Fatalf("Could not get key directory: '%s'", err)
	}
	if _, err := cryptogo.CreateRSAPrivateKey(keyDir, alias, []byte(password)); err != nil {
		t.Fatalf("Could not create keys: '%s'", err)
	}
}

func unsetAlias(t *testing.T) {
	t.Helper()
	os.Unsetenv("ALIAS")
	os.Unsetenv("PASSWORD")
}

func makeNetwork(t *testing.T) *network.TCP {
	t.Helper()
	return &network.TCP{
		DialTimeout: time.Second,
		GetTimeout:  time.Second,
	}
}

func TestClientInit(t *testing.T) {
	// TODO set ROOT_DIRECTORY, ALIAS env
	/*
		t.Run("Success", func(t *testing.T) {
			root := testinggo.SetEnvTempDir(t, "ROOT_DIRECTORY", "root")
			defer testinggo.UnsetEnvTempDir(t, "ROOT_DIRECTORY", root)
			client := &main.BCClient{
				Root:    root,
				Network: makeNetwork(t),
			}
			node, err := client.Init()
			testinggo.AssertNoError(t, err)
		})
		t.Run("AliasAlreadyRegistered", func(t *testing.T) {
		})
	*/
}

func TestClientAlias(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := cache.NewMemory(2)
		account := makeAlias(t, cache, "Alice")
		expectedFormat, expectedBytes, err := account.PublicKey()
		testinggo.AssertNoError(t, err)
		expectedKey := base64.RawURLEncoding.EncodeToString(expectedBytes)
		client := bcclientgo.NewBCClient()
		client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
		actualFormat, actualBytes, err := client.PublicKey("Alice")
		testinggo.AssertNoError(t, err)

		actualKey := base64.RawURLEncoding.EncodeToString(actualBytes)
		if actualKey != expectedKey {
			t.Fatalf("Incorrect key; expected '%s', instead got '%s'", expectedKey, actualKey)
		}
		if actualFormat != expectedFormat {
			t.Fatalf("Incorrect key format; expected '%s', instead got '%s'", expectedFormat, actualFormat)
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		client := bcclientgo.NewBCClient()
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))
		_, _, err := client.PublicKey("Alice")
		testinggo.AssertError(t, aliasgo.ErrPublicKeyNotFound{Alias: "Alice"}.Error(), err)
	})
}

func TestClientHead(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := cache.NewMemory(2)
		client := bcclientgo.NewBCClient()
		client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
		block := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "Test",
		}
		hash, err := cryptogo.HashProtobuf(block)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, cache.PutBlock(hash, block))
		testinggo.AssertNoError(t, cache.PutHead("Test", &bcgo.Reference{
			Timestamp:   1,
			ChannelName: "Test",
			BlockHash:   hash,
		}))

		// TODO channel head also loads block
		head, err := client.Head("Test")
		testinggo.AssertNoError(t, err)
		if !bytes.Equal(hash, head) {
			t.Fatalf("Incorrect head; expected '%s', got '%s'", string(hash), string(head))
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		client := bcclientgo.NewBCClient()
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))
		_, err := client.Head("Test")
		testinggo.AssertError(t, "Could not get Test from peers", err)
	})
}

func TestClientBlock(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := cache.NewMemory(2)
		client := bcclientgo.NewBCClient()
		client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
		expected := &bcgo.Block{
			ChannelName: "Test",
			Miner:       "FooBar123",
		}
		hash, err := cryptogo.HashProtobuf(expected)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, cache.PutBlock(hash, expected))
		block, err := client.Block("Test", hash)
		testinggo.AssertNoError(t, err)
		if block.String() != expected.String() {
			t.Fatalf("Incorrect block; expected '%s', got '%s'", expected.String(), block.String())
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		client := bcclientgo.NewBCClient()
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))
		_, err := client.Block("Test", []byte("FooBar123"))
		testinggo.AssertError(t, "Could not get Test block from peers", err)
	})
}

func TestClientRecord(t *testing.T) {
	// TODO
	/*
				t.Run("Exists", func(t *testing.T) {
					cache := cache.NewMemory(2)
				client := bcclientgo.NewBCClient()
				client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
					record, err := client.Record("Test", hash)
					testinggo.AssertNoError(t, err)
				})
				t.Run("NotExists", func(t *testing.T) {
					cache := cache.NewMemory(2)
				client := bcclientgo.NewBCClient()
				client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
					record, err := client.Record("Test", hash)
					testinggo.AssertNoError(t, err)
				})
	*/
}

func TestClientWrite(t *testing.T) {
	t.Run("PublicEmpty", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))
		buffer := &bytes.Buffer{}
		size, err := client.Write("Test", nil, buffer)
		testinggo.AssertNoError(t, err)
		if size != 0 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 0, size)
		}
	})
	t.Run("PublicNotEmpty", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))
		buffer := bytes.NewBufferString("FooBar123")
		size, err := client.Write("Test", nil, buffer)
		testinggo.AssertNoError(t, err)
		if size != 9 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 9, size)
		}
	})
	t.Run("PrivateEmpty", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		cache := cache.NewMemory(2)
		makeAlias(t, cache, "Alice")
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
		buffer := &bytes.Buffer{}
		size, err := client.Write("Test", []string{"Alice"}, buffer)
		testinggo.AssertNoError(t, err)
		if size != 0 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 0, size)
		}
	})
	t.Run("PrivateNotEmpty", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		cache := cache.NewMemory(2)
		makeAlias(t, cache, "Alice")
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))
		buffer := bytes.NewBufferString("FooBar123")
		size, err := client.Write("Test", []string{"Alice"}, buffer)
		testinggo.AssertNoError(t, err)
		if size != 9 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 9, size)
		}
	})
}

func TestClientMine(t *testing.T) {
	t.Run("NoEntries", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))
		_, err := client.Mine("Test", 1, nil)
		testinggo.AssertError(t, bcgo.ErrNoEntriesToMine{Channel: "Test"}.Error(), err)
	})
	t.Run("SingleEntry", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache.NewMemory(2))
		client.SetNetwork(makeNetwork(t))

		record := &bcgo.Record{
			Timestamp: 1234,
		}

		recordHash, err := cryptogo.HashProtobuf(record)
		testinggo.AssertNoError(t, err)

		cache, err := client.Cache()
		testinggo.AssertNoError(t, err)
		cache.PutBlockEntry("Test", &bcgo.BlockEntry{
			Record:     record,
			RecordHash: recordHash,
		})

		hash, err := client.Mine("Test", 1, nil)
		testinggo.AssertNoError(t, err)

		head, err := client.Head("Test")
		testinggo.AssertNoError(t, err)

		testinggo.AssertHashEqual(t, head, hash)
	})
	t.Run("MultipleEntries", func(t *testing.T) {
		root := testinggo.SetEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnsetEnvTempDir(t, "ROOT", root)
		cache := cache.NewMemory(2)
		client := bcclientgo.NewBCClient()
		client.SetRoot(root)
		client.SetCache(cache)
		client.SetNetwork(makeNetwork(t))

		record1 := &bcgo.Record{
			Timestamp: 1234,
		}

		recordHash1, err := cryptogo.HashProtobuf(record1)
		testinggo.AssertNoError(t, err)

		cache.PutBlockEntry("Test", &bcgo.BlockEntry{
			Record:     record1,
			RecordHash: recordHash1,
		})

		record2 := &bcgo.Record{
			Timestamp: 5678,
		}

		recordHash2, err := cryptogo.HashProtobuf(record2)
		testinggo.AssertNoError(t, err)

		cache.PutBlockEntry("Test", &bcgo.BlockEntry{
			Record:     record2,
			RecordHash: recordHash2,
		})

		hash, err := client.Mine("Test", 1, nil)
		testinggo.AssertNoError(t, err)

		head, err := client.Head("Test")
		testinggo.AssertNoError(t, err)

		testinggo.AssertHashEqual(t, head, hash)
	})
}
