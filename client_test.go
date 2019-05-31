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

package main_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/AletheiaWareLLC/aliasgo"
	"github.com/AletheiaWareLLC/bcclientgo"
	"github.com/AletheiaWareLLC/bcgo"
	"github.com/AletheiaWareLLC/testinggo"
	"os"
	"testing"
)

// TODO split/move
func makeAlias(t *testing.T, cache bcgo.Cache, alias string) (*rsa.PrivateKey, *bcgo.Record) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	testinggo.AssertNoError(t, err)

	record, err := aliasgo.CreateSignedAliasRecord(alias, privateKey)
	testinggo.AssertNoError(t, err)

	recordHash, err := bcgo.HashProtobuf(record)
	testinggo.AssertNoError(t, err)

	block := &bcgo.Block{
		Entry: []*bcgo.BlockEntry{
			&bcgo.BlockEntry{
				Record:     record,
				RecordHash: recordHash,
			},
		},
	}

	blockHash, err := bcgo.HashProtobuf(block)
	testinggo.AssertNoError(t, err)

	err = cache.PutHead(aliasgo.ALIAS, &bcgo.Reference{
		ChannelName: aliasgo.ALIAS,
		BlockHash:   blockHash,
	})
	testinggo.AssertNoError(t, err)

	err = cache.PutBlock(blockHash, block)
	testinggo.AssertNoError(t, err)

	return privateKey, record
}

func setAlias(t *testing.T, dir string) {
	t.Helper()
	alias := "Alice"
	password := "Password1234"
	os.Setenv("ALIAS", alias)
	os.Setenv("PASSWORD", password)
	keyDir, err := bcgo.GetKeyDirectory(dir)
	if err != nil {
		t.Fatalf("Could not get key directory: '%s'", err)
	}
	if _, err := bcgo.CreateRSAPrivateKey(keyDir, alias, []byte(password)); err != nil {
		t.Fatalf("Could not create keys: '%s'", err)
	}
}

func unsetAlias(t *testing.T) {
	t.Helper()
	os.Unsetenv("ALIAS")
	os.Unsetenv("PASSWORD")
}

func TestClientInit(t *testing.T) {
	// TODO set ROOT_DIRECTORY, ALIAS env
	/*
		t.Run("Success", func(t *testing.T) {
		   root := testinggo.MakeEnvTempDir(t, "ROOT_DIRECTORY", "root")
		   defer testinggo.UnmakeEnvTempDir(t, "ROOT_DIRECTORY", root)
		   client := &main.Client{
		       Root: root,
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
		cache := bcgo.NewMemoryCache(2)
		key, _ := makeAlias(t, cache, "Alice")
		publicKeyBytes, err := bcgo.RSAPublicKeyToPKIXBytes(&key.PublicKey)
		testinggo.AssertNoError(t, err)
		expected := base64.RawURLEncoding.EncodeToString(publicKeyBytes)
		client := &main.Client{
			Cache: cache,
		}
		actual, err := client.Alias("Alice")
		testinggo.AssertNoError(t, err)

		if actual != expected {
			t.Fatalf("Incorrect key; expected '%s', instead got '%s'", expected, actual)
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		client := &main.Client{
			Cache: bcgo.NewMemoryCache(2),
		}
		_, err := client.Alias("Alice")
		testinggo.AssertError(t, aliasgo.ERROR_PUBLIC_KEY_NOT_FOUND, err)
	})
}

func TestClientHead(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(2)
		client := &main.Client{
			Cache: cache,
		}
		block := &bcgo.Block{
			Timestamp:   1234,
			ChannelName: "Test",
		}
		hash, err := bcgo.HashProtobuf(block)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, cache.PutBlock(hash, block))
		testinggo.AssertNoError(t, cache.PutHead("Test", &bcgo.Reference{
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
		client := &main.Client{
			Cache: bcgo.NewMemoryCache(2),
		}
		_, err := client.Head("Test")
		testinggo.AssertError(t, "Head not found Test", err)
	})
}

func TestClientBlock(t *testing.T) {
	t.Run("Exists", func(t *testing.T) {
		cache := bcgo.NewMemoryCache(2)
		client := &main.Client{
			Cache: cache,
		}
		expected := &bcgo.Block{
			ChannelName: "Test",
			Miner:       "FooBar123",
		}
		hash, err := bcgo.HashProtobuf(expected)
		testinggo.AssertNoError(t, err)
		testinggo.AssertNoError(t, cache.PutBlock(hash, expected))
		block, err := client.Block("Test", hash)
		testinggo.AssertNoError(t, err)
		if block.String() != expected.String() {
			t.Fatalf("Incorrect block; expected '%s', got '%s'", expected.String(), block.String())
		}
	})
	t.Run("NotExists", func(t *testing.T) {
		client := &main.Client{
			Cache: bcgo.NewMemoryCache(2),
		}
		hash := []byte("FooBar123")
		expected := base64.RawURLEncoding.EncodeToString(hash)
		_, err := client.Block("Test", hash)
		testinggo.AssertError(t, fmt.Sprintf(bcgo.ERROR_BLOCK_NOT_FOUND, expected), err)
	})
}

func TestClientRecord(t *testing.T) {
	// TODO
	/*
		t.Run("Exists", func(t *testing.T) {
			cache := bcgo.NewMemoryCache(2)
			client := &main.Client{
				Cache: cache,
			}
			record, err := client.Record("Test", hash)
			testinggo.AssertNoError(t, err)
		})
		t.Run("NotExists", func(t *testing.T) {
			cache := bcgo.NewMemoryCache(2)
			client := &main.Client{
				Cache: cache,
			}
			record, err := client.Record("Test", hash)
			testinggo.AssertNoError(t, err)
		})
	*/
}

func TestClientMine(t *testing.T) {
	t.Run("PublicEmpty", func(t *testing.T) {
		root := testinggo.MakeEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnmakeEnvTempDir(t, "ROOT", root)
		client := &main.Client{
			Root:  root,
			Cache: bcgo.NewMemoryCache(2),
		}
		buffer := &bytes.Buffer{}
		size, _, err := client.Mine("Test", 1, nil, buffer, nil)
		testinggo.AssertNoError(t, err)
		if size != 0 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 0, size)
		}
		// TODO test channel head points to block containing expected payload
	})
	t.Run("PublicNotEmpty", func(t *testing.T) {
		root := testinggo.MakeEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnmakeEnvTempDir(t, "ROOT", root)
		client := &main.Client{
			Root:  root,
			Cache: bcgo.NewMemoryCache(2),
		}
		buffer := bytes.NewBufferString("FooBar123")
		size, _, err := client.Mine("Test", 1, nil, buffer, nil)
		testinggo.AssertNoError(t, err)
		if size != 9 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 9, size)
		}
		// TODO test channel head points to block containing expected payload
	})
	t.Run("PrivateEmpty", func(t *testing.T) {
		root := testinggo.MakeEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnmakeEnvTempDir(t, "ROOT", root)
		cache := bcgo.NewMemoryCache(2)
		makeAlias(t, cache, "Alice")
		client := &main.Client{
			Root:  root,
			Cache: cache,
		}
		buffer := &bytes.Buffer{}
		size, _, err := client.Mine("Test", 1, []string{"Alice"}, buffer, nil)
		testinggo.AssertNoError(t, err)
		if size != 0 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 0, size)
		}
		// TODO test channel head points to block containing expected payload
	})
	t.Run("PrivateNotEmpty", func(t *testing.T) {
		root := testinggo.MakeEnvTempDir(t, "ROOT", "root")
		setAlias(t, root)
		defer unsetAlias(t)
		defer testinggo.UnmakeEnvTempDir(t, "ROOT", root)
		cache := bcgo.NewMemoryCache(2)
		/*key, _ := */ makeAlias(t, cache, "Alice")
		client := &main.Client{
			Root:  root,
			Cache: cache,
		}
		buffer := bytes.NewBufferString("FooBar123")
		size, _, err := client.Mine("Test", 1, []string{"Alice"}, buffer, nil)
		testinggo.AssertNoError(t, err)
		if size != 9 {
			t.Fatalf("Incorrect size; expected '%d', got '%d'", 9, size)
		}
		// TODO test channel head points to block containing expected payload
	})
}
