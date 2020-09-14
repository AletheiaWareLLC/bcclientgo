// +build !android
// +build !ios

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

package bcclientgo

import (
	"fmt"
	"github.com/AletheiaWareLLC/bcgo"
	"log"
	"os"
)

func (c *BCClient) GetRoot() (string, error) {
	if c.Root == "" {
		log.Println("bcclientgo.BCClient.GetRoot()")
		log.Println(os.Environ())
		rootDir, err := bcgo.GetRootDirectory()
		if err != nil {
			return "", fmt.Errorf("Could not get root directory: %s\n", err.Error())
		}
		if err := bcgo.ReadConfig(rootDir); err != nil {
			log.Println("Error reading config:", err)
		}
		c.Root = rootDir
	}
	return c.Root, nil
}
