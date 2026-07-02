// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

// The C functions the SDK links: a JSON request in, a JSON response out.
package main

// #include <stdlib.h>
import "C"

import "unsafe"

// passbolt_gopenpgp_call runs the request of `length` bytes at `input`. The response, of
// `*output_length` bytes, is to be freed with passbolt_gopenpgp_free.
//
//export passbolt_gopenpgp_call
func passbolt_gopenpgp_call(input *C.char, length C.size_t, outputLength *C.size_t) *C.char {
	output := Call(C.GoBytes(unsafe.Pointer(input), C.int(length)))
	*outputLength = C.size_t(len(output))
	return (*C.char)(C.CBytes(output))
}

//export passbolt_gopenpgp_free
func passbolt_gopenpgp_free(output *C.char) {
	C.free(unsafe.Pointer(output))
}

func main() {}
