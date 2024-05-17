//
// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build e2e && github

package test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	cliverify "github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
)

func TestSignBlobWithGitHubOIDC(t *testing.T) {
	td := t.TempDir()
	blob := "someblob"
	bp := filepath.Join(td, blob)
	if err := os.WriteFile(bp, []byte(blob), 0644); err != nil {
		t.Fatal(err)
	}
	ko := options.KeyOpts{
		FulcioURL:        "https://fulcio.sigstore.dev", // FIXME
		RekorURL:         "https://rekor.sigstore.dev",  // FIXME
		SkipConfirmation: true,
	}
	//signaturePath := filepath.Join(td, "blob.sig")
	certPath := filepath.Join(td, "blob.cert")
	sig, err := sign.SignBlobCmd(ro, ko, bp, true, "", certPath, true)
	must(err, t)

	verifyCmd := cliverify.VerifyBlobCmd{
		KeyOpts: ko,
		SigRef:  string(sig),
		CertRef: certPath,
		CertVerifyOptions: options.CertVerifyOptions{
			CertIdentityRegexp:   ".*",
			CertOidcIssuerRegexp: ".*",
		},
	}
	must(verifyCmd.Exec(context.Background(), bp), t)
}
