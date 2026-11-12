package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteSarif(t *testing.T) {
	tests := []struct {
		findings       []Finding
		testReportName string
		expected       string
		wantEmpty      bool
		cfgName        string
	}{
		{
			cfgName:        "simple",
			testReportName: "simple",
			expected:       filepath.Join(expectPath, "report", "sarif_simple.sarif"),
			findings: []Finding{
				{

					RuleID:      "test-rule",
					Description: "A test rule",
					Match:       "line containing secret",
					Secret:      "a secret",
					StartLine:   1,
					EndLine:     2,
					StartColumn: 1,
					EndColumn:   2,
					Message:     "opps",
					File:        "auth.py",
					Commit:      "0000000000000000",
					Author:      "John Doe",
					Email:       "johndoe@gmail.com",
					Date:        "10-19-2003",
					Tags:        []string{"tag1", "tag2", "tag3"},
				},
			}},
	}

	for _, test := range tests {
		t.Run(test.cfgName, func(t *testing.T) {
			tmpfile, err := os.Create(filepath.Join(t.TempDir(), test.testReportName+".json"))
			require.NoError(t, err)
			defer tmpfile.Close()

			reporter := SarifReporter{
				OrderedRules: []config.Rule{
					{
						RuleID:      "aws-access-key",
						Description: "AWS Access Key",
					},
					{
						RuleID:      "pypi",
						Description: "PyPI upload token",
					},
				},
			}
			err = reporter.Write(tmpfile, test.findings)
			require.NoError(t, err)
			assert.FileExists(t, tmpfile.Name())

			got, err := os.ReadFile(tmpfile.Name())
			require.NoError(t, err)

			if test.wantEmpty {
				assert.Empty(t, got)
				return
			}

			want, err := os.ReadFile(test.expected)
			require.NoError(t, err)

			wantStr := lineEndingReplacer.Replace(string(want))
			gotStr := lineEndingReplacer.Replace(string(got))
			assert.Equal(t, wantStr, gotStr)
		})
	}
}

func writeSarif(t *testing.T, reporter *SarifReporter, findings []Finding) Sarif {
	t.Helper()
	tmpfile, err := os.Create(filepath.Join(t.TempDir(), "out.json"))
	require.NoError(t, err)
	defer tmpfile.Close()
	require.NoError(t, reporter.Write(tmpfile, findings))

	got, err := os.ReadFile(tmpfile.Name())
	require.NoError(t, err)

	var sarif Sarif
	require.NoError(t, json.Unmarshal(got, &sarif))
	return sarif
}

func finding(rule, file, secret string, startLine int) Finding {
	return Finding{
		RuleID:    rule,
		Secret:    secret,
		Match:     secret,
		File:      file,
		StartLine: startLine,
		EndLine:   startLine,
	}
}

func resultFingerprint(r Results) string {
	return r.PartialFingerPrints.Stable
}

// TestSarifRelativeURI ensures artifact URIs are relative to the scan root
// and use forward slashes whether the source and finding paths are absolute
// or relative.
func TestSarifRelativeURI(t *testing.T) {
	findings := []Finding{
		finding("rule", filepath.Join("repo", "sub", "one.go"), "AKIALALEMEL33243OLIA", 5),
	}

	absSource, err := filepath.Abs("repo")
	require.NoError(t, err)

	relative := writeSarif(t, &SarifReporter{Source: "repo"}, findings)
	absolute := writeSarif(t, &SarifReporter{Source: absSource},
		// Mirror what filepath.WalkDir produces when handed an absolute root.
		[]Finding{finding("rule", filepath.Join(absSource, "sub", "one.go"), "AKIALALEMEL33243OLIA", 5)})

	gotRel := relative.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	gotAbs := absolute.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI

	assert.Equal(t, "sub/one.go", gotRel)
	assert.Equal(t, "sub/one.go", gotAbs)
	assert.NotContains(t, gotRel, "\\")
	assert.NotContains(t, gotAbs, "\\")
	assert.False(t, filepath.IsAbs(gotRel))
	assert.False(t, filepath.IsAbs(gotAbs))
}

// TestSarifGitStylePaths verifies that repository-root-relative paths (the
// shape produced by git scans) are not mangled into "../"-prefixed URIs.
func TestSarifGitStylePaths(t *testing.T) {
	findings := []Finding{finding("rule", "main.go", "AKIALALEMEL33243OLIA", 3)}

	rel := writeSarif(t, &SarifReporter{Source: "repo"}, findings)
	dot := writeSarif(t, &SarifReporter{Source: "."}, findings)
	absSource, err := filepath.Abs("repo")
	require.NoError(t, err)
	abs := writeSarif(t, &SarifReporter{Source: absSource}, findings)

	for _, sarif := range []Sarif{rel, dot, abs} {
		uri := sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
		assert.Equal(t, "main.go", uri)
	}
}

// TestSarifStableFingerprintLineShift checks the fingerprint does not depend
// on line numbers: shifting the same leak down by inserting lines keeps it.
func TestSarifStableFingerprintLineShift(t *testing.T) {
	secret := "AKIALALEMEL33243OLIA"
	before := writeSarif(t, &SarifReporter{Source: "repo"},
		[]Finding{finding("rule", "main.go", secret, 3)})
	after := writeSarif(t, &SarifReporter{Source: "repo"},
		[]Finding{finding("rule", "main.go", secret, 47)})

	fpBefore := resultFingerprint(before.Runs[0].Results[0])
	fpAfter := resultFingerprint(after.Runs[0].Results[0])

	assert.NotEmpty(t, fpBefore)
	assert.Equal(t, fpBefore, fpAfter)
}

// TestSarifDistinctLocationsNotMerged ensures identical secrets and line
// content at different locations (same file or different files) produce
// distinct fingerprints.
func TestSarifDistinctLocationsNotMerged(t *testing.T) {
	secret := "AKIALALEMEL33243OLIA"
	findings := []Finding{
		finding("rule", "dup.go", secret, 4),
		finding("rule", "dup.go", secret, 5),
		finding("rule", "other.go", secret, 4),
	}
	sarif := writeSarif(t, &SarifReporter{Source: "repo"}, findings)

	fps := map[string]struct{}{}
	for _, r := range sarif.Runs[0].Results {
		fps[resultFingerprint(r)] = struct{}{}
	}
	assert.Len(t, fps, len(findings), "each location needs a unique fingerprint")
}

// TestSarifFingerprintHasNoPlaintextSecret confirms the stable fingerprint
// and the partialFingerprints object never embed the raw secret.
func TestSarifFingerprintHasNoPlaintextSecret(t *testing.T) {
	secret := "AKIALALEMEL33243OLIA"
	sarif := writeSarif(t, &SarifReporter{Source: "repo"},
		[]Finding{finding("rule", "main.go", secret, 3)})

	for _, r := range sarif.Runs[0].Results {
		raw, err := json.Marshal(r.PartialFingerPrints)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), secret)
		assert.Len(t, resultFingerprint(r), 64, "expected a hex-encoded SHA-256 digest")
	}
}

// TestSarifFingerprintStableAcrossInvocationRoot checks the fingerprint is
// identical whether the scan root was passed as an absolute or relative path.
func TestSarifFingerprintStableAcrossInvocationRoot(t *testing.T) {
	secret := "AKIALALEMEL33243OLIA"

	absSource, err := filepath.Abs("repo")
	require.NoError(t, err)

	rel := writeSarif(t, &SarifReporter{Source: "repo"},
		[]Finding{finding("rule", filepath.Join("repo", "main.go"), secret, 3)})
	abs := writeSarif(t, &SarifReporter{Source: absSource},
		[]Finding{finding("rule", filepath.Join(absSource, "main.go"), secret, 3)})

	assert.Equal(t,
		resultFingerprint(rel.Runs[0].Results[0]),
		resultFingerprint(abs.Runs[0].Results[0]))
}

// TestSarifLegacyPartialFingerprintsRetained makes sure the pre-existing
// commit/author metadata is still emitted alongside the new fingerprint.
func TestSarifLegacyPartialFingerprintsRetained(t *testing.T) {
	f := finding("rule", "main.go", "AKIALALEMEL33243OLIA", 3)
	f.Commit = "0000000000000000"
	f.Author = "John Doe"
	f.Email = "john@example.com"

	sarif := writeSarif(t, &SarifReporter{Source: "repo"}, []Finding{f})
	pf := sarif.Runs[0].Results[0].PartialFingerPrints

	assert.Equal(t, "0000000000000000", pf.CommitSha)
	assert.Equal(t, "John Doe", pf.Author)
	assert.Equal(t, "john@example.com", pf.Email)
	assert.NotEmpty(t, pf.Stable)
}
