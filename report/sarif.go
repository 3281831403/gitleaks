package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
)

type SarifReporter struct {
	OrderedRules []config.Rule

	// Source is the root path the scan was invoked with (the directory,
	// file or git repository passed on the command line). Artifact URIs are
	// emitted relative to this root so that SARIF consumers such as GitHub
	// code scanning can map results back to repository files regardless of
	// whether the source was given as an absolute or relative path.
	Source string
}

var _ Reporter = (*SarifReporter)(nil)

// stableFingerprintKey is the partialFingerprints key for the location-based
// fingerprint. The "/v1" suffix versions the hashing scheme.
const stableFingerprintKey = "gitleaksFingerprint/v1"

func (r *SarifReporter) Write(w io.WriteCloser, findings []Finding) error {
	sarif := Sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    r.getRuns(findings),
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(sarif)
}

func (r *SarifReporter) getRuns(findings []Finding) []Runs {
	return []Runs{
		{
			Tool:    r.getTool(),
			Results: r.getResults(findings),
		},
	}
}

func (r *SarifReporter) getTool() Tool {
	tool := Tool{
		Driver: Driver{
			Name:            driver,
			SemanticVersion: version,
			InformationUri:  "https://github.com/gitleaks/gitleaks",
			Rules:           r.getRules(),
		},
	}

	// if this tool has no rules, ensure that it is represented as [] instead of null/nil
	if hasEmptyRules(tool) {
		tool.Driver.Rules = make([]Rules, 0)
	}

	return tool
}

func hasEmptyRules(tool Tool) bool {
	return len(tool.Driver.Rules) == 0
}

func (r *SarifReporter) getRules() []Rules {
	// TODO	for _, rule := range cfg.Rules {
	var rules []Rules
	for _, rule := range r.OrderedRules {
		rules = append(rules, Rules{
			ID: rule.RuleID,
			Description: ShortDescription{
				Text: rule.Description,
			},
		})
	}
	return rules
}

func messageText(f Finding) string {
	if f.Commit == "" {
		return fmt.Sprintf("%s has detected secret for file %s.", f.RuleID, f.File)
	}

	return fmt.Sprintf("%s has detected secret for file %s at commit %s.", f.RuleID, f.File, f.Commit)

}

func (r *SarifReporter) getResults(findings []Finding) []Results {
	results := []Results{}

	// Assign a stable ordinal to every finding within its (rule, file)
	// group. The ordinal is position-based rather than line-based so that
	// the fingerprint survives line shifts (for example inserting a
	// comment above the leak), while findings at different locations keep
	// distinct fingerprints even when the secret and line content are
	// identical.
	ordinals := r.stableOrdinals(findings)

	for i, f := range findings {
		uri := r.artifactURI(f)
		r := Results{
			Message: Message{
				Text: messageText(f),
			},
			RuleId:    f.RuleID,
			Locations: getLocation(f, uri),
			// This information goes in partial fingerprings until revision
			// data can be added somewhere else
			PartialFingerPrints: PartialFingerPrints{
				CommitSha:     f.Commit,
				Email:         f.Email,
				CommitMessage: f.Message,
				Date:          f.Date,
				Author:        f.Author,
				Stable:        r.stableFingerprint(f, uri, ordinals[i]),
			},
			Properties: Properties{
				Tags: f.Tags,
			},
		}
		results = append(results, r)
	}
	return results
}

// stableOrdinals returns, for each finding (by slice index), the zero-based
// ordinal of the finding within its (rule id, artifact uri) group ordered by
// physical location.
func (r *SarifReporter) stableOrdinals(findings []Finding) []int {
	indices := make(map[string][]int)
	for i, f := range findings {
		key := f.RuleID + "\x00" + r.artifactURI(f)
		indices[key] = append(indices[key], i)
	}

	ordinals := make([]int, len(findings))
	for _, group := range indices {
		sort.Slice(group, func(a, b int) bool {
			fa, fb := findings[group[a]], findings[group[b]]
			if fa.StartLine != fb.StartLine {
				return fa.StartLine < fb.StartLine
			}
			if fa.StartColumn != fb.StartColumn {
				return fa.StartColumn < fb.StartColumn
			}
			if fa.EndLine != fb.EndLine {
				return fa.EndLine < fb.EndLine
			}
			if fa.EndColumn != fb.EndColumn {
				return fa.EndColumn < fb.EndColumn
			}
			// Deterministic tiebreaker for multiple matches starting at
			// the exact same location.
			return fa.Secret < fb.Secret
		})
		for ordinal, findingIndex := range group {
			ordinals[findingIndex] = ordinal
		}
	}
	return ordinals
}

// stableFingerprint builds a location-based fingerprint that does not contain
// the plaintext secret. It hashes the rule id, the artifact URI relative to
// the scan root, the finding's position ordinal within that (rule, file)
// group and a hash of the secret. Because the input contains neither line
// numbers nor machine-specific paths, the value is stable across line shifts,
// inserted comments and different machines, while distinct locations are
// never merged.
func (r *SarifReporter) stableFingerprint(f Finding, uri string, ordinal int) string {
	secretHash := sha256.Sum256([]byte(f.Secret))
	canonical := strings.Join([]string{
		f.RuleID,
		uri,
		fmt.Sprintf("%d", ordinal),
		hex.EncodeToString(secretHash[:]),
	}, "\n")

	fingerprint := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(fingerprint[:])
}

// artifactURI returns the slash-normalized URI of the finding's file
// relative to the scan root. Symlink paths are preferred to mirror the
// location the file was discovered at.
func (r *SarifReporter) artifactURI(f Finding) string {
	path := f.File
	if f.SymlinkFile != "" {
		path = f.SymlinkFile
	}
	return r.relativeURI(path)
}

// relativeURI makes path relative to the scan root and normalizes the path
// separator to "/". Git scans already yield repository-root-relative paths
// and stdin scans have no source, in which cases the slash-normalized path
// is used unchanged. When the path cannot be made relative to the root
// (for example paths on different volumes, or symlink targets outside the
// scan root), the slash-normalized path itself is returned rather than a
// URI containing "..".
func (r *SarifReporter) relativeURI(path string) string {
	uri := filepath.ToSlash(path)
	if r.Source == "" || path == "" {
		return uri
	}

	rel, err := filepath.Rel(filepath.Clean(r.Source), filepath.Clean(path))
	if err != nil {
		return uri
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return uri
	}
	return rel
}

func getLocation(f Finding, uri string) []Locations {
	return []Locations{
		{
			PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{
					URI: uri,
				},
				Region: Region{
					StartLine:   f.StartLine,
					EndLine:     f.EndLine,
					StartColumn: f.StartColumn,
					EndColumn:   f.EndColumn,
					Snippet: Snippet{
						Text: f.Secret,
					},
				},
			},
		},
	}
}

type PartialFingerPrints struct {
	CommitSha     string `json:"commitSha"`
	Email         string `json:"email"`
	Author        string `json:"author"`
	Date          string `json:"date"`
	CommitMessage string `json:"commitMessage"`
	Stable        string `json:"gitleaksFingerprint/v1"`
}

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}

type ShortDescription struct {
	Text string `json:"text"`
}

type FullDescription struct {
	Text string `json:"text"`
}

type Rules struct {
	ID          string           `json:"id"`
	Description ShortDescription `json:"shortDescription"`
}

type Driver struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	InformationUri  string  `json:"informationUri"`
	Rules           []Rules `json:"rules"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Message struct {
	Text string `json:"text"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int     `json:"startLine"`
	StartColumn int     `json:"startColumn"`
	EndLine     int     `json:"endLine"`
	EndColumn   int     `json:"endColumn"`
	Snippet     Snippet `json:"snippet"`
}

type Snippet struct {
	Text string `json:"text"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type Properties struct {
	Tags []string `json:"tags"`
}

type Results struct {
	Message             Message     `json:"message"`
	RuleId              string      `json:"ruleId"`
	Locations           []Locations `json:"locations"`
	PartialFingerPrints `json:"partialFingerprints"`
	Properties          Properties `json:"properties"`
}

type Runs struct {
	Tool    Tool      `json:"tool"`
	Results []Results `json:"results"`
}
