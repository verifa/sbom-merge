package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/spdx/tools-golang/convert"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Not enough arguments, pass as args at least 2 SBOM files to be merged")
	}

	finalSbomFileName := os.Args[1]
	finalSbomFile, err := os.Open(finalSbomFileName)
	if err != nil {
		log.Fatalf("cannot open file %s: %w", finalSbomFileName, err)
	}
	finalSpdxDoc, err := Read(finalSbomFile)
	if err != nil {
		log.Fatalf("cannot convert %s to SPDX: %w", finalSbomFileName, err)
	}

	// merge into the finalSbom all the files that come after it in arguments
	for _, v := range os.Args[2:] {
		sbomFile, err := os.Open(v)
		if err != nil {
			log.Fatalf("cannot open file %s: %w", v, err)
		}
		spdxDoc, err := Read(sbomFile)
		if err != nil {
			log.Fatalf("cannot convert %s to SPDX: %w", v, err)
		}
		finalSpdxDoc.Packages = append(finalSpdxDoc.Packages, spdxDoc.Packages...)
		finalSpdxDoc.Files = append(finalSpdxDoc.Files, spdxDoc.Files...)
		finalSpdxDoc.Relationships = append(finalSpdxDoc.Relationships, spdxDoc.Relationships...)
		finalSpdxDoc.OtherLicenses = append(finalSpdxDoc.OtherLicenses, spdxDoc.OtherLicenses...)
		// These two are not present in either SBOM that I'm dealing with right now
		// but might be useful in future:
		finalSpdxDoc.Snippets = append(finalSpdxDoc.Snippets, spdxDoc.Snippets...)
		finalSpdxDoc.Annotations = append(finalSpdxDoc.Annotations, spdxDoc.Annotations...)
		// ExternalDocumentReferences does not seem relevant right now, one big SBOM rather
	}

	finalJsonSpdx, _ := json.MarshalIndent(finalSpdxDoc, "", "  ")
	fmt.Println(string(finalJsonSpdx))
}

// Read takes an io.Reader and returns a fully-parsed current model SPDX Document
// or an error if any error is encountered.
func Read(content io.Reader) (*spdx.Document, error) {
	doc := spdx.Document{}
	err := ReadInto(content, &doc)
	return &doc, err
}

// ReadInto takes an io.Reader, reads in the SPDX document at the version provided
// and converts to the doc version
func ReadInto(content io.Reader, doc common.AnyDocument) error {
	if !convert.IsPtr(doc) {
		return fmt.Errorf("doc to read into must be a pointer")
	}

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(content)
	if err != nil {
		return err
	}

	var data interface{}
	err = json.Unmarshal(buf.Bytes(), &data)
	if err != nil {
		return err
	}

	val, ok := data.(map[string]interface{})
	if !ok {
		return fmt.Errorf("not a valid SPDX JSON document")
	}

	version, ok := val["spdxVersion"]
	if !ok {
		return fmt.Errorf("JSON document does not contain spdxVersion field")
	}

	if version == v2_3.Version {
		var doc v2_3.Document
		err = json.Unmarshal(buf.Bytes(), &doc)
		if err != nil {
			return err
		}
		data = doc
	} else {
		return fmt.Errorf("unsupported SDPX version: %s", version)
	}

	return convert.Document(data, doc)
}
