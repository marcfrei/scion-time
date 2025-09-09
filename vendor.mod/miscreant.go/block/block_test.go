package block

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"
)

type MultiplyByXExample struct {
	input  []byte
	output []byte
}

// Load MultiplyByX test vectors from mult_by_x.tjson
// TODO: switch to a native Go TJSON parser when available
func loadMultiplyByXExamples() []MultiplyByXExample {
	var examplesJSON map[string]interface{}

	exampleData, err := ioutil.ReadFile("../vectors/mult_by_x.tjson")
	if err != nil {
		panic(err)
	}

	if err = json.Unmarshal(exampleData, &examplesJSON); err != nil {
		panic(err)
	}

	examplesArray := examplesJSON["examples:A<O>"].([]interface{})

	if examplesArray == nil {
		panic("no toplevel 'examples:A<O>' key in mult_by_x.tjson")
	}

	result := make([]MultiplyByXExample, len(examplesArray))

	for i, exampleJSON := range examplesArray {
		example := exampleJSON.(map[string]interface{})

		inputHex := example["input:d16"].(string)
		input := make([]byte, hex.DecodedLen(len(inputHex)))

		if _, err := hex.Decode(input, []byte(inputHex)); err != nil {
			panic(err)
		}

		outputHex := example["output:d16"].(string)
		output := make([]byte, hex.DecodedLen(len(outputHex)))

		if _, err := hex.Decode(output, []byte(outputHex)); err != nil {
			panic(err)
		}

		result[i] = MultiplyByXExample{input, output}
	}

	return result
}

func TestMultiplyByX(t *testing.T) {
	for i, tt := range loadMultiplyByXExamples() {
		var b Block
		copy(b[:], tt.input)
		b.MultiplyByX()

		if !bytes.Equal(b[:], tt.output) {
			t.Errorf("test %d: MultiplyByX mismatch\n\twant %x\n\thave %x", i, tt.output, b)
			continue
		}
	}
}
