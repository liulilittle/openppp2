package auxiliary

import "encoding/json"

type JsonAuxiliary struct{}

func (*JsonAuxiliary) Serialize(v any) string {
	json_bytes, err := json.Marshal(v)
	if err != nil {
		return ""
	}

	return string(json_bytes)
}

func (*JsonAuxiliary) Deserialize(json_string string, v any) bool {
	if json_string == "" {
		v = ""
		return true
	}

	err := json.Unmarshal([]byte(json_string), v)
	return err == nil
}
