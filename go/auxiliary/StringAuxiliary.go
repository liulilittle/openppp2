package auxiliary

import (
	"regexp"
	"strings"

	"github.com/google/uuid"
)

type StringAuxiliary struct{}

const _STRING_TRIM_CHARATERS = " \t\n\r"

func (*StringAuxiliary) NewGUID() string {
	guid := uuid.New()
	return guid.String()
}

func (*StringAuxiliary) LTrim(v string) string {
	return strings.TrimLeft(v, _STRING_TRIM_CHARATERS)
}

func (*StringAuxiliary) RTrim(v string) string {
	return strings.TrimRight(v, _STRING_TRIM_CHARATERS)
}

func (*StringAuxiliary) Trim(v string) string {
	return strings.Trim(v, _STRING_TRIM_CHARATERS)
}

func (*StringAuxiliary) IsGuid(v string) bool {
	if v == "" {
		return false
	}

	pattern := `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[4][0-9a-fA-F]{3}-[89ABab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(v)
}
