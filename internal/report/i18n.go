package report

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Language represents a supported localization code.
type Language string

const (
	// LangEnglish renders the report in English.
	LangEnglish Language = "en"
	// LangTurkish renders the report in Turkish.
	LangTurkish Language = "tr"
)

// ErrUnsupportedLanguage is returned when an unknown language code is requested.
var ErrUnsupportedLanguage = errors.New("report: unsupported language")

//go:embed en.json tr.json
var localeFS embed.FS

var locales = map[Language]map[string]string{}

func init() {
	mustLoadLocale(LangEnglish, "en.json")
	mustLoadLocale(LangTurkish, "tr.json")
}

func mustLoadLocale(lang Language, file string) {
	data, err := localeFS.ReadFile(file)
	if err != nil {
		panic(fmt.Sprintf("report: load locale %s: %v", lang, err))
	}
	var parsed map[string]string
	if err := json.Unmarshal(data, &parsed); err != nil {
		panic(fmt.Sprintf("report: parse locale %s: %v", lang, err))
	}
	locales[lang] = parsed
}

// Translator resolves localized strings for a specific language.
type Translator struct {
	lang Language
	data map[string]string
}

// NewTranslator builds a translator for the requested language, falling back to English.
func NewTranslator(lang Language) Translator {
	data, ok := locales[lang]
	if !ok {
		lang = LangEnglish
		data = locales[LangEnglish]
	}
	return Translator{lang: lang, data: data}
}

// Lang returns the active language.
func (t Translator) Lang() Language {
	return t.lang
}

// T returns the localized string for the provided key.
func (t Translator) T(key string) string {
	if val, ok := t.data[key]; ok {
		return val
	}
	if t.lang != LangEnglish {
		if val, ok := locales[LangEnglish][key]; ok {
			return val
		}
	}
	return key
}

// Format returns the localized string for the key formatted with the given arguments.
func (t Translator) Format(key string, args ...interface{}) string {
	return fmt.Sprintf(t.T(key), args...)
}

// ParseLanguage converts a flag value into a supported Language.
func ParseLanguage(lang string) (Language, error) {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "", "en", "en-us", "en-gb", "english":
		return LangEnglish, nil
	case "tr", "tr-tr", "turkish", "türkçe", "turkce":
		return LangTurkish, nil
	default:
		return LangEnglish, fmt.Errorf("%w: %s", ErrUnsupportedLanguage, lang)
	}
}
