package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Ops a leaf may take (ADR 0077 point 4).
const (
	OpEq       = "eq"
	OpContains = "contains"
	OpHas      = "has"
)

// Rule is `all` or `any` over leaves, judged on one event of the job (ADR 0078 point 4).
type Rule struct {
	All    bool
	Leaves []Leaf
}

// Leaf compares the value at Field in an event.
type Leaf struct {
	Field []string
	Op    string
	Value any // string or json.Number holding an integer; nil for has
}

// The built-in controls (ADR 0077 point 5, acceptance control_empty and control_all).
var (
	ControlEmpty = Rule{All: false}
	ControlAll   = Rule{All: true}
)

func decodeRule(v any) (Rule, error) {
	o, ok := v.(object)
	if !ok || len(o) != 1 {
		return Rule{}, errors.New("a rule is one of all or any")
	}
	var r Rule
	var list any
	if l, ok := o["all"]; ok {
		r.All, list = true, l
	} else if l, ok := o["any"]; ok {
		list = l
	} else {
		return Rule{}, errors.New("a rule is one of all or any")
	}
	leaves, ok := list.([]any)
	if !ok {
		return Rule{}, errors.New("a rule's leaves are a list")
	}
	for i, lv := range leaves {
		leaf, err := decodeLeaf(lv)
		if err != nil {
			return Rule{}, fmt.Errorf("leaf %d: %w", i, err)
		}
		r.Leaves = append(r.Leaves, leaf)
	}
	return r, nil
}

func decodeLeaf(v any) (Leaf, error) {
	o, err := fields(v, []string{"field", "op"}, []string{"value"})
	if err != nil {
		return Leaf{}, err
	}
	var leaf Leaf
	path, ok := o["field"].([]any)
	if !ok || len(path) == 0 {
		return Leaf{}, errors.New("field is a non-empty list of keys")
	}
	for _, step := range path {
		s, ok := step.(string)
		if !ok || s == "" {
			return Leaf{}, errors.New("field is a list of non-empty keys")
		}
		leaf.Field = append(leaf.Field, s)
	}
	leaf.Op, _ = str(o, "op")
	value, hasValue := o["value"]
	switch leaf.Op {
	case OpHas:
		if hasValue {
			return Leaf{}, errors.New("has takes no value")
		}
	case OpEq, OpContains:
		switch x := value.(type) {
		case string:
			leaf.Value = x
		case json.Number:
			if leaf.Op != OpEq || !integerLiteral.MatchString(string(x)) {
				return Leaf{}, errors.New("a number is an integer, for eq only")
			}
			leaf.Value = x
		default:
			return Leaf{}, errors.New("eq and contains take a string or an integer")
		}
	default:
		return Leaf{}, fmt.Errorf("op %q unknown", leaf.Op)
	}
	return leaf, nil
}

// matches reports whether one of the job's events satisfies the whole rule (ADR 0078 point 4).
func (r Rule) matches(events []object) bool {
	for _, ev := range events {
		if r.holds(ev) {
			return true
		}
	}
	return false
}

func (r Rule) holds(ev object) bool {
	if r.All {
		for _, l := range r.Leaves {
			if !l.holds(ev) {
				return false
			}
		}
		return true
	}
	for _, l := range r.Leaves {
		if l.holds(ev) {
			return true
		}
	}
	return false
}

func (l Leaf) holds(ev object) bool {
	return reach(ev, l.Field, func(v any) bool { return l.test(v) })
}

// reach follows path from v; a step that meets a list goes into each element; it reports whether test holds
// for some value the whole path reaches (ADR 0079 point 4).
func reach(v any, path []string, test func(any) bool) bool {
	if list, ok := v.([]any); ok {
		for _, el := range list {
			if reach(el, path, test) {
				return true
			}
		}
		return false
	}
	if len(path) == 0 {
		return test(v)
	}
	o, ok := v.(object)
	if !ok {
		return false
	}
	next, ok := o[path[0]]
	if !ok {
		return false
	}
	return reach(next, path[1:], test)
}

// test is the leaf's op on one value the path reached; reach never hands it a list, and an empty list reaches
// nothing, so `has` holds on a value that is not null.
func (l Leaf) test(v any) bool {
	switch l.Op {
	case OpHas:
		return v != nil
	case OpEq:
		switch want := l.Value.(type) {
		case string:
			got, ok := v.(string)
			return ok && got == want
		case json.Number:
			got, ok := v.(json.Number)
			return ok && integerLiteral.MatchString(string(got)) && got == want
		}
	case OpContains:
		want, _ := l.Value.(string)
		got, ok := v.(string)
		return ok && strings.Contains(got, want)
	}
	return false
}
