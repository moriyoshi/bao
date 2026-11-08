package bindings

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"go/token"
	"strings"
	"unicode"

	"github.com/moriyoshi/bao/internal/ar"
	"github.com/moriyoshi/bao/pecoff"
)

// Infer reads source-level DWARF from original object/archive bytes. Explicitly
// selected exports assert that their public ABI is C: DWARF does not reliably
// distinguish Rust's native ABI from extern C. Unwind tables alone contain no
// signature information. No debug companion files or source paths are opened.
func Infer(name string, input []byte, symbols []string) (Manifest, error) {
	m := Manifest{Schema: 1, ABI: "c"}
	if len(symbols) == 0 {
		return m, fmt.Errorf("DWARF inference requires explicitly selected C ABI exports")
	}
	wanted := map[string]bool{}
	for _, s := range symbols {
		if !token.IsIdentifier(s) || s == "_" || wanted[s] {
			return m, fmt.Errorf("invalid or duplicate selected C ABI export %q", s)
		}
		wanted[s] = true
	}
	members := []ar.Member{{Name: name, Data: input}}
	if bytes.HasPrefix(input, []byte("!<arch>\n")) {
		var err error
		members, err = ar.Parse(input)
		if err != nil {
			return m, err
		}
	}
	found := map[string]Function{}
	for _, member := range members {
		data, exports, err := objectDWARF(member.Data, wanted)
		if err != nil {
			return m, fmt.Errorf("DWARF %s: %w", member.Name, err)
		}
		if len(exports) == 0 {
			continue
		}
		if data == nil {
			return m, fmt.Errorf("selected exports in %s have no source-level DWARF", member.Name)
		}
		tree, err := readDwarfTree(data)
		if err != nil {
			return m, fmt.Errorf("DWARF %s: %w", member.Name, err)
		}
		for symbol := range exports {
			if _, exists := found[symbol]; exists {
				return m, fmt.Errorf("ambiguous export %q is defined in multiple archive members", symbol)
			}
			function, err := tree.function(symbol)
			if err != nil {
				return m, fmt.Errorf("DWARF %s: %w", member.Name, err)
			}
			found[symbol] = function
		}
	}
	for _, s := range symbols {
		function, ok := found[s]
		if !ok {
			return m, fmt.Errorf("selected C ABI function %q has no external object definition", s)
		}
		m.Functions = append(m.Functions, function)
	}
	return m, m.Validate()
}

func objectDWARF(input []byte, wanted map[string]bool) (*dwarf.Data, map[string]bool, error) {
	exports := map[string]bool{}
	if _, err := pecoff.Machine(input); err == nil {
		f, err := pe.NewFile(bytes.NewReader(input))
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		for _, s := range f.Symbols {
			if !wanted[s.Name] || s.StorageClass != 2 || s.SectionNumber <= 0 {
				continue
			}
			if int(s.SectionNumber) > len(f.Sections) || f.Sections[s.SectionNumber-1].Characteristics&pe.IMAGE_SCN_CNT_CODE == 0 || s.Type&0x30 != 0x20 {
				return nil, nil, fmt.Errorf("selected COFF export %q is not a native function", s.Name)
			}
			if exports[s.Name] {
				return nil, nil, fmt.Errorf("duplicate COFF definition %s", s.Name)
			}
			exports[s.Name] = true
		}
		if len(exports) == 0 || f.Section(".debug_info") == nil {
			return nil, exports, nil
		}
		d, err := pecoff.DWARF(input)
		return d, exports, err
	}
	if bytes.HasPrefix(input, []byte{0x7f, 'E', 'L', 'F'}) {
		f, err := elf.NewFile(bytes.NewReader(input))
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		if f.Type != elf.ET_REL || f.Class != elf.ELFCLASS64 {
			return nil, nil, fmt.Errorf("requires an ELF64 relocatable object")
		}
		syms, err := f.Symbols()
		if err != nil {
			return nil, nil, err
		}
		for _, s := range syms {
			if !wanted[s.Name] || s.Section == elf.SHN_UNDEF || elf.ST_BIND(s.Info) == elf.STB_LOCAL {
				continue
			}
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
				return nil, nil, fmt.Errorf("selected export %q is not a native function", s.Name)
			}
			if exports[s.Name] {
				return nil, nil, fmt.Errorf("duplicate native function definition %q", s.Name)
			}
			exports[s.Name] = true
		}
		if len(exports) == 0 {
			return nil, exports, nil
		}
		if f.Section(".debug_info") == nil && f.Section(".zdebug_info") == nil {
			return nil, exports, nil
		}
		data, err := f.DWARF()
		return data, exports, err
	}
	f, err := macho.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, nil, fmt.Errorf("requires a Mach-O/ELF relocatable object: %w", err)
	}
	defer f.Close()
	if f.Type != macho.TypeObj || f.Magic != macho.Magic64 || f.Symtab == nil {
		return nil, nil, fmt.Errorf("requires a Mach-O64 relocatable object with symbols")
	}
	for _, s := range f.Symtab.Syms {
		name := strings.TrimPrefix(s.Name, "_")
		if !wanted[name] || s.Type&0xe0 != 0 || s.Type&1 == 0 || s.Sect == 0 {
			continue
		}
		if int(s.Sect) > len(f.Sections) || f.Sections[s.Sect-1].Flags&0x80000400 == 0 {
			return nil, nil, fmt.Errorf("selected export %q is not native text", name)
		}
		if exports[name] {
			return nil, nil, fmt.Errorf("duplicate native function definition %q", name)
		}
		exports[name] = true
	}
	if len(exports) == 0 {
		return nil, exports, nil
	}
	if f.Section("__debug_info") == nil && f.Section("__zdebug_info") == nil {
		return nil, exports, nil
	}
	data, err := f.DWARF()
	return data, exports, err
}

type dwarfUnit struct {
	language int64
	types    int
}
type dwarfNode struct {
	entry    dwarf.Entry
	children []*dwarfNode
	unit     *dwarfUnit
}
type dwarfTree struct {
	nodes     map[dwarf.Offset]*dwarfNode
	functions []*dwarfNode
}

func readDwarfTree(data *dwarf.Data) (*dwarfTree, error) {
	t := &dwarfTree{nodes: map[dwarf.Offset]*dwarfNode{}}
	reader := data.Reader()
	var stack []*dwarfNode
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		if entry.Tag == 0 {
			if len(stack) == 0 {
				return nil, fmt.Errorf("unbalanced DWARF child terminator")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		node := &dwarfNode{entry: *entry}
		if len(stack) > 0 {
			parent := stack[len(stack)-1]
			node.unit = parent.unit
			parent.children = append(parent.children, node)
		}
		if entry.Tag == dwarf.TagCompileUnit || entry.Tag == dwarf.TagPartialUnit {
			node.unit = &dwarfUnit{language: integer(entry.Val(dwarf.AttrLanguage))}
		}
		if node.unit == nil {
			node.unit = &dwarfUnit{}
		}
		if isTypeTag(entry.Tag) {
			node.unit.types++
		}
		t.nodes[entry.Offset] = node
		if entry.Tag == dwarf.TagSubprogram {
			t.functions = append(t.functions, node)
		}
		if entry.Children {
			stack = append(stack, node)
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unterminated DWARF children")
	}
	return t, nil
}

func isTypeTag(tag dwarf.Tag) bool {
	switch tag {
	case dwarf.TagBaseType, dwarf.TagPointerType, dwarf.TagReferenceType, dwarf.TagRvalueReferenceType, dwarf.TagTypedef, dwarf.TagStructType, dwarf.TagUnionType, dwarf.TagArrayType, dwarf.TagSubroutineType, dwarf.TagEnumerationType:
		return true
	}
	return false
}
func integer(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	case int:
		return int64(v)
	}
	return 0
}

func (t *dwarfTree) lineage(node *dwarfNode) ([]*dwarfNode, error) {
	var result []*dwarfNode
	seen := map[dwarf.Offset]bool{}
	active := map[dwarf.Offset]bool{}
	var walk func(*dwarfNode, int) error
	walk = func(n *dwarfNode, depth int) error {
		if depth > 128 || active[n.entry.Offset] {
			return fmt.Errorf("cyclic/deep DWARF origin or specification")
		}
		if seen[n.entry.Offset] {
			return nil
		}
		seen[n.entry.Offset] = true
		active[n.entry.Offset] = true
		result = append(result, n)
		for _, attr := range []dwarf.Attr{dwarf.AttrAbstractOrigin, dwarf.AttrSpecification} {
			if value := n.entry.Val(attr); value != nil {
				off, ok := value.(dwarf.Offset)
				if !ok || t.nodes[off] == nil {
					return fmt.Errorf("invalid DWARF origin/specification reference")
				}
				if err := walk(t.nodes[off], depth+1); err != nil {
					return err
				}
			}
		}
		active[n.entry.Offset] = false
		return nil
	}
	err := walk(node, 0)
	return result, err
}
func (t *dwarfTree) attr(node *dwarfNode, attr dwarf.Attr) (any, error) {
	lineage, err := t.lineage(node)
	if err != nil {
		return nil, err
	}
	for _, n := range lineage {
		if value := n.entry.Val(attr); value != nil {
			return value, nil
		}
	}
	return nil, nil
}
func (t *dwarfTree) functionName(n *dwarfNode) (string, error) {
	for _, attr := range []dwarf.Attr{dwarf.AttrLinkageName, dwarf.Attr(0x2007), dwarf.AttrName} {
		value, err := t.attr(n, attr)
		if err != nil {
			return "", err
		}
		if name, ok := value.(string); ok && name != "" {
			return name, nil
		}
	}
	return "", nil
}

func (t *dwarfTree) function(symbol string) (Function, error) {
	var match *dwarfNode
	var signature Function
	var identity dwarf.Offset
	for _, n := range t.functions {
		// GCC can fold identical exported bodies into one address and retain
		// only a typed declaration/abstract record for the alias. Actual
		// external text definitions were checked against the object symbols;
		// a PC range is not required to recover the declared signature.
		name, err := t.functionName(n)
		if err != nil {
			return Function{}, err
		}
		if name != symbol {
			continue
		}
		lineage, err := t.lineage(n)
		if err != nil {
			return Function{}, err
		}
		root := lineage[len(lineage)-1].entry.Offset
		if match != nil && root != identity {
			return Function{}, fmt.Errorf("ambiguous independent DWARF definitions for %q", symbol)
		}
		current, err := t.signature(n)
		if err != nil {
			return Function{}, fmt.Errorf("%s: %w", symbol, err)
		}
		if match != nil && !sameSignature(current, signature) {
			return Function{}, fmt.Errorf("conflicting DWARF signatures for %q", symbol)
		}
		match = n
		identity = root
		signature = current
	}
	if match == nil {
		return Function{}, fmt.Errorf("selected function %q has no source-level DWARF signature", symbol)
	}
	f := signature
	f.Symbol = symbol
	f.Name = exportedName(symbol)
	return f, nil
}

func sameSignature(a, b Function) bool {
	if !sameScalar(a.Result, b.Result) || len(a.Params) != len(b.Params) {
		return false
	}
	for i, p := range a.Params {
		if !sameScalar(p, b.Params[i]) {
			return false
		}
	}
	return true
}

func exportedName(symbol string) string {
	var result []rune
	upper := true
	for _, r := range symbol {
		if r == '_' {
			upper = true
			continue
		}
		if upper {
			r = unicode.ToUpper(r)
			upper = false
		}
		result = append(result, r)
	}
	if len(result) == 0 || !unicode.IsUpper(result[0]) {
		return "Native" + string(result)
	}
	return string(result)
}

func parameters(n *dwarfNode) ([]*dwarfNode, bool) {
	var params []*dwarfNode
	variadic := false
	for _, child := range n.children {
		if child.entry.Tag == dwarf.TagFormalParameter {
			params = append(params, child)
		}
		variadic = variadic || child.entry.Tag == dwarf.TagUnspecifiedParameters
	}
	return params, variadic
}

func (t *dwarfTree) signature(node *dwarfNode) (Function, error) {
	lineage, err := t.lineage(node)
	if err != nil {
		return Function{}, err
	}
	var declared []*dwarfNode
	for _, n := range lineage {
		if cc := n.entry.Val(dwarf.AttrCalling); cc != nil && integer(cc) != 1 {
			return Function{}, fmt.Errorf("unsupported DWARF calling convention %d", integer(cc))
		}
		params, variadic := parameters(n)
		if variadic {
			return Function{}, fmt.Errorf("variadic/unspecified parameters require an explicit supported ABI")
		}
		if len(params) >= len(declared) {
			declared = params
		}
	}
	f := Function{Params: []string{}, Result: "void"}
	for _, param := range declared {
		artificial, err := t.attr(param, dwarf.AttrArtificial)
		if err != nil {
			return f, err
		}
		if artificial == true {
			return f, fmt.Errorf("artificial/implicit parameter cannot be inferred")
		}
		value, err := t.attr(param, dwarf.AttrType)
		if err != nil {
			return f, err
		}
		typ, err := t.scalarReference(value, false, map[dwarf.Offset]bool{})
		if err != nil {
			return f, err
		}
		f.Params = append(f.Params, typ)
	}
	// Optimization can omit concrete parameter DIEs. Their origins identify
	// declaration order; a same-arity standalone list is compared by position.
	for _, n := range lineage {
		params, _ := parameters(n)
		for i, param := range params {
			which := -1
			origins, err := t.lineage(param)
			if err != nil {
				return f, err
			}
			for j, base := range declared {
				for _, origin := range origins {
					if origin.entry.Offset == base.entry.Offset {
						which = j
					}
				}
			}
			if which < 0 && len(params) == len(declared) {
				which = i
			}
			if which < 0 {
				return f, fmt.Errorf("optimized parameter order cannot be established")
			}
			value, err := t.attr(param, dwarf.AttrType)
			if err != nil {
				return f, err
			}
			typ, err := t.scalarReference(value, false, map[dwarf.Offset]bool{})
			if err != nil {
				return f, err
			}
			if !sameScalar(typ, f.Params[which]) {
				return f, fmt.Errorf("conflicting declaration/optimized parameter types")
			}
		}
	}
	value, err := t.attr(node, dwarf.AttrType)
	if err != nil {
		return f, err
	}
	if value != nil {
		f.Result, err = t.scalarReference(value, true, map[dwarf.Offset]bool{})
		if err != nil {
			return f, err
		}
	} else {
		prototype, err := t.attr(node, dwarf.AttrPrototyped)
		if err != nil {
			return f, err
		}
		if prototype != true && len(declared) == 0 && node.unit.types == 0 {
			return f, fmt.Errorf("no complete type evidence for a zero-argument void signature; use full DWARF or a manifest")
		}
	}
	for _, n := range lineage {
		if own := n.entry.Val(dwarf.AttrType); own != nil {
			typ, err := t.scalarReference(own, true, map[dwarf.Offset]bool{})
			if err != nil {
				return f, err
			}
			if !sameScalar(typ, f.Result) {
				return f, fmt.Errorf("conflicting declaration/optimized result types")
			}
		}
	}
	return f, nil
}

func sameScalar(a, b string) bool {
	return a == b || a == "uintptr" && b == "uint64" || b == "uintptr" && a == "uint64"
}

func (t *dwarfTree) scalarReference(value any, result bool, active map[dwarf.Offset]bool) (string, error) {
	off, ok := value.(dwarf.Offset)
	if !ok || t.nodes[off] == nil {
		return "", fmt.Errorf("missing/unsupported DWARF type reference")
	}
	if active[off] || len(active) > 128 {
		return "", fmt.Errorf("cyclic/deep DWARF type")
	}
	active[off] = true
	defer delete(active, off)
	n := t.nodes[off]
	name, _ := n.entry.Val(dwarf.AttrName).(string)
	switch n.entry.Tag {
	case dwarf.TagTypedef, dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType, dwarf.TagAtomicType, dwarf.TagImmutableType:
		underlying, err := t.scalarReference(n.entry.Val(dwarf.AttrType), result, active)
		if err != nil {
			return "", err
		}
		if (name == "uintptr_t" || name == "size_t" || name == "usize") && underlying == "uint64" {
			return "uintptr", nil
		}
		return underlying, nil
	case dwarf.TagPointerType, dwarf.TagReferenceType, dwarf.TagRvalueReferenceType:
		if size := n.entry.Val(dwarf.AttrByteSize); size != nil && integer(size) != 8 {
			return "", fmt.Errorf("non-native-width pointer/reference")
		}
		if cls := n.entry.Val(dwarf.AttrAddrClass); cls != nil && integer(cls) != 0 {
			return "", fmt.Errorf("non-default pointer address class")
		}
		if t.callbackType(n.entry.Val(dwarf.AttrType), map[dwarf.Offset]bool{}) {
			return "", fmt.Errorf("callback/function-pointer signatures require explicit callback support")
		}
		return "pointer", nil
	case dwarf.TagBaseType:
		size, encoding := integer(n.entry.Val(dwarf.AttrByteSize)), integer(n.entry.Val(dwarf.AttrEncoding))
		if bits := n.entry.Val(dwarf.AttrBitSize); bits != nil && integer(bits) != size*8 {
			return "", fmt.Errorf("non-byte scalar width")
		}
		prefix := ""
		switch encoding {
		case 5, 6:
			prefix = "int"
		case 7, 8:
			prefix = "uint"
		case 4:
			if size == 4 {
				return "float32", nil
			}
			if size == 8 {
				return "float64", nil
			}
		case 1:
			if size == 8 {
				return "uintptr", nil
			}
		}
		if prefix != "" && (size == 1 || size == 2 || size == 4 || size == 8) {
			if name == "usize" && prefix == "uint" && size == 8 {
				return "uintptr", nil
			}
			return fmt.Sprintf("%s%d", prefix, size*8), nil
		}
		return "", fmt.Errorf("unsupported base type %q (encoding %d, size %d)", name, encoding, size)
	case dwarf.TagUnspecifiedType:
		if result && (name == "void" || name == "()") {
			return "void", nil
		}
	case dwarf.TagStructType:
		if result && n.unit.language == 0x1c && name == "()" && integer(n.entry.Val(dwarf.AttrByteSize)) == 0 {
			return "void", nil
		}
	case dwarf.TagEnumerationType:
		if underlying := n.entry.Val(dwarf.AttrType); underlying != nil {
			return t.scalarReference(underlying, result, active)
		}
	}
	return "", fmt.Errorf("unsupported aggregate/function/opaque DWARF type %s %q", n.entry.Tag, name)
}

func (t *dwarfTree) callbackType(value any, seen map[dwarf.Offset]bool) bool {
	off, ok := value.(dwarf.Offset)
	if !ok || seen[off] || t.nodes[off] == nil {
		return false
	}
	seen[off] = true
	n := t.nodes[off]
	if n.entry.Tag == dwarf.TagSubroutineType {
		return true
	}
	switch n.entry.Tag {
	case dwarf.TagPointerType, dwarf.TagReferenceType, dwarf.TagRvalueReferenceType, dwarf.TagTypedef, dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType, dwarf.TagAtomicType, dwarf.TagImmutableType:
		return t.callbackType(n.entry.Val(dwarf.AttrType), seen)
	}
	return false
}
