module vldap

pub struct LdapFilter {
pub:
	kind     string
	attr     string
	value    string
	children []LdapFilter
}

struct FilterCursor {
mut:
	pos int
}

pub fn parse_filter(text string) !LdapFilter {
	clean := text.trim_space()
	if clean == '' {
		return error('LDAP filter is required')
	}
	mut cursor := FilterCursor{}
	filter := parse_filter_node(clean, mut cursor)!
	if cursor.pos != clean.len {
		return error('unexpected LDAP filter suffix')
	}
	return filter
}

pub fn encode_filter(text string) ![]u8 {
	return parse_filter(text)!.encode()
}

pub fn (filter LdapFilter) encode() ![]u8 {
	match filter.kind {
		'and' {
			return ber_context_constructed(0, encode_filter_children(filter.children)!)
		}
		'or' {
			return ber_context_constructed(1, encode_filter_children(filter.children)!)
		}
		'not' {
			if filter.children.len != 1 {
				return error('LDAP not filter requires one child')
			}
			return ber_context_constructed(2, filter.children[0].encode()!)
		}
		'eq' {
			return ber_context_constructed(3, join_bytes([ber_octet(filter.attr),
				ber_octet(filter.value)]))
		}
		else {
			return error('unsupported LDAP filter ${filter.kind}')
		}
	}
}

fn encode_filter_children(children []LdapFilter) ![]u8 {
	if children.len == 0 {
		return error('LDAP compound filter requires children')
	}
	mut parts := [][]u8{}
	for child in children {
		parts << child.encode()!
	}
	return join_bytes(parts)
}

fn parse_filter_node(text string, mut cursor FilterCursor) !LdapFilter {
	expect_char(text, mut cursor, `(`)!
	skip_spaces(text, mut cursor)
	if cursor.pos >= text.len {
		return error('unexpected end of LDAP filter')
	}
	operator := text[cursor.pos]
	if operator == `&` || operator == `|` {
		cursor.pos++
		mut children := []LdapFilter{}
		for {
			skip_spaces(text, mut cursor)
			if cursor.pos >= text.len {
				return error('unterminated LDAP compound filter')
			}
			if text[cursor.pos] == `)` {
				cursor.pos++
				break
			}
			children << parse_filter_node(text, mut cursor)!
		}
		return LdapFilter{
			kind:     if operator == `&` { 'and' } else { 'or' }
			children: children
		}
	}
	if operator == `!` {
		cursor.pos++
		child := parse_filter_node(text, mut cursor)!
		expect_char(text, mut cursor, `)`)!
		return LdapFilter{
			kind:     'not'
			children: [child]
		}
	}
	attr := read_until(text, mut cursor, `=`)!.trim_space()
	cursor.pos++
	value := read_until(text, mut cursor, `)`)!
	cursor.pos++
	if attr == '' {
		return error('LDAP equality filter attribute is required')
	}
	return LdapFilter{
		kind:  'eq'
		attr:  attr
		value: unescape_filter_value(value)
	}
}

fn expect_char(text string, mut cursor FilterCursor, expected u8) ! {
	if cursor.pos >= text.len || text[cursor.pos] != expected {
		return error('expected ${expected.ascii_str()} in LDAP filter')
	}
	cursor.pos++
}

fn skip_spaces(text string, mut cursor FilterCursor) {
	for cursor.pos < text.len && text[cursor.pos].is_space() {
		cursor.pos++
	}
}

fn read_until(text string, mut cursor FilterCursor, stop u8) !string {
	start := cursor.pos
	for cursor.pos < text.len && text[cursor.pos] != stop {
		cursor.pos++
	}
	if cursor.pos >= text.len {
		return error('unterminated LDAP filter value')
	}
	return text[start..cursor.pos]
}

fn unescape_filter_value(value string) string {
	mut out := ''
	mut i := 0
	for i < value.len {
		if value[i] == `\\` && i + 2 < value.len {
			hex := value[i + 1..i + 3]
			decoded := hex_to_byte(hex) or {
				out += value[i].ascii_str()
				i++
				continue
			}
			out += decoded.ascii_str()
			i += 3
			continue
		}
		out += value[i].ascii_str()
		i++
	}
	return out
}

fn hex_to_byte(value string) ?u8 {
	if value.len != 2 {
		return none
	}
	hi := hex_nibble(value[0])?
	lo := hex_nibble(value[1])?
	return u8((hi << 4) | lo)
}

fn hex_nibble(ch u8) ?u8 {
	if ch >= `0` && ch <= `9` {
		return u8(ch - `0`)
	}
	if ch >= `a` && ch <= `f` {
		return u8(ch - `a` + 10)
	}
	if ch >= `A` && ch <= `F` {
		return u8(ch - `A` + 10)
	}
	return none
}
