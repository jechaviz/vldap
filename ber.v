module vldap

pub struct BerValue {
pub:
	tag      u8
	content  []u8
	children []BerValue
}

pub struct BerCursor {
pub mut:
	pos int
}

pub fn ber_sequence(parts ...[]u8) []u8 {
	return ber_tlv(0x30, join_bytes(parts))
}

pub fn ber_set(parts ...[]u8) []u8 {
	return ber_tlv(0x31, join_bytes(parts))
}

pub fn ber_app(tag_number int, content []u8) []u8 {
	return ber_tlv(u8(0x60 + tag_number), content)
}

pub fn ber_context_primitive(tag_number int, content []u8) []u8 {
	return ber_tlv(u8(0x80 + tag_number), content)
}

pub fn ber_context_constructed(tag_number int, content []u8) []u8 {
	return ber_tlv(u8(0xa0 + tag_number), content)
}

pub fn ber_integer(value int) []u8 {
	return ber_tlv(0x02, positive_int_bytes(value))
}

pub fn ber_enumerated(value int) []u8 {
	return ber_tlv(0x0a, positive_int_bytes(value))
}

pub fn ber_boolean(value bool) []u8 {
	return ber_tlv(0x01, [u8(if value { 0xff } else { 0x00 })])
}

pub fn ber_octet(value string) []u8 {
	return ber_tlv(0x04, value.bytes())
}

pub fn ber_octet_bytes(value []u8) []u8 {
	return ber_tlv(0x04, value)
}

pub fn ber_tlv(tag u8, content []u8) []u8 {
	mut out := []u8{cap: 1 + content.len + 4}
	out << tag
	out << ber_length(content.len)
	out << content
	return out
}

pub fn ber_length(length int) []u8 {
	if length < 0 {
		return []u8{}
	}
	if length < 128 {
		return [u8(length)]
	}
	mut bytes := []u8{}
	if length <= 0xff {
		bytes = [u8(length)]
	} else if length <= 0xffff {
		bytes = [u8((length >> 8) & 0xff), u8(length & 0xff)]
	} else {
		bytes = [u8((length >> 16) & 0xff), u8((length >> 8) & 0xff), u8(length & 0xff)]
	}
	mut out := [u8(0x80 | bytes.len)]
	out << bytes
	return out
}

pub fn decode_ber(bytes []u8) !BerValue {
	mut cursor := BerCursor{}
	value := read_ber_value(bytes, mut cursor)!
	if cursor.pos != bytes.len {
		return error('trailing BER bytes')
	}
	return value
}

pub fn read_ber_value(bytes []u8, mut cursor BerCursor) !BerValue {
	if cursor.pos >= bytes.len {
		return error('missing BER tag')
	}
	tag := bytes[cursor.pos]
	cursor.pos++
	length := read_ber_length(bytes, mut cursor)!
	if cursor.pos + length > bytes.len {
		return error('BER value length exceeds packet')
	}
	content := bytes[cursor.pos..cursor.pos + length].clone()
	cursor.pos += length
	mut children := []BerValue{}
	if ber_is_constructed(tag) {
		mut child_cursor := BerCursor{}
		for child_cursor.pos < content.len {
			children << read_ber_value(content, mut child_cursor)!
		}
	}
	return BerValue{
		tag:      tag
		content:  content
		children: children
	}
}

pub fn read_ber_length(bytes []u8, mut cursor BerCursor) !int {
	if cursor.pos >= bytes.len {
		return error('missing BER length')
	}
	first := bytes[cursor.pos]
	cursor.pos++
	if first & 0x80 == 0 {
		return int(first)
	}
	count := int(first & 0x7f)
	if count == 0 || count > 4 || cursor.pos + count > bytes.len {
		return error('unsupported BER length')
	}
	mut length := u32(0)
	for _ in 0 .. count {
		length = (length << 8) | u32(bytes[cursor.pos])
		cursor.pos++
	}
	return int(length)
}

pub fn (value BerValue) int_value() int {
	mut out := u32(0)
	for b in value.content {
		out = (out << 8) | u32(b)
	}
	return int(out)
}

pub fn (value BerValue) string_value() string {
	return value.content.bytestr()
}

fn ber_is_constructed(tag u8) bool {
	return tag == 0x30 || tag == 0x31 || (tag & 0x20) != 0
}

fn positive_int_bytes(value int) []u8 {
	if value <= 0 {
		return [u8(0)]
	}
	if value <= 0x7f {
		return [u8(value)]
	}
	if value <= 0xff {
		return [u8(0), u8(value)]
	}
	if value <= 0x7fff {
		return [u8((value >> 8) & 0xff), u8(value & 0xff)]
	}
	if value <= 0xffff {
		return [u8(0), u8((value >> 8) & 0xff), u8(value & 0xff)]
	}
	return [u8((value >> 16) & 0xff), u8((value >> 8) & 0xff), u8(value & 0xff)]
}

fn join_bytes(parts [][]u8) []u8 {
	mut total := 0
	for part in parts {
		total += part.len
	}
	mut out := []u8{cap: total}
	for part in parts {
		out << part
	}
	return out
}
