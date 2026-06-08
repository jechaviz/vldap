module vldap

const ldap_scope_subtree = 2
const ldap_deref_never = 0
const ldap_result_success = 0

pub struct LdapEntry {
pub:
	dn         string
	attributes map[string][]string
}

pub struct SearchPacket {
pub:
	has_entry bool
	entry     LdapEntry
	done      bool
}

pub fn bind_request(message_id int, dn string, password string) []u8 {
	return ldap_message(message_id, ber_app(0, join_bytes([
		ber_integer(3),
		ber_octet(dn),
		ber_context_primitive(0, password.bytes()),
	])))
}

pub fn search_request(message_id int, base_dn string, filter string, attributes []string) ![]u8 {
	mut attr_parts := [][]u8{}
	for attr in attributes {
		attr_parts << ber_octet(attr)
	}
	request := join_bytes([
		ber_octet(base_dn),
		ber_enumerated(ldap_scope_subtree),
		ber_enumerated(ldap_deref_never),
		ber_integer(0),
		ber_integer(0),
		ber_boolean(false),
		encode_filter(filter)!,
		ber_sequence(...attr_parts),
	])
	return ldap_message(message_id, ber_app(3, request))
}

pub fn bind_response(message_id int, result_code int, message string) []u8 {
	return ldap_message(message_id, ber_app(1, join_bytes([
		ber_enumerated(result_code),
		ber_octet(''),
		ber_octet(message),
	])))
}

pub fn search_entry_response(message_id int, dn string, attrs map[string][]string) []u8 {
	mut attr_parts := [][]u8{}
	for key, values in attrs {
		mut value_parts := [][]u8{}
		for value in values {
			value_parts << ber_octet(value)
		}
		attr_parts << ber_sequence(ber_octet(key), ber_set(...value_parts))
	}
	return ldap_message(message_id, ber_app(4, join_bytes([ber_octet(dn),
		ber_sequence(...attr_parts)])))
}

pub fn search_done_response(message_id int, result_code int, message string) []u8 {
	return ldap_message(message_id, ber_app(5, join_bytes([
		ber_enumerated(result_code),
		ber_octet(''),
		ber_octet(message),
	])))
}

pub fn parse_bind_result(packet BerValue) ! {
	op := ldap_operation(packet)!
	if op.tag != 0x61 {
		return error('expected LDAP bind response')
	}
	code := ldap_result_code(op)!
	if code != ldap_result_success {
		return error(ldap_diagnostic(op, 'LDAP bind failed'))
	}
}

pub fn parse_search_packet(packet BerValue) !SearchPacket {
	op := ldap_operation(packet)!
	if op.tag == 0x64 {
		return SearchPacket{
			has_entry: true
			entry:     parse_search_entry(op)!
		}
	}
	if op.tag == 0x65 {
		code := ldap_result_code(op)!
		if code != ldap_result_success {
			return error(ldap_diagnostic(op, 'LDAP search failed'))
		}
		return SearchPacket{
			done: true
		}
	}
	return error('unexpected LDAP search response')
}

pub fn parse_bind_request(packet BerValue) !(string, string) {
	op := ldap_operation(packet)!
	if op.tag != 0x60 || op.children.len < 3 {
		return error('expected LDAP bind request')
	}
	return op.children[1].string_value(), op.children[2].string_value()
}

pub fn parse_search_request_filter(packet BerValue) !string {
	op := ldap_operation(packet)!
	if op.tag != 0x63 || op.children.len < 7 {
		return error('expected LDAP search request')
	}
	return filter_debug(op.children[6])
}

pub fn ldap_message_id(packet BerValue) !int {
	if packet.tag != 0x30 || packet.children.len < 2 {
		return error('expected LDAP message')
	}
	return packet.children[0].int_value()
}

fn ldap_message(message_id int, protocol_op []u8) []u8 {
	return ber_sequence(ber_integer(message_id), protocol_op)
}

fn ldap_operation(packet BerValue) !BerValue {
	if packet.tag != 0x30 || packet.children.len < 2 {
		return error('expected LDAP message')
	}
	return packet.children[1]
}

fn ldap_result_code(op BerValue) !int {
	if op.children.len < 1 {
		return error('missing LDAP result code')
	}
	return op.children[0].int_value()
}

fn ldap_diagnostic(op BerValue, fallback string) string {
	if op.children.len >= 3 && op.children[2].string_value() != '' {
		return op.children[2].string_value()
	}
	return fallback
}

fn parse_search_entry(op BerValue) !LdapEntry {
	if op.children.len < 2 {
		return error('invalid LDAP search entry')
	}
	mut attrs := map[string][]string{}
	for attr in op.children[1].children {
		if attr.children.len < 2 {
			continue
		}
		key := attr.children[0].string_value().to_lower()
		mut values := []string{}
		for value in attr.children[1].children {
			values << value.string_value()
		}
		attrs[key] = values
	}
	return LdapEntry{
		dn:         op.children[0].string_value()
		attributes: attrs
	}
}

fn filter_debug(value BerValue) string {
	if value.tag == 0xa0 || value.tag == 0xa1 {
		operator := if value.tag == 0xa0 { '&' } else { '|' }
		mut out := '(${operator}'
		for child in value.children {
			out += filter_debug(child)
		}
		return out + ')'
	}
	if value.tag == 0xa2 && value.children.len == 1 {
		return '(!${filter_debug(value.children[0])})'
	}
	if value.tag == 0xa3 && value.children.len >= 2 {
		return '(${value.children[0].string_value()}=${value.children[1].string_value()})'
	}
	return '(unsupported=filter)'
}
