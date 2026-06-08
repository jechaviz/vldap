module vldap

fn test_ber_roundtrip_decodes_nested_values() {
	packet := ber_sequence(ber_integer(2), ber_app(1, join_bytes([
		ber_enumerated(0),
		ber_octet(''),
		ber_octet('ok'),
	])))
	decoded := decode_ber(packet)!
	assert decoded.tag == 0x30
	assert decoded.children[0].int_value() == 2
	assert decoded.children[1].tag == 0x61
	assert decoded.children[1].children[2].string_value() == 'ok'
}

fn test_filter_parser_encodes_teedy_ldap_filter() {
	filter := parse_filter('(&(objectclass=inetOrgPerson)(uid=ldap1))')!
	assert filter.kind == 'and'
	assert filter.children.len == 2
	encoded := filter.encode()!
	decoded := decode_ber(encoded)!
	assert decoded.tag == 0xa0
	assert filter_debug(decoded) == '(&(objectclass=inetOrgPerson)(uid=ldap1))'
}
