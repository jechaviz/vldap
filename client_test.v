module vldap

import net
import time

fn test_authenticate_user_runs_teedy_ldap_bind_search_bind_flow() {
	port := 14389
	mut listener := net.listen_tcp(.ip, '127.0.0.1:${port}')!
	defer {
		listener.close() or {}
	}
	spawn fake_ldap_server(mut listener)
	time.sleep(50 * time.millisecond)

	entry := authenticate_user(ClientConfig{
		host:     '127.0.0.1'
		port:     port
		bind_dn:  'uid=admin,ou=system'
		password: 'secret'
	}, UserAuthRequest{
		username: 'ldap1'
		password: 'secret'
		base_dn:  'o=TEST'
		filter:   '(&(objectclass=inetOrgPerson)(uid=ldap1))'
	})!
	assert entry.dn == 'uid=ldap1,o=TEST'
	assert entry.attributes['mail'][0] == 'ldap1@teedy.io'
}

fn fake_ldap_server(mut listener net.TcpListener) {
	mut conn := listener.accept() or { return }
	defer {
		conn.close() or {}
	}
	conn.set_read_timeout(3000 * time.millisecond)
	for step in 0 .. 3 {
		packet := fake_read_packet(mut conn) or { return }
		message_id := ldap_message_id(packet) or { return }
		if step == 0 {
			dn, password := parse_bind_request(packet) or { return }
			if dn == 'uid=admin,ou=system' && password == 'secret' {
				conn.write(bind_response(message_id, 0, '')) or { return }
			} else {
				conn.write(bind_response(message_id, 49, 'invalid credentials')) or { return }
			}
		} else if step == 1 {
			filter := parse_search_request_filter(packet) or { return }
			if filter.contains('(uid=ldap1)') {
				conn.write(search_entry_response(message_id, 'uid=ldap1,o=TEST', {
					'mail': ['ldap1@teedy.io']
				})) or { return }
			}
			conn.write(search_done_response(message_id, 0, '')) or { return }
		} else {
			dn, password := parse_bind_request(packet) or { return }
			code := if dn == 'uid=ldap1,o=TEST' && password == 'secret' { 0 } else { 49 }
			conn.write(bind_response(message_id, code, '')) or { return }
		}
	}
}

fn fake_read_packet(mut conn net.TcpConn) !BerValue {
	mut header := []u8{len: 2}
	fake_read_exact(mut conn, mut header)!
	mut length := int(header[1])
	mut len_prefix := [header[1]]
	if header[1] & 0x80 != 0 {
		count := int(header[1] & 0x7f)
		mut extra := []u8{len: count}
		fake_read_exact(mut conn, mut extra)!
		len_prefix << extra
		mut cursor := BerCursor{}
		length = read_ber_length(len_prefix, mut cursor)!
	}
	mut content := []u8{len: length}
	fake_read_exact(mut conn, mut content)!
	mut packet := [header[0]]
	packet << len_prefix
	packet << content
	return decode_ber(packet)
}

fn fake_read_exact(mut conn net.TcpConn, mut buffer []u8) ! {
	mut offset := 0
	for offset < buffer.len {
		read_count := conn.read(mut buffer[offset..])!
		if read_count <= 0 {
			return error('connection closed')
		}
		offset += read_count
	}
}
