module vldap

import net
import net.ssl
import time

pub struct ClientConfig {
pub:
	host       string
	port       int = 389
	use_ssl    bool
	bind_dn    string
	password   string
	timeout_ms int = 30_000
}

pub struct UserAuthRequest {
pub:
	username   string
	password   string
	base_dn    string
	filter     string
	attributes []string = ['mail']
}

pub struct Client {
mut:
	tcp        &net.TcpConn = unsafe { nil }
	tls        &ssl.SSLConn = unsafe { nil }
	use_ssl    bool
	message_id int = 1
}

pub fn authenticate_user(config ClientConfig, request UserAuthRequest) !LdapEntry {
	mut client := connect(config)!
	defer {
		client.close() or {}
	}
	client.bind(config.bind_dn, config.password)!
	entries := client.search(request.base_dn, request.filter, request.attributes)!
	if entries.len == 0 {
		return error('LDAP user not found')
	}
	client.bind(entries[0].dn, request.password)!
	return entries[0]
}

pub fn connect(config ClientConfig) !Client {
	clean := validate_client_config(config)!
	timeout := timeout_duration(clean)
	if clean.use_ssl {
		mut tls := ssl.new_ssl_conn(ssl.SSLConnectConfig{
			validate: false
		})!
		tls.set_read_timeout(timeout)
		tls.dial(clean.host, clean.port)!
		return Client{
			tls:     tls
			use_ssl: true
		}
	}
	mut conn := net.dial_tcp('${clean.host}:${clean.port}')!
	conn.set_read_timeout(timeout)
	conn.set_write_timeout(timeout)
	return Client{
		tcp: conn
	}
}

pub fn (mut client Client) bind(dn string, password string) ! {
	message_id := client.next_message_id()
	client.write_packet(bind_request(message_id, dn, password))!
	packet := client.read_packet()!
	if ldap_message_id(packet)! != message_id {
		return error('LDAP bind response id mismatch')
	}
	parse_bind_result(packet)!
}

pub fn (mut client Client) search(base_dn string, filter string, attributes []string) ![]LdapEntry {
	message_id := client.next_message_id()
	client.write_packet(search_request(message_id, base_dn, filter, attributes)!)!
	mut entries := []LdapEntry{}
	for {
		packet := client.read_packet()!
		if ldap_message_id(packet)! != message_id {
			return error('LDAP search response id mismatch')
		}
		search_packet := parse_search_packet(packet)!
		if search_packet.has_entry {
			entries << search_packet.entry
		}
		if search_packet.done {
			return entries
		}
	}
	return entries
}

pub fn (mut client Client) close() ! {
	if client.use_ssl {
		if !isnil(client.tls) {
			client.tls.shutdown()!
		}
		return
	}
	if !isnil(client.tcp) {
		client.tcp.close()!
	}
}

fn (mut client Client) next_message_id() int {
	id := client.message_id
	client.message_id++
	return id
}

fn (mut client Client) write_packet(packet []u8) ! {
	written := if client.use_ssl {
		client.tls.write(packet)!
	} else {
		client.tcp.write(packet)!
	}
	if written != packet.len {
		return error('short LDAP write')
	}
}

fn (mut client Client) read_packet() !BerValue {
	mut header := []u8{len: 2}
	client.read_exact(mut header)!
	mut length_cursor := BerCursor{
		pos: 1
	}
	length := read_ber_length(header, mut length_cursor) or {
		if header[1] & 0x80 == 0 {
			return err
		}
		count := int(header[1] & 0x7f)
		mut extra := []u8{len: count}
		client.read_exact(mut extra)!
		mut len_bytes := [header[1]]
		len_bytes << extra
		mut cursor := BerCursor{}
		read_ber_length(len_bytes, mut cursor)!
	}
	mut packet := []u8{cap: length + 5}
	packet << header[0]
	packet << ber_length(length)
	mut content := []u8{len: length}
	client.read_exact(mut content)!
	packet << content
	return decode_ber(packet)
}

fn (mut client Client) read_exact(mut buffer []u8) ! {
	mut offset := 0
	for offset < buffer.len {
		read_count := if client.use_ssl {
			client.tls.read(mut buffer[offset..])!
		} else {
			client.tcp.read(mut buffer[offset..])!
		}
		if read_count <= 0 {
			return error('LDAP connection closed')
		}
		offset += read_count
	}
}

fn validate_client_config(config ClientConfig) !ClientConfig {
	if config.host.trim_space() == '' {
		return error('LDAP host is required')
	}
	if config.port <= 0 {
		return error('LDAP port is required')
	}
	return ClientConfig{
		host:       config.host.trim_space()
		port:       config.port
		use_ssl:    config.use_ssl
		bind_dn:    config.bind_dn.trim_space()
		password:   config.password
		timeout_ms: config.timeout_ms
	}
}

fn timeout_duration(config ClientConfig) time.Duration {
	timeout_ms := if config.timeout_ms <= 0 { 30_000 } else { config.timeout_ms }
	return timeout_ms * time.millisecond
}
