use std::io;

/// Check if buffer contains a TLS ClientHello
pub fn is_tls_chello(buffer: &[u8]) -> bool {
    if buffer.len() < 5 {
        return false;
    }
    
    // TLS record header: ContentType(1) | Version(2) | Length(2)
    let content_type = buffer[0];
    let version = u16::from_be_bytes([buffer[1], buffer[2]]);
    
    // Content type 0x16 = Handshake
    // Version 0x0301, 0x0302, 0x0303, 0x0304 = TLS 1.0-1.3
    content_type == 0x16 && version >= 0x0301 && version <= 0x0304
}

/// Check if buffer contains HTTP request
pub fn is_http(buffer: &[u8]) -> bool {
    if buffer.len() < 4 {
        return false;
    }
    
    // Check for common HTTP methods
    let methods = [
        b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"CONN", b"TRAC", b"PATC"
    ];
    
    methods.iter().any(|&method| buffer.starts_with(method))
}

/// Parse HTTP CONNECT request and extract host:port
pub fn parse_http_connect(buffer: &[u8]) -> Option<(String, u16)> {
    let s = std::str::from_utf8(buffer).ok()?;
    let lines: Vec<&str> = s.lines().collect();
    
    if lines.is_empty() {
        return None;
    }
    
    // Parse CONNECT line: "CONNECT host:port HTTP/1.1"
    let connect_line = lines[0];
    if !connect_line.starts_with("CONNECT ") {
        return None;
    }
    
    let parts: Vec<&str> = connect_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    
    let host_port = parts[1];
    let colon_pos = host_port.find(':')?;
    let host = host_port[..colon_pos].to_string();
    let port: u16 = host_port[colon_pos + 1..].parse().ok()?;
    
    Some((host, port))
}

/// Find SNI offset in TLS ClientHello
pub fn find_sni_offset(buffer: &[u8]) -> Option<usize> {
    if !is_tls_chello(buffer) || buffer.len() < 43 {
        return None;
    }
    
    // Skip TLS record header (5 bytes)
    let mut offset = 5;
    
    // Skip Handshake header (4 bytes)
    if buffer.len() < offset + 4 {
        return None;
    }
    offset += 4;
    
    // Skip ClientVersion (2 bytes)
    offset += 2;
    
    // Skip Random (32 bytes)
    offset += 32;
    
    // Skip SessionID length + SessionID
    if buffer.len() < offset + 1 {
        return None;
    }
    let session_id_len = buffer[offset] as usize;
    offset += 1 + session_id_len;
    
    // Skip CipherSuites length + CipherSuites
    if buffer.len() < offset + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    
    // Skip CompressionMethods length + CompressionMethods
    if buffer.len() < offset + 1 {
        return None;
    }
    let compression_len = buffer[offset] as usize;
    offset += 1 + compression_len;
    
    // Now we're at Extensions
    if buffer.len() < offset + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) as usize;
    offset += 2;
    
    let extensions_end = offset + extensions_len;
    while offset < extensions_end && offset < buffer.len() - 4 {
        let ext_type = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]);
        offset += 2;
        
        if buffer.len() < offset + 2 {
            break;
        }
        let ext_len = u16::from_be_bytes([buffer[offset], buffer[offset + 1]]) as usize;
        offset += 2;
        
        // Extension type 0x0000 = Server Name Indication
        if ext_type == 0x0000 {
            if buffer.len() < offset + 3 {
                break;
            }
            // Skip ServerNameList length
            offset += 2;
            // Skip NameType (1 byte, should be 0x00 for hostname)
            if buffer[offset] == 0x00 {
                offset += 1;
                // Skip HostName length (2 bytes)
                if buffer.len() >= offset + 2 {
                    return Some(offset + 2);
                }
            }
            break;
        }
        
        offset += ext_len;
    }
    
    None
}

/// Find HTTP Host header offset
pub fn find_http_host_offset(buffer: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(buffer).ok()?;
    let host_header = "Host: ";
    
    s.find(host_header).map(|pos| pos + host_header.len())
}

/// Split TLS record at specified position
pub fn split_tls_record(buffer: &mut Vec<u8>, position: usize) -> io::Result<()> {
    if buffer.len() < position + 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Position too close to end of buffer"
        ));
    }
    
    // Get original record length
    let original_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    
    // Calculate split point
    let first_part_len = position - 5; // Exclude header
    let second_part_len = original_len - first_part_len;
    
    // Create new TLS record header for second part
    let new_header = [
        buffer[0],           // ContentType
        buffer[1], buffer[2], // Version
        (second_part_len >> 8) as u8,
        second_part_len as u8,
    ];
    
    // Update original record length
    buffer[3] = (first_part_len >> 8) as u8;
    buffer[4] = first_part_len as u8;
    
    // Insert new header before second part
    buffer.splice(position..position, new_header.iter().cloned());
    
    Ok(())
}

