use crate::config::{DesyncConfig, SplitConfig};
use crate::packets::{is_tls_chello, find_sni_offset, find_http_host_offset};
use std::io;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
pub struct DesyncEngine {
    config: DesyncConfig,
}

impl DesyncEngine {
    pub fn new(config: DesyncConfig) -> Self {
        Self { config }
    }
    
    /// Apply desync techniques to outgoing data
    pub async fn apply_desync<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        buffer: &[u8],
    ) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        
        // Check if this is TLS ClientHello
        let is_tls = is_tls_chello(buffer);
        
        // Apply split techniques
        if !self.config.split.is_empty() {
            return self.apply_split(stream, buffer, is_tls).await;
        }
        
        // Apply disorder techniques
        if !self.config.disorder.is_empty() {
            return self.apply_disorder(stream, buffer, is_tls).await;
        }
        
        // Apply fake packet techniques
        if !self.config.fake.is_empty() {
            return self.apply_fake(stream, buffer, is_tls).await;
        }
        
        // Default: send normally
        stream.write_all(buffer).await?;
        stream.flush().await?;
        Ok(buffer.len())
    }
    
    async fn apply_split<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        buffer: &[u8],
        is_tls: bool,
    ) -> io::Result<usize> {
        let mut total_sent = 0;
        let mut last_pos = 0;
        
        for split_cfg in &self.config.split {
            let pos = self.calculate_offset(split_cfg, buffer, is_tls)?;
            
            if pos > last_pos && pos <= buffer.len() {
                // Send chunk from last_pos to pos
                stream.write_all(&buffer[last_pos..pos]).await?;
                stream.flush().await?;
                total_sent += pos - last_pos;
                last_pos = pos;
            }
        }
        
        // Send remaining data
        if last_pos < buffer.len() {
            stream.write_all(&buffer[last_pos..]).await?;
            stream.flush().await?;
            total_sent += buffer.len() - last_pos;
        }
        
        Ok(total_sent)
    }
    
    async fn apply_disorder<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        buffer: &[u8],
        is_tls: bool,
    ) -> io::Result<usize> {
        // For disorder, we send parts out of order
        // This is a simplified version - full implementation would use TTL manipulation
        let mut total_sent = 0;
        let mut positions: Vec<usize> = vec![0];
        
        for disorder_cfg in &self.config.disorder {
            let pos = self.calculate_offset(disorder_cfg, buffer, is_tls)?;
            if pos <= buffer.len() {
                positions.push(pos);
            }
        }
        positions.push(buffer.len());
        positions.sort();
        positions.dedup();
        
        // Send in reverse order (simplified - real implementation uses TTL=1)
        for i in (1..positions.len()).rev() {
            let start = positions[i - 1];
            let end = positions[i];
            stream.write_all(&buffer[start..end]).await?;
            stream.flush().await?;
            total_sent += end - start;
        }
        
        Ok(total_sent)
    }
    
    async fn apply_fake<W: AsyncWriteExt + Unpin>(
        &self,
        stream: &mut W,
        buffer: &[u8],
        is_tls: bool,
    ) -> io::Result<usize> {
        // Simplified fake implementation
        // Real implementation would send fake packet with low TTL first
        for fake_cfg in &self.config.fake {
            let pos = self.calculate_offset(&fake_cfg.split, buffer, is_tls)?;
            
            if let Some(fake_data) = &fake_cfg.data {
                // Send fake data first (simplified)
                if fake_data.len() <= pos {
                    stream.write_all(&fake_data[..fake_data.len().min(pos)]).await?;
                    stream.flush().await?;
                }
            }
            
            // Then send real data
            stream.write_all(buffer).await?;
            stream.flush().await?;
            return Ok(buffer.len());
        }
        
        // Fallback
        stream.write_all(buffer).await?;
        stream.flush().await?;
        Ok(buffer.len())
    }
    
    fn calculate_offset(
        &self,
        split_cfg: &SplitConfig,
        buffer: &[u8],
        is_tls: bool,
    ) -> io::Result<usize> {
        let mut offset = split_cfg.offset;
        
        // Handle negative offsets (relative to end)
        if offset < 0 {
            offset = buffer.len() as i64 + offset;
        }
        
        // Apply flags
        if split_cfg.flags.sni && is_tls {
            if let Some(sni_offset) = find_sni_offset(buffer) {
                offset += sni_offset as i64;
            }
        }
        
        if split_cfg.flags.host {
            if let Some(host_offset) = find_http_host_offset(buffer) {
                offset += host_offset as i64;
            }
        }
        
        if split_cfg.flags.middle {
            offset = offset / 2;
        }
        
        if split_cfg.flags.end {
            offset = buffer.len() as i64 - offset;
        }
        
        let pos = offset.max(0) as usize;
        Ok(pos.min(buffer.len()))
    }
}

