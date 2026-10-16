//! CDN server discovery through Steam's public WebAPI
//! (`IContentServerDirectoryService/GetServersForSteamPipe`).
//!
//! No Steam login is required for this endpoint: with no `cell_id` provided Steam answers with
//! servers appropriate for the caller's IP geolocation, i.e. "the closest CDN" for free.

use prost::Message;
use steam_protobuf_rs::CContentServerDirectoryGetServersForSteamPipeResponse;

use crate::error::{Error, Result};

const DIRECTORY_URL: &str = "https://api.steampowered.com/IContentServerDirectoryService/GetServersForSteamPipe/v1/?format=protobuf_raw";

/// One usable Steam CDN/cache server.
///
/// Public so callers can inject explicit servers (LAN caches, test fixtures) through
/// [`crate::DepotDownloaderBuilder::cdn_servers`].
#[derive(Clone, Debug)]
pub struct CdnServer {
    /// Hostname or `host:port`.
    pub host: String,
    pub port: u16,
    pub https: bool,
    /// Load metric; lower is preferred (DepotDownloader's ordering).
    pub weighted_load: f32,
    /// When non-empty, the server only serves these app ids.
    pub allowed_app_ids: Vec<u32>,
}

impl CdnServer {
    /// Plain-HTTP server from an `host[:port]` address (tests, LAN caches).
    pub fn http(address: &str) -> Result<Self> {
        Self::from_address(address, false)
    }

    /// HTTPS server from an `host[:port]` address.
    pub fn https(address: &str) -> Result<Self> {
        Self::from_address(address, true)
    }

    fn from_address(address: &str, https: bool) -> Result<Self> {
        let default_port = if https { 443 } else { 80 };
        let (host, port) = match address.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| {
                    Error::InvalidConfig(format!("invalid port in CDN address '{address}'"))
                })?;
                (host.to_owned(), port)
            }
            None => (address.to_owned(), default_port),
        };
        if host.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "invalid CDN address '{address}'"
            )));
        }
        Ok(CdnServer {
            host,
            port,
            https,
            weighted_load: 0.0,
            allowed_app_ids: Vec::new(),
        })
    }

    /// Whether this server serves content for `app_id`.
    pub fn serves_app(&self, app_id: u32) -> bool {
        self.allowed_app_ids.is_empty() || self.allowed_app_ids.contains(&app_id)
    }

    pub(crate) fn chunk_url(&self, depot_id: u32, chunk_hex: &str) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!(
            "{}://{}:{}/depot/{depot_id}/chunk/{chunk_hex}",
            scheme, self.host, self.port
        )
    }

    fn from_proto(server: steam_protobuf_rs::CContentServerDirectoryServerInfo) -> Option<Self> {
        let ty = server.r#type.unwrap_or_default();
        if ty != "SteamCache" && ty != "CDN" {
            return None;
        }
        if server.steam_china_only.unwrap_or(false) {
            return None;
        }

        let host = server
            .vhost
            .filter(|v| !v.is_empty())
            .or(server.host)
            .filter(|h| !h.is_empty())?;

        // `https_support` is a string: "mandatory"/"prefer" → 443/TLS, anything else → 80/plain.
        let https = matches!(
            server.https_support.as_deref(),
            Some("mandatory") | Some("prefer")
        );

        Some(CdnServer {
            host,
            port: if https { 443 } else { 80 },
            https,
            weighted_load: server.weighted_load.unwrap_or(f32::MAX),
            allowed_app_ids: server.allowed_app_ids,
        })
    }
}

/// Query Steam's public content server directory.
///
/// Returns usable servers sorted by ascending weighted load (matching DepotDownloader's
/// effective pick order), excluding China-only hosts and non-cache server types.
pub(crate) async fn fetch_servers(http: &reqwest::Client) -> Result<Vec<CdnServer>> {
    let response = http.get(DIRECTORY_URL).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::HttpStatus {
            status: status.as_u16(),
            url: DIRECTORY_URL.to_owned(),
        });
    }
    let bytes = response.bytes().await?;

    let decoded = CContentServerDirectoryGetServersForSteamPipeResponse::decode(bytes.as_ref())
        .map_err(|e| Error::CdnDirectory(format!("protobuf decode failed: {e}")))?;

    let mut servers: Vec<CdnServer> = decoded
        .servers
        .into_iter()
        .filter_map(CdnServer::from_proto)
        .collect();
    servers.sort_by(|a, b| {
        a.weighted_load
            .partial_cmp(&b.weighted_load)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if servers.is_empty() {
        return Err(Error::NoCdnServers);
    }
    Ok(servers)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use steam_protobuf_rs::CContentServerDirectoryServerInfo;

    #[test]
    fn proto_mapping_filters_and_sorts() {
        let response = CContentServerDirectoryGetServersForSteamPipeResponse {
            servers: vec![
                // skippable: wrong type
                CContentServerDirectoryServerInfo {
                    r#type: Some("CM".to_owned()),
                    host: Some("cm.example".to_owned()),
                    ..Default::default()
                },
                // skippable: china only
                CContentServerDirectoryServerInfo {
                    r#type: Some("CDN".to_owned()),
                    host: Some("china.example".to_owned()),
                    steam_china_only: Some(true),
                    ..Default::default()
                },
                CContentServerDirectoryServerInfo {
                    r#type: Some("CDN".to_owned()),
                    host: Some("b.example".to_owned()),
                    weighted_load: Some(2.0),
                    https_support: Some("mandatory".to_owned()),
                    ..Default::default()
                },
                CContentServerDirectoryServerInfo {
                    r#type: Some("SteamCache".to_owned()),
                    host: Some("a.example".to_owned()),
                    weighted_load: Some(1.0),
                    ..Default::default()
                },
            ],
            no_change: None,
        };
        let decoded = CContentServerDirectoryGetServersForSteamPipeResponse::decode(
            response.encode_to_vec().as_slice(),
        )
        .expect("decode");
        let mut servers: Vec<CdnServer> = decoded
            .servers
            .into_iter()
            .filter_map(CdnServer::from_proto)
            .collect();
        servers.sort_by(|a, b| {
            a.weighted_load
                .partial_cmp(&b.weighted_load)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].host, "a.example");
        assert_eq!(servers[0].port, 80);
        assert!(!servers[0].https);
        assert_eq!(servers[1].host, "b.example");
        assert_eq!(servers[1].port, 443);
        assert!(servers[1].https);
    }

    #[test]
    fn urls_are_shaped_like_steamkit() {
        let server = CdnServer::http("cache.example:8080").expect("addr");
        assert_eq!(
            server.chunk_url(731, "00ab"),
            "http://cache.example:8080/depot/731/chunk/00ab"
        );
        let secure = CdnServer::https("cdn.example").expect("addr");
        assert!(
            secure
                .chunk_url(731, "00ab")
                .starts_with("https://cdn.example:443/")
        );
    }
}
