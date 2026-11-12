use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{header, request::Parts, HeaderMap, Method};

const MAX_USER_AGENT_CHARS: usize = 256;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientInfo {
    pub ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

impl ClientInfo {
    pub fn ip_string(&self) -> Option<String> {
        self.ip.map(|ip| ip.to_string())
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|info| info.0.ip());
        Ok(client_info(&parts.headers, peer, trust_proxy()))
    }
}

pub fn trust_proxy() -> bool {
    static TRUST: OnceLock<bool> = OnceLock::new();
    *TRUST.get_or_init(|| {
        std::env::var("DBX_WEB_TRUST_PROXY")
            .is_ok_and(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    })
}

pub fn client_info(headers: &HeaderMap, peer: Option<IpAddr>, trust_proxy: bool) -> ClientInfo {
    let forwarded = trust_proxy
        .then(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
                .or_else(|| headers.get("x-real-ip").and_then(|value| value.to_str().ok()))
                .and_then(|value| value.trim().parse::<IpAddr>().ok())
        })
        .flatten();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(MAX_USER_AGENT_CHARS).collect::<String>())
        .filter(|value| !value.is_empty());
    ClientInfo { ip: forwarded.or(peer), user_agent }
}

pub fn trusted_origins_from_env() -> Vec<String> {
    parse_trusted_origins(std::env::var("DBX_WEB_TRUSTED_ORIGINS").ok().as_deref())
}

pub fn parse_trusted_origins(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|origin| origin.trim().trim_end_matches('/').to_ascii_lowercase())
        .filter(|origin| !origin.is_empty())
        .collect()
}

fn header_str(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn normalize_authority(authority: &str) -> String {
    let authority = authority.trim().to_ascii_lowercase();
    authority.strip_suffix(":80").or_else(|| authority.strip_suffix(":443")).unwrap_or(&authority).to_string()
}

pub fn is_cross_site(method: &Method, headers: &HeaderMap, trusted_origins: &[String]) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    let origin = header_str(headers, header::ORIGIN).map(str::trim);
    if origin.is_some_and(|origin| {
        let origin = origin.trim_end_matches('/').to_ascii_lowercase();
        trusted_origins.contains(&origin)
    }) {
        return false;
    }
    if let Some(site) = header_str(headers, "sec-fetch-site") {
        return site.trim().eq_ignore_ascii_case("cross-site");
    }
    let Some(origin) = origin else {
        return false;
    };
    let Some((_, origin_authority)) = origin.split_once("://") else {
        return true;
    };
    let origin_authority = normalize_authority(origin_authority.trim_end_matches('/'));
    let candidates = [header_str(headers, header::HOST), header_str(headers, "x-forwarded-host")];
    !candidates.into_iter().flatten().any(|host| normalize_authority(host) == origin_authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn forwarded_address_is_used_only_when_the_proxy_is_trusted() {
        let peer: IpAddr = "172.17.0.1".parse().unwrap();
        let map = headers(&[("x-forwarded-for", "203.0.113.7, 10.0.0.1"), ("user-agent", "Firefox")]);
        assert_eq!(client_info(&map, Some(peer), false).ip, Some(peer));
        let trusted = client_info(&map, Some(peer), true);
        assert_eq!(trusted.ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(trusted.user_agent.as_deref(), Some("Firefox"));
        let garbage = headers(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(client_info(&garbage, Some(peer), true).ip, Some(peer));
    }

    #[test]
    fn safe_methods_are_never_cross_site_blocked() {
        let map = headers(&[("sec-fetch-site", "cross-site")]);
        assert!(!is_cross_site(&Method::GET, &map, &[]));
        assert!(is_cross_site(&Method::POST, &map, &[]));
    }

    #[test]
    fn fetch_metadata_decides_when_present() {
        for (site, blocked) in [("same-origin", false), ("same-site", false), ("none", false), ("cross-site", true)] {
            let map = headers(&[("sec-fetch-site", site), ("origin", "https://evil.example"), ("host", "dbx.local")]);
            assert_eq!(is_cross_site(&Method::POST, &map, &[]), blocked, "{site}");
        }
    }

    #[test]
    fn origin_must_match_host_without_fetch_metadata() {
        let same = headers(&[("origin", "http://dbx.local:4224"), ("host", "dbx.local:4224")]);
        assert!(!is_cross_site(&Method::POST, &same, &[]));
        let default_port = headers(&[("origin", "https://dbx.example.com"), ("host", "dbx.example.com:443")]);
        assert!(!is_cross_site(&Method::POST, &default_port, &[]));
        let proxied = headers(&[
            ("origin", "https://dbx.example.com"),
            ("host", "127.0.0.1:4224"),
            ("x-forwarded-host", "dbx.example.com"),
        ]);
        assert!(!is_cross_site(&Method::POST, &proxied, &[]));
        let foreign = headers(&[("origin", "https://evil.example"), ("host", "dbx.local")]);
        assert!(is_cross_site(&Method::DELETE, &foreign, &[]));
        let opaque = headers(&[("origin", "null"), ("host", "dbx.local")]);
        assert!(is_cross_site(&Method::POST, &opaque, &[]));
        assert!(!is_cross_site(&Method::POST, &HeaderMap::new(), &[]));
    }

    #[test]
    fn trusted_origins_are_allowed_explicitly() {
        let trusted = parse_trusted_origins(Some(" https://Portal.example/ , ,https://other.example"));
        assert_eq!(trusted, vec!["https://portal.example".to_string(), "https://other.example".to_string()]);
        let map = headers(&[("sec-fetch-site", "cross-site"), ("origin", "https://portal.example")]);
        assert!(!is_cross_site(&Method::POST, &map, &trusted));
    }
}
