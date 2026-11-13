use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const INVALID_CREDENTIALS: u32 = 49;
const DEFAULT_FILTER: &str = "(uid={username})";
const DEFAULT_USERNAME_ATTRIBUTE: &str = "uid";
const DEFAULT_DISPLAY_ATTRIBUTE: &str = "cn";
const SUBJECT_ATTRIBUTE: &str = "entryUUID";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    #[serde(default)]
    pub start_tls: bool,
    #[serde(default)]
    pub bind_dn: String,
    pub user_base_dn: String,
    #[serde(default)]
    pub user_filter: String,
    #[serde(default)]
    pub username_attribute: String,
    #[serde(default)]
    pub display_name_attribute: String,
}

impl LdapConfig {
    fn normalized(mut self) -> Self {
        self.url = self.url.trim().to_string();
        self.bind_dn = self.bind_dn.trim().to_string();
        self.user_base_dn = self.user_base_dn.trim().to_string();
        self.user_filter = self.user_filter.trim().to_string();
        self.username_attribute = self.username_attribute.trim().to_string();
        self.display_name_attribute = self.display_name_attribute.trim().to_string();
        self
    }

    fn filter(&self) -> &str {
        if self.user_filter.is_empty() {
            DEFAULT_FILTER
        } else {
            &self.user_filter
        }
    }

    fn username_attribute(&self) -> &str {
        if self.username_attribute.is_empty() {
            DEFAULT_USERNAME_ATTRIBUTE
        } else {
            &self.username_attribute
        }
    }

    fn display_name_attribute(&self) -> &str {
        if self.display_name_attribute.is_empty() {
            DEFAULT_DISPLAY_ATTRIBUTE
        } else {
            &self.display_name_attribute
        }
    }
}

fn balanced(filter: &str) -> bool {
    let mut depth = 0i32;
    for ch in filter.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

pub fn parse_config(value: &serde_json::Value) -> Result<LdapConfig, &'static str> {
    let config = serde_json::from_value::<LdapConfig>(value.clone())
        .map_err(|_| "identity_provider_config_invalid")?
        .normalized();
    let url_valid = (config.url.starts_with("ldap://") || config.url.starts_with("ldaps://"))
        && config.url.len() > "ldaps://".len()
        && !config.url.contains(char::is_whitespace);
    if !url_valid {
        return Err("ldap_url_invalid");
    }
    if config.user_base_dn.is_empty() {
        return Err("ldap_base_required");
    }
    let filter = config.filter();
    if !filter.contains("{username}") || !filter.starts_with('(') || !balanced(filter) {
        return Err("ldap_filter_invalid");
    }
    Ok(config)
}

pub fn validated_config(value: serde_json::Value) -> Result<serde_json::Value, &'static str> {
    let config = parse_config(&value)?;
    serde_json::to_value(config).map_err(|_| "identity_provider_config_invalid")
}

pub fn escape_filter_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '*' | '(' | ')' | '\0' => escaped.push_str(&format!("\\{:02x}", ch as u32)),
            other => escaped.push(other),
        }
    }
    escaped
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapIdentity {
    pub subject: String,
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapFailure {
    InvalidCredentials,
    Unavailable(String),
}

fn unavailable(error: impl std::fmt::Display) -> LdapFailure {
    LdapFailure::Unavailable(error.to_string())
}

async fn connect(config: &LdapConfig) -> Result<ldap3::Ldap, LdapFailure> {
    let settings = LdapConnSettings::new().set_conn_timeout(CONNECT_TIMEOUT).set_starttls(config.start_tls);
    let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &config.url).await.map_err(unavailable)?;
    ldap3::drive!(connection);
    ldap.with_timeout(OPERATION_TIMEOUT);
    Ok(ldap)
}

async fn bind_service(ldap: &mut ldap3::Ldap, config: &LdapConfig, secret: Option<&str>) -> Result<(), LdapFailure> {
    if config.bind_dn.is_empty() {
        return Ok(());
    }
    ldap.simple_bind(&config.bind_dn, secret.unwrap_or_default())
        .await
        .map_err(unavailable)?
        .success()
        .map(|_| ())
        .map_err(|error| unavailable(format!("service account bind failed: {error}")))
}

fn first_value(entry: &SearchEntry, attribute: &str) -> Option<String> {
    entry
        .attrs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(attribute))
        .and_then(|(_, values)| values.first())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub async fn authenticate(
    config_value: &serde_json::Value,
    secret: Option<&str>,
    username: &str,
    password: &str,
) -> Result<LdapIdentity, LdapFailure> {
    let config = parse_config(config_value).map_err(unavailable)?;
    let username = username.trim();
    if username.is_empty() || password.is_empty() {
        return Err(LdapFailure::InvalidCredentials);
    }
    let mut ldap = connect(&config).await?;
    bind_service(&mut ldap, &config, secret).await?;
    let filter = config.filter().replace("{username}", &escape_filter_value(username));
    let attributes = vec![config.username_attribute(), config.display_name_attribute(), SUBJECT_ATTRIBUTE];
    let (entries, _) = ldap
        .search(&config.user_base_dn, Scope::Subtree, &filter, attributes)
        .await
        .map_err(unavailable)?
        .success()
        .map_err(unavailable)?;
    if entries.len() != 1 {
        let _ = ldap.unbind().await;
        return Err(LdapFailure::InvalidCredentials);
    }
    let entry = SearchEntry::construct(entries.into_iter().next().expect("one entry"));
    let bound = ldap.simple_bind(&entry.dn, password).await.map_err(unavailable)?;
    let _ = ldap.unbind().await;
    if bound.rc == INVALID_CREDENTIALS {
        return Err(LdapFailure::InvalidCredentials);
    }
    bound.success().map_err(unavailable)?;
    Ok(LdapIdentity {
        subject: first_value(&entry, SUBJECT_ATTRIBUTE).unwrap_or_else(|| entry.dn.to_ascii_lowercase()),
        username: first_value(&entry, config.username_attribute()).unwrap_or_else(|| username.to_string()),
        display_name: first_value(&entry, config.display_name_attribute()),
    })
}

pub async fn test_connection(config_value: &serde_json::Value, secret: Option<&str>) -> Result<(), String> {
    let config = parse_config(config_value).map_err(str::to_string)?;
    let mut ldap = connect(&config).await.map_err(|failure| format!("{failure:?}"))?;
    bind_service(&mut ldap, &config, secret).await.map_err(|failure| format!("{failure:?}"))?;
    let result = ldap
        .search(&config.user_base_dn, Scope::Base, "(objectClass=*)", vec!["1.1"])
        .await
        .map_err(|error| error.to_string())?
        .success()
        .map(|_| ())
        .map_err(|error| error.to_string());
    let _ = ldap.unbind().await;
    result
}

#[cfg(test)]
pub(crate) mod test_server {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub const SERVICE_DN: &str = "cn=dbx,dc=example,dc=com";
    pub const SERVICE_SECRET: &str = "svc-secret";
    pub const BASE_DN: &str = "ou=people,dc=example,dc=com";

    struct Person {
        uid: &'static str,
        password: &'static str,
        name: &'static str,
        uuid: &'static str,
    }

    const PEOPLE: &[Person] = &[
        Person { uid: "ana", password: "ana-ldap", name: "Ana López", uuid: "uuid-ana" },
        Person { uid: "bob", password: "bob-ldap", name: "Bob", uuid: "uuid-bob" },
    ];

    fn dn(uid: &str) -> String {
        format!("uid={uid},{BASE_DN}")
    }

    fn read_tlv(buffer: &[u8]) -> Option<(u8, &[u8], usize)> {
        let tag = *buffer.first()?;
        let first = *buffer.get(1)?;
        let (length, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7f);
            let mut length = 0usize;
            for index in 0..count {
                length = (length << 8) | usize::from(*buffer.get(2 + index)?);
            }
            (length, 2 + count)
        };
        let content = buffer.get(header..header + length)?;
        Some((tag, content, header + length))
    }

    fn children(mut content: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut items = Vec::new();
        while let Some((tag, value, used)) = read_tlv(content) {
            items.push((tag, value.to_vec()));
            content = &content[used..];
        }
        items
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let length = content.len();
        if length < 0x80 {
            out.push(length as u8);
        } else {
            let bytes: Vec<u8> = length.to_be_bytes().into_iter().skip_while(|byte| *byte == 0).collect();
            out.push(0x80 | bytes.len() as u8);
            out.extend(bytes);
        }
        out.extend_from_slice(content);
        out
    }

    fn integer(value: &[u8]) -> Vec<u8> {
        tlv(0x02, value)
    }

    fn octets(value: &str) -> Vec<u8> {
        tlv(0x04, value.as_bytes())
    }

    fn result(tag: u8, code: u8) -> Vec<u8> {
        let mut content = tlv(0x0a, &[code]);
        content.extend(octets(""));
        content.extend(octets(""));
        tlv(tag, &content)
    }

    fn message(id: &[u8], operation: Vec<u8>) -> Vec<u8> {
        let mut content = integer(id);
        content.extend(operation);
        tlv(0x30, &content)
    }

    fn entry(person: &Person) -> Vec<u8> {
        let attribute = |name: &str, value: &str| {
            let mut content = octets(name);
            content.extend(tlv(0x31, &octets(value)));
            tlv(0x30, &content)
        };
        let mut attributes = attribute("uid", person.uid);
        attributes.extend(attribute("cn", person.name));
        attributes.extend(attribute("entryUUID", person.uuid));
        let mut content = octets(&dn(person.uid));
        content.extend(tlv(0x30, &attributes));
        tlv(0x64, &content)
    }

    fn matching(filter_tag: u8, filter: &[u8]) -> Vec<&'static Person> {
        let parts = children(filter);
        let text = |index: usize| {
            parts.get(index).map(|(_, value)| String::from_utf8_lossy(value).to_string()).unwrap_or_default()
        };
        match filter_tag {
            0x87 => PEOPLE.iter().collect(),
            0xa3 if text(0) == "uid" => PEOPLE.iter().filter(|person| person.uid == text(1)).collect(),
            0xa4 => {
                let prefix = parts
                    .get(1)
                    .map(|(_, value)| children(value))
                    .and_then(|subs| subs.first().map(|(_, initial)| String::from_utf8_lossy(initial).to_string()))
                    .unwrap_or_default();
                PEOPLE.iter().filter(|person| person.uid.starts_with(&prefix)).collect()
            }
            _ => Vec::new(),
        }
    }

    #[derive(Clone, Default)]
    pub struct Recorded {
        pub filters: Arc<Mutex<Vec<u8>>>,
        pub binds: Arc<Mutex<Vec<String>>>,
    }

    async fn serve_connection(mut stream: tokio::net::TcpStream, recorded: Recorded) {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            while let Some((_, content, used)) = read_tlv(&buffer) {
                let parts = children(content);
                buffer.drain(..used);
                let (Some((_, id)), Some((operation, body))) = (parts.first(), parts.get(1)) else {
                    return;
                };
                let reply = match *operation {
                    0x60 => {
                        let fields = children(body);
                        let name = String::from_utf8_lossy(&fields[1].1).to_string();
                        let password = String::from_utf8_lossy(&fields[2].1).to_string();
                        recorded.binds.lock().unwrap().push(name.clone());
                        let valid = (name == SERVICE_DN && password == SERVICE_SECRET)
                            || PEOPLE.iter().any(|person| dn(person.uid) == name && person.password == password);
                        vec![message(id, result(0x61, if valid { 0 } else { 49 }))]
                    }
                    0x63 => {
                        let fields = children(body);
                        let (filter_tag, filter) = fields.get(6).cloned().unwrap_or((0, Vec::new()));
                        recorded.filters.lock().unwrap().push(filter_tag);
                        let mut replies: Vec<Vec<u8>> = matching(filter_tag, &filter)
                            .into_iter()
                            .map(|person| message(id, entry(person)))
                            .collect();
                        replies.push(message(id, result(0x65, 0)));
                        replies
                    }
                    _ => return,
                };
                for packet in reply {
                    if stream.write_all(&packet).await.is_err() {
                        return;
                    }
                }
            }
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    pub async fn spawn() -> (SocketAddr, Recorded, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let recorded = Recorded::default();
        let shared = recorded.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_connection(stream, shared.clone()));
            }
        });
        (address, recorded, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(address: std::net::SocketAddr) -> serde_json::Value {
        serde_json::json!({
            "url": format!("ldap://{address}"),
            "bind_dn": test_server::SERVICE_DN,
            "user_base_dn": test_server::BASE_DN,
        })
    }

    #[test]
    fn validates_settings_and_escapes_filter_values() {
        let valid = serde_json::json!({ "url": "ldaps://ldap.example.com", "user_base_dn": "dc=example,dc=com" });
        assert!(validated_config(valid.clone()).is_ok());
        let with = |key: &str, value: &str| {
            let mut config = valid.clone();
            config[key] = serde_json::json!(value);
            validated_config(config)
        };
        assert_eq!(with("url", "http://ldap"), Err("ldap_url_invalid"));
        assert_eq!(with("user_base_dn", " "), Err("ldap_base_required"));
        assert_eq!(with("user_filter", "(uid=fixed)"), Err("ldap_filter_invalid"));
        assert_eq!(with("user_filter", "(&(uid={username})"), Err("ldap_filter_invalid"));
        assert!(with("user_filter", "(&(objectClass=person)(mail={username}))").is_ok());
        assert_eq!(escape_filter_value("a*(b)\\c\0"), "a\\2a\\28b\\29\\5cc\\00");
        assert_eq!(escape_filter_value("José"), "José");
    }

    #[tokio::test]
    async fn authenticates_against_a_directory_and_resists_filter_injection() {
        let (address, recorded, task) = test_server::spawn().await;
        let config = config(address);
        let secret = Some(test_server::SERVICE_SECRET);
        let identity = authenticate(&config, secret, "ana", "ana-ldap").await.unwrap();
        assert_eq!(
            identity,
            LdapIdentity {
                subject: "uuid-ana".into(), username: "ana".into(), display_name: Some("Ana López".into())
            }
        );
        assert_eq!(authenticate(&config, secret, "ana", "wrong").await, Err(LdapFailure::InvalidCredentials));
        assert_eq!(authenticate(&config, secret, "nobody", "x").await, Err(LdapFailure::InvalidCredentials));
        assert_eq!(authenticate(&config, secret, "*", "ana-ldap").await, Err(LdapFailure::InvalidCredentials));
        assert_eq!(authenticate(&config, secret, "an*", "ana-ldap").await, Err(LdapFailure::InvalidCredentials));
        assert_eq!(authenticate(&config, secret, "ana", "").await, Err(LdapFailure::InvalidCredentials));
        assert!(
            recorded.filters.lock().unwrap().iter().all(|tag| *tag == 0xa3),
            "{:?}",
            recorded.filters.lock().unwrap()
        );
        assert!(matches!(
            authenticate(&config, Some("bad"), "ana", "ana-ldap").await,
            Err(LdapFailure::Unavailable(_))
        ));
        assert!(test_connection(&config, secret).await.is_ok());
        task.abort();

        let unreachable = serde_json::json!({ "url": "ldap://127.0.0.1:9", "user_base_dn": test_server::BASE_DN });
        assert!(matches!(authenticate(&unreachable, None, "ana", "ana-ldap").await, Err(LdapFailure::Unavailable(_))));
    }
}
