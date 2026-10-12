use anyhow::{Context, Result, bail};
use url::Url;

#[derive(Debug, Clone)]
enum HostPattern {
    Exact(String),
    Suffix(String),
}

impl HostPattern {
    fn matches(&self, host: &str) -> bool {
        match self {
            HostPattern::Exact(h) => host == h,
            HostPattern::Suffix(s) => host == s || host.ends_with(&format!(".{s}")),
        }
    }
}

#[derive(Debug, Clone)]
struct Rule {
    scheme: Option<String>,
    host: HostPattern,
    port: Option<u16>,
    path_prefix: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    rules: Vec<Rule>,
    allow_any: bool,
}

impl Whitelist {
    pub fn new(rules: &[String], allow_any: bool) -> Result<Self> {
        let mut parsed = Vec::with_capacity(rules.len());
        for r in rules {
            parsed.push(parse_rule(r).with_context(|| format!("invalid --allow rule: {r:?}"))?);
        }
        Ok(Whitelist {
            rules: parsed,
            allow_any,
        })
    }

    pub fn allows(&self, url: &Url) -> bool {
        if self.allow_any {
            return true;
        }
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return false;
        }
        let Some(host) = url.host_str().map(|h| h.to_ascii_lowercase()) else {
            return false;
        };
        self.rules.iter().any(|rule| {
            rule.scheme.as_deref().is_none_or(|s| s == scheme)
                && rule.host.matches(&host)
                && rule.port.is_none_or(|p| url.port() == Some(p))
                && rule
                    .path_prefix
                    .as_deref()
                    .is_none_or(|pfx| url.path().starts_with(pfx))
        })
    }
}

fn parse_rule(raw: &str) -> Result<Rule> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty rule");
    }
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, raw),
    };
    let (host_port, path_prefix) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_string())),
        None => (rest, None),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h, Some(p.parse().context("invalid port")?))
        }
        _ => (host_port, None),
    };
    let host = host.to_ascii_lowercase();
    let host = match host.strip_prefix("*.") {
        Some(suffix) if !suffix.is_empty() => HostPattern::Suffix(suffix.to_string()),
        _ if host == "*" => HostPattern::Suffix(String::new()),
        _ => HostPattern::Exact(host),
    };
    Ok(Rule {
        scheme,
        host,
        port,
        path_prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wl(rules: &[&str]) -> Whitelist {
        Whitelist::new(
            &rules.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            false,
        )
        .unwrap()
    }

    #[test]
    fn matching() {
        let w = wl(&["example.com", "*.foo.org", "https://bar.net:8443/x"]);
        assert!(w.allows(&Url::parse("http://example.com/a").unwrap()));
        assert!(w.allows(&Url::parse("https://example.com/a").unwrap()));
        assert!(!w.allows(&Url::parse("https://sub.example.com/a").unwrap()));
        assert!(w.allows(&Url::parse("http://a.foo.org/").unwrap()));
        assert!(w.allows(&Url::parse("http://foo.org/").unwrap()));
        assert!(!w.allows(&Url::parse("http://evilfoo.org/").unwrap()));
        assert!(w.allows(&Url::parse("https://bar.net:8443/x/y").unwrap()));
        assert!(!w.allows(&Url::parse("https://bar.net:8443/z").unwrap()));
        assert!(!w.allows(&Url::parse("https://bar.net/x").unwrap()));
        assert!(!w.allows(&Url::parse("file:///etc/passwd").unwrap()));
    }

    #[test]
    fn empty_denies_all() {
        let w = wl(&[]);
        assert!(!w.allows(&Url::parse("https://example.com/").unwrap()));
    }
}
