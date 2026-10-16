use serde::Serialize;
use serde_json::Value;

/// Protokol spojení mezi CDWS a Connect:Direct uzlem (pole `protocol` při sign-on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcpip,
    None,
    Tls12,
    Tls13,
    /// Libovolná jiná hodnota, kterou vaše verze CDWS podporuje.
    Custom(String),
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Tcpip => "TCPIP",
            Protocol::None => "NONE",
            Protocol::Tls12 => "TLS1.2",
            Protocol::Tls13 => "TLS1.3",
            Protocol::Custom(s) => s,
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_uppercase().as_str() {
            "TCPIP" => Protocol::Tcpip,
            "NONE" => Protocol::None,
            "TLS1.2" => Protocol::Tls12,
            "TLS1.3" => Protocol::Tls13,
            _ => Protocol::Custom(s.to_string()),
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignonBody<'a> {
    pub ip_address: &'a str,
    pub port: u16,
    pub protocol: &'a str,
}

/// Tělo pro `POST /processcontrolcriterias` (Submit Process).
///
/// `process_file` je buď cesta k `.cdp` souboru **na serveru C:D uzlu**, nebo
/// přímo text procesu (CDWS akceptuje obojí). Ostatní pole jsou volitelná;
/// API je v příkladech posílá jako prázdné řetězce, takže je posíláme také.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SubmitProcess {
    #[serde(rename = "processFile")]
    pub process_file: String,
    #[serde(rename = "maxDelay")]
    pub max_delay: String,
    pub fasp: String,
    #[serde(rename = "faspBandwidth")]
    pub fasp_bandwidth: String,
    #[serde(rename = "faspFileSizeThreshold")]
    pub fasp_file_size_threshold: String,
    #[serde(rename = "faspPolicy")]
    pub fasp_policy: String,
    #[serde(rename = "newName")]
    pub new_name: String,
    #[serde(rename = "secondaryNode")]
    pub secondary_node: String,
    #[serde(rename = "className")]
    pub class_name: String,
    pub hold: String,
    pub notify: String,
    #[serde(rename = "newPNodeAccountInfo")]
    pub new_pnode_account_info: String,
    #[serde(rename = "newSNodeAccountInfo")]
    pub new_snode_account_info: String,
    pub pnodeid: String,
    pub snodeid: String,
    #[serde(rename = "newPriority")]
    pub new_priority: String,
    pub retain: String,
    #[serde(rename = "startTime")]
    pub start_time: String,
}

impl SubmitProcess {
    /// Proces zadaný textem nebo cestou k `.cdp` souboru na serveru.
    pub fn new(process_file: impl Into<String>) -> Self {
        Self {
            process_file: process_file.into(),
            ..Default::default()
        }
    }

    /// Přepíše SNODE z procesu.
    pub fn secondary_node(mut self, snode: impl Into<String>) -> Self {
        self.secondary_node = snode.into();
        self
    }

    /// `yes` / `no` / `call`.
    pub fn hold(mut self, hold: impl Into<String>) -> Self {
        self.hold = hold.into();
        self
    }

    /// MAXDELAY – např. `unlimited`, `queued`, `0` nebo `hh:mm:ss`.
    /// S `unlimited` čeká submit synchronně na dokončení procesu.
    pub fn max_delay(mut self, v: impl Into<String>) -> Self {
        self.max_delay = v.into();
        self
    }

    pub fn new_name(mut self, v: impl Into<String>) -> Self {
        self.new_name = v.into();
        self
    }
}

/// Filtr pro `DELETE /processcontrolcriterias`.
/// Aspoň jedno z `process_name`, `process_number`, `submitter`, `secondary_node` musí být vyplněno.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteProcess {
    pub process_name: String,
    pub process_number: String,
    pub secondary_node: String,
    pub submitter: String,
    pub hold: String,
    /// `yes` smaže i běžící proces.
    pub force: String,
}

impl DeleteProcess {
    pub fn by_number(n: u64) -> Self {
        Self {
            process_number: n.to_string(),
            ..Default::default()
        }
    }

    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            process_name: name.into(),
            ..Default::default()
        }
    }

    pub fn force(mut self) -> Self {
        self.force = "yes".into();
        self
    }

    pub(crate) fn is_empty_filter(&self) -> bool {
        self.process_name.is_empty()
            && self.process_number.is_empty()
            && self.secondary_node.is_empty()
            && self.submitter.is_empty()
    }
}

/// Query parametry pro GET dotazy (select statistics, select process).
///
/// `processNumber` a `processName` jsou zdokumentované; další parametry
/// (časové rozsahy apod.) přidejte přes [`Query::param`] podle `/cdws-doc`
/// vaší instalace.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub(crate) params: Vec<(String, String)>,
}

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_number(n: u64) -> Self {
        Self::new().param("processNumber", n.to_string())
    }

    pub fn process_name(name: impl Into<String>) -> Self {
        Self::new().param("processName", name)
    }

    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((key.into(), value.into()));
        self
    }
}

/// Najde v libovolně zanořené JSON odpovědi číslo procesu
/// (klíče `processNumber`, `pnumber`, `pnum` – case-insensitive).
pub fn extract_process_number(v: &Value) -> Option<u64> {
    const KEYS: [&str; 3] = ["processnumber", "pnumber", "pnum"];
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if KEYS.contains(&k.to_ascii_lowercase().as_str()) {
                    let n = match val {
                        Value::Number(n) => n.as_u64(),
                        Value::String(s) => s.trim().parse().ok(),
                        _ => None,
                    };
                    if n.is_some() {
                        return n;
                    }
                }
            }
            map.values().find_map(extract_process_number)
        }
        Value::Array(items) => items.iter().find_map(extract_process_number),
        _ => None,
    }
}

/// Najde ve statistikách záznam s daným record ID (např. `PRED` = konec procesu).
///
/// Heuristika: objekt, který má klíč obsahující "rec" (recordId, recId, ...)
/// s hodnotou rovnou `record_id`. Ověřte názvy polí proti své verzi CDWS.
pub fn find_stat_record<'a>(v: &'a Value, record_id: &str) -> Option<&'a Value> {
    match v {
        Value::Object(map) => {
            let hit = map.iter().any(|(k, val)| {
                k.to_ascii_lowercase().contains("rec")
                    && val
                        .as_str()
                        .is_some_and(|s| s.trim().eq_ignore_ascii_case(record_id))
            });
            if hit {
                Some(v)
            } else {
                map.values().find_map(|x| find_stat_record(x, record_id))
            }
        }
        Value::Array(items) => items.iter().find_map(|x| find_stat_record(x, record_id)),
        _ => None,
    }
}

/// Vytáhne completion code ze statistického záznamu (`ccode`, `completionCode`, `ccod`).
pub fn completion_code(record: &Value) -> Option<String> {
    const KEYS: [&str; 3] = ["ccode", "completioncode", "ccod"];
    record.as_object()?.iter().find_map(|(k, v)| {
        if KEYS.contains(&k.to_ascii_lowercase().as_str()) {
            match v {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn submit_body_has_exact_field_names() {
        let v = serde_json::to_value(SubmitProcess::new("x")).unwrap();
        for k in [
            "processFile",
            "newPNodeAccountInfo",
            "newSNodeAccountInfo",
            "pnodeid",
            "startTime",
        ] {
            assert!(v.get(k).is_some(), "missing {k}");
        }
    }

    #[test]
    fn finds_process_number_nested() {
        let v = json!([{ "messageCode": 200, "data": { "processNumber": "126" } }]);
        assert_eq!(extract_process_number(&v), Some(126));
    }

    #[test]
    fn finds_pred_record_and_ccode() {
        let v = json!({ "records": [
            { "recordId": "PSTR", "ccode": "0" },
            { "recordId": "PRED", "ccode": "8" }
        ]});
        let rec = find_stat_record(&v, "PRED").unwrap();
        assert_eq!(completion_code(rec).as_deref(), Some("8"));
    }
}
