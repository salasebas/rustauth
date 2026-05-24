//! SCIM filter parsing.

use http::StatusCode;
use serde_json::Value;

use crate::errors::ScimError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimFilterOperator {
    Eq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimDbFilter {
    pub field: String,
    pub value: String,
    pub operator: ScimFilterOperator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScimFilterExpression {
    Compare {
        path: ScimAttributePath,
        operator: ScimCompareOperator,
        value: Value,
    },
    Present(ScimAttributePath),
    And(Box<ScimFilterExpression>, Box<ScimFilterExpression>),
    Or(Box<ScimFilterExpression>, Box<ScimFilterExpression>),
    Not(Box<ScimFilterExpression>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimCompareOperator {
    Eq,
    Ne,
    Co,
    Sw,
    Ew,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScimAttributePath {
    pub attribute: String,
    pub value_filter: Option<Box<ScimFilterExpression>>,
    pub sub_attribute: Option<String>,
}

impl ScimAttributePath {
    pub fn value_path(
        attribute: impl Into<String>,
        value_filter: ScimFilterExpression,
        sub_attribute: Option<&str>,
    ) -> Self {
        Self {
            attribute: attribute.into(),
            value_filter: Some(Box::new(value_filter)),
            sub_attribute: sub_attribute.map(str::to_owned),
        }
    }
}

impl From<&str> for ScimAttributePath {
    fn from(value: &str) -> Self {
        Self {
            attribute: value.to_owned(),
            value_filter: None,
            sub_attribute: None,
        }
    }
}

pub fn parse_filter(filter: &str) -> Result<ScimFilterExpression, ScimError> {
    let tokens = tokenize(filter)?;
    let mut parser = FilterParser { tokens, cursor: 0 };
    let expression = parser.parse_or()?;
    if parser.peek().is_some() {
        return Err(invalid_filter("Invalid filter expression"));
    }
    Ok(expression)
}

pub fn parse_user_filter(filter: &str) -> Result<Vec<ScimDbFilter>, ScimError> {
    let expression = parse_filter(filter)?;
    let ScimFilterExpression::Compare {
        path,
        operator,
        value,
    } = expression
    else {
        return Err(invalid_filter("Invalid filter expression"));
    };
    if path.attribute != "userName" || path.value_filter.is_some() || path.sub_attribute.is_some() {
        return Err(invalid_filter(format!(
            r#"The attribute "{}" is not supported"#,
            path.attribute
        )));
    }
    if operator != ScimCompareOperator::Eq {
        return Err(invalid_filter(format!(
            r#"The operator "{}" is not supported"#,
            operator.as_str()
        )));
    }
    let Some(value) = value.as_str().map(str::to_ascii_lowercase) else {
        return Err(invalid_filter("Invalid filter expression"));
    };
    if value.is_empty() {
        return Err(invalid_filter("Invalid filter expression"));
    }

    Ok(vec![ScimDbFilter {
        field: "email".to_owned(),
        value,
        operator: ScimFilterOperator::Eq,
    }])
}

pub fn resource_matches_filter(resource: &Value, filter: &str) -> Result<bool, ScimError> {
    let expression = parse_filter(filter)?;
    evaluate_filter(resource, &expression)
}

fn evaluate_filter(resource: &Value, expression: &ScimFilterExpression) -> Result<bool, ScimError> {
    match expression {
        ScimFilterExpression::Compare {
            path,
            operator,
            value,
        } => Ok(extract_path_values(resource, path)?
            .iter()
            .any(|candidate| compare_value(candidate, *operator, value, path))),
        ScimFilterExpression::Present(path) => Ok(!extract_path_values(resource, path)?.is_empty()),
        ScimFilterExpression::And(left, right) => {
            Ok(evaluate_filter(resource, left)? && evaluate_filter(resource, right)?)
        }
        ScimFilterExpression::Or(left, right) => {
            Ok(evaluate_filter(resource, left)? || evaluate_filter(resource, right)?)
        }
        ScimFilterExpression::Not(expression) => Ok(!evaluate_filter(resource, expression)?),
    }
}

fn extract_path_values<'a>(
    resource: &'a Value,
    path: &ScimAttributePath,
) -> Result<Vec<&'a Value>, ScimError> {
    let (root_attribute, derived_sub_attribute) =
        resolve_extension_attribute(resource, &path.attribute);
    let Some(root) = resource.get(root_attribute) else {
        return Ok(Vec::new());
    };

    let values = if let Some(value_filter) = path.value_filter.as_deref() {
        let Some(items) = root.as_array() else {
            return Ok(Vec::new());
        };
        items
            .iter()
            .filter_map(|item| match evaluate_filter(item, value_filter) {
                Ok(true) => Some(Ok(item)),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>, _>>()?
    } else if let Some(items) = root.as_array() {
        items.iter().collect()
    } else {
        vec![root]
    };

    let sub_attribute = path
        .sub_attribute
        .as_deref()
        .or(derived_sub_attribute.as_deref());
    if let Some(sub_attribute) = sub_attribute {
        Ok(values
            .into_iter()
            .filter_map(|value| value.get(sub_attribute))
            .collect())
    } else {
        Ok(values)
    }
}

fn resolve_extension_attribute<'a>(
    resource: &Value,
    attribute: &'a str,
) -> (&'a str, Option<String>) {
    if resource.get(attribute).is_some() {
        return (attribute, None);
    }
    let Some((schema, sub_attribute)) = attribute.rsplit_once(':') else {
        return (attribute, None);
    };
    if schema.starts_with("urn:ietf:params:scim:schemas:") && resource.get(schema).is_some() {
        (schema, Some(sub_attribute.to_owned()))
    } else {
        (attribute, None)
    }
}

fn compare_value(
    candidate: &Value,
    operator: ScimCompareOperator,
    expected: &Value,
    path: &ScimAttributePath,
) -> bool {
    match (candidate, expected) {
        (Value::String(left), Value::String(right)) => {
            compare_strings(left, operator, right, is_case_exact_path(path))
        }
        (Value::Bool(left), Value::Bool(right)) => {
            matches!(operator, ScimCompareOperator::Eq) && left == right
                || matches!(operator, ScimCompareOperator::Ne) && left != right
        }
        (Value::Number(left), Value::Number(right)) => left
            .as_f64()
            .zip(right.as_f64())
            .is_some_and(|(left, right)| compare_f64(left, operator, right)),
        (Value::Null, Value::Null) => matches!(operator, ScimCompareOperator::Eq),
        _ => false,
    }
}

fn compare_strings(
    left: &str,
    operator: ScimCompareOperator,
    right: &str,
    case_exact: bool,
) -> bool {
    if !case_exact {
        let left = left.to_ascii_lowercase();
        let right = right.to_ascii_lowercase();
        return compare_strings(&left, operator, &right, true);
    }
    match operator {
        ScimCompareOperator::Eq => left == right,
        ScimCompareOperator::Ne => left != right,
        ScimCompareOperator::Co => left.contains(right),
        ScimCompareOperator::Sw => left.starts_with(right),
        ScimCompareOperator::Ew => left.ends_with(right),
        ScimCompareOperator::Gt => left > right,
        ScimCompareOperator::Ge => left >= right,
        ScimCompareOperator::Lt => left < right,
        ScimCompareOperator::Le => left <= right,
    }
}

fn is_case_exact_path(path: &ScimAttributePath) -> bool {
    match (path.attribute.as_str(), path.sub_attribute.as_deref()) {
        ("id", None) | ("externalId", None) | ("meta", _) => true,
        ("displayName", None) => true,
        ("groups", Some("value")) => true,
        (attribute, Some("value")) if attribute.ends_with(":manager") => true,
        _ => false,
    }
}

fn compare_f64(left: f64, operator: ScimCompareOperator, right: f64) -> bool {
    match operator {
        ScimCompareOperator::Eq => left == right,
        ScimCompareOperator::Ne => left != right,
        ScimCompareOperator::Gt => left > right,
        ScimCompareOperator::Ge => left >= right,
        ScimCompareOperator::Lt => left < right,
        ScimCompareOperator::Le => left <= right,
        ScimCompareOperator::Co | ScimCompareOperator::Sw | ScimCompareOperator::Ew => false,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    String(String),
    Boolean(bool),
    Number(String),
    Null,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Dot,
}

struct FilterParser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl FilterParser {
    fn parse_or(&mut self) -> Result<ScimFilterExpression, ScimError> {
        let mut expression = self.parse_and()?;
        while self.consume_word("or") {
            expression =
                ScimFilterExpression::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<ScimFilterExpression, ScimError> {
        let mut expression = self.parse_not()?;
        while self.consume_word("and") {
            expression =
                ScimFilterExpression::And(Box::new(expression), Box::new(self.parse_not()?));
        }
        Ok(expression)
    }

    fn parse_not(&mut self) -> Result<ScimFilterExpression, ScimError> {
        if self.consume_word("not") {
            return Ok(ScimFilterExpression::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<ScimFilterExpression, ScimError> {
        if self.consume_symbol(&Token::LeftParen) {
            let expression = self.parse_or()?;
            self.expect_symbol(&Token::RightParen)?;
            return Ok(expression);
        }
        let path = self.parse_path()?;
        if self.consume_word("pr") {
            return Ok(ScimFilterExpression::Present(path));
        }
        let Some(operator) = self.consume_compare_operator() else {
            return Err(invalid_filter("Invalid filter expression"));
        };
        let value = self.parse_value()?;
        Ok(ScimFilterExpression::Compare {
            path,
            operator,
            value,
        })
    }

    fn parse_path(&mut self) -> Result<ScimAttributePath, ScimError> {
        let Some(Token::Word(mut attribute)) = self.next().cloned() else {
            return Err(invalid_filter("Invalid filter expression"));
        };
        let mut sub_attribute =
            split_embedded_sub_attribute(&attribute).map(|(root_attribute, sub_attribute)| {
                attribute = root_attribute;
                sub_attribute
            });
        let value_filter = if self.consume_symbol(&Token::LeftBracket) {
            let filter = self.parse_or()?;
            self.expect_symbol(&Token::RightBracket)?;
            Some(Box::new(filter))
        } else {
            None
        };
        if self.consume_symbol(&Token::Dot) {
            let Some(Token::Word(parsed_sub_attribute)) = self.next().cloned() else {
                return Err(invalid_filter("Invalid filter expression"));
            };
            sub_attribute = Some(parsed_sub_attribute);
        }
        Ok(ScimAttributePath {
            attribute,
            value_filter,
            sub_attribute,
        })
    }

    fn parse_value(&mut self) -> Result<Value, ScimError> {
        match self.next().cloned() {
            Some(Token::String(value)) => Ok(Value::String(value)),
            Some(Token::Boolean(value)) => Ok(Value::Bool(value)),
            Some(Token::Null) => Ok(Value::Null),
            Some(Token::Number(value)) => value
                .parse::<serde_json::Number>()
                .map(Value::Number)
                .map_err(|_| invalid_filter("Invalid filter expression")),
            Some(Token::Word(value)) => Ok(Value::String(value)),
            _ => Err(invalid_filter("Invalid filter expression")),
        }
    }

    fn consume_compare_operator(&mut self) -> Option<ScimCompareOperator> {
        let Some(Token::Word(value)) = self.peek() else {
            return None;
        };
        let operator = match value.to_ascii_lowercase().as_str() {
            "eq" => ScimCompareOperator::Eq,
            "ne" => ScimCompareOperator::Ne,
            "co" => ScimCompareOperator::Co,
            "sw" => ScimCompareOperator::Sw,
            "ew" => ScimCompareOperator::Ew,
            "gt" => ScimCompareOperator::Gt,
            "ge" => ScimCompareOperator::Ge,
            "lt" => ScimCompareOperator::Lt,
            "le" => ScimCompareOperator::Le,
            _ => return None,
        };
        self.cursor += 1;
        Some(operator)
    }

    fn consume_word(&mut self, expected: &str) -> bool {
        match self.peek() {
            Some(Token::Word(value)) if value.eq_ignore_ascii_case(expected) => {
                self.cursor += 1;
                true
            }
            _ => false,
        }
    }

    fn consume_symbol(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.cursor += 1;
            return true;
        }
        false
    }

    fn expect_symbol(&mut self, expected: &Token) -> Result<(), ScimError> {
        if self.consume_symbol(expected) {
            Ok(())
        } else {
            Err(invalid_filter("Invalid filter expression"))
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.cursor);
        if token.is_some() {
            self.cursor += 1;
        }
        token
    }
}

impl ScimCompareOperator {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Co => "co",
            Self::Sw => "sw",
            Self::Ew => "ew",
            Self::Gt => "gt",
            Self::Ge => "ge",
            Self::Lt => "lt",
            Self::Le => "le",
        }
    }
}

fn tokenize(input: &str) -> Result<Vec<Token>, ScimError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            ch if ch.is_whitespace() => {}
            '(' => tokens.push(Token::LeftParen),
            ')' => tokens.push(Token::RightParen),
            '[' => tokens.push(Token::LeftBracket),
            ']' => tokens.push(Token::RightBracket),
            '.' => tokens.push(Token::Dot),
            '"' => tokens.push(Token::String(read_string(input, &mut chars)?)),
            '-' | '0'..='9' => tokens.push(Token::Number(read_number(input, index, &mut chars))),
            _ => {
                if is_word_char(ch) {
                    let word = read_word(input, index, &mut chars);
                    tokens.push(match word.to_ascii_lowercase().as_str() {
                        "true" => Token::Boolean(true),
                        "false" => Token::Boolean(false),
                        "null" => Token::Null,
                        _ => Token::Word(word),
                    });
                } else {
                    return Err(invalid_filter("Invalid filter expression"));
                }
            }
        }
    }
    if tokens.is_empty() {
        return Err(invalid_filter("Invalid filter expression"));
    }
    Ok(tokens)
}

fn read_string(
    input: &str,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> Result<String, ScimError> {
    let mut value = String::new();
    while let Some((_, ch)) = chars.next() {
        match ch {
            '"' => return Ok(value),
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    return Err(invalid_filter("Invalid filter expression"));
                };
                value.push(match escaped {
                    '"' | '\\' | '/' => escaped,
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => escaped,
                });
            }
            _ => value.push(ch),
        }
    }
    let _ = input;
    Err(invalid_filter("Invalid filter expression"))
}

fn read_number(
    input: &str,
    start: usize,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> String {
    while let Some((_, ch)) = chars.peek() {
        if ch.is_ascii_digit() || matches!(ch, '.' | 'e' | 'E' | '+' | '-') {
            chars.next();
        } else {
            break;
        }
    }
    let end = chars.peek().map(|(index, _)| *index).unwrap_or(input.len());
    input[start..end].to_owned()
}

fn read_word(
    input: &str,
    start: usize,
    chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> String {
    while let Some((_, ch)) = chars.peek() {
        if is_word_char(*ch) {
            chars.next();
        } else {
            break;
        }
    }
    let end = chars.peek().map(|(index, _)| *index).unwrap_or(input.len());
    input[start..end].to_owned()
}

fn is_word_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '$' | '.')
}

fn split_embedded_sub_attribute(path: &str) -> Option<(String, String)> {
    let split_at = path
        .char_indices()
        .filter(|(index, ch)| {
            if *ch != '.' {
                return false;
            }
            let previous = path[..*index].chars().next_back();
            let next = path[index + ch.len_utf8()..].chars().next();
            !matches!((previous, next), (Some(left), Some(right)) if left.is_ascii_digit() && right.is_ascii_digit())
        })
        .map(|(index, _)| index)
        .next()?;
    let root = path[..split_at].to_owned();
    let child = path[split_at + 1..].to_owned();
    (!root.is_empty() && !child.is_empty()).then_some((root, child))
}

fn invalid_filter(detail: impl Into<String>) -> ScimError {
    ScimError::new(StatusCode::BAD_REQUEST, detail).with_scim_type("invalidFilter")
}
