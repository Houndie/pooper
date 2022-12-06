use chrono::{DateTime, Local, TimeZone};
use lazy_static::lazy_static;
use reqwest::{self, StatusCode, Url};
use serde::de::{Error as DeError, Unexpected};
use serde::{Deserialize, Deserializer};
use serde_json::Number;
use std::vec::Vec;
use thiserror::Error;

lazy_static! {
    static ref EVENTS_URL: Url = {
        let mut base_url = Url::parse("https://www.tadpoles.com/remote/v1/events").unwrap();

        base_url
            .query_pairs_mut()
            .append_pair("direction", "range")
            .append_pair("num_events", "300")
            .append_pair("client", "dashboard");

        base_url
    };
}

pub enum Event {
    DailyReport(DailyReport),
    Other,
}

pub struct DailyReport {
    pub entries: Vec<Entry>,
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct JsonDailyReport {
            #[serde(rename = "type")]
            typ: String,
            entries: Option<Vec<Entry>>,
        }

        let json_daily_report = JsonDailyReport::deserialize(deserializer)?;

        match json_daily_report.typ.as_str() {
            "DailyReport" => {
                let entries = json_daily_report
                    .entries
                    .ok_or(D::Error::missing_field("entries"))?;

                Ok(Event::DailyReport(DailyReport { entries: entries }))
            }

            _ => Ok(Event::Other),
        }
    }
}

pub enum Entry {
    Bathroom(BathroomEntry),
    Other,
}

pub struct BathroomEntry {
    pub classification: String,
    pub start_time: DateTime<Local>,
}

#[derive(Deserialize)]
pub struct EventsResponse {
    pub events: Vec<Event>,
}

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct JsonEntry {
            #[serde(rename = "type")]
            typ: String,
            classification: Option<String>,
            start_time: Option<Number>,
        }

        let json_entry = JsonEntry::deserialize(deserializer)?;

        match json_entry.typ.as_str() {
            "bathroom" => {
                let class = json_entry
                    .classification
                    .ok_or(D::Error::missing_field("classification"))?;
                let start_time_number = json_entry
                    .start_time
                    .ok_or(D::Error::missing_field("start_time"))?;

                let start_time_int = match start_time_number.as_i64() {
                    Some(t) => t,
                    None => match start_time_number.as_u64() {
                        Some(t) => t as i64,
                        None => match start_time_number.as_f64() {
                            Some(t) => t as i64,
                            None => {
                                return Err(D::Error::invalid_value(
                                    Unexpected::Other(start_time_number.to_string().as_str()),
                                    &"value cannot be converted to an int",
                                ))
                            }
                        },
                    },
                };

                Ok(Entry::Bathroom(BathroomEntry {
                    classification: class,
                    start_time: Local.timestamp(start_time_int, 0),
                }))
            }
            _ => Ok(Entry::Other),
        }
    }
}

pub struct Client {
    client: reqwest::Client,
    user_name: String,
    password: String,
}

#[derive(Debug)]
pub enum Endpoint {
    Login,
    Enter,
    Events,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error creating reqwest client: {0:?}")]
    ClientCreateError(reqwest::Error),

    #[error("error making network request to {endpoint:?}: {err:?}")]
    NetworkError {
        endpoint: Endpoint,
        err: reqwest::Error,
    },

    #[error("unexpected response from {endpoint:?}: {err:?}")]
    ResponseError {
        endpoint: Endpoint,
        err: reqwest::Error,
    },

    #[error("error parsing json response from {endpoint:?}: {err:?}")]
    JsonParseError {
        endpoint: Endpoint,
        err: reqwest::Error,
    },
}

impl Client {
    pub fn new(user_name: String, password: String) -> Result<Self, Error> {
        Ok(Client {
            user_name: user_name,
            password: password,
            client: reqwest::Client::builder()
                .cookie_store(true)
                .build()
                .map_err(|e| Error::ClientCreateError(e))?,
        })
    }

    async fn login(&self) -> Result<(), Error> {
        let form = [
            ("service", "tadpoles"),
            ("email", self.user_name.as_str()),
            ("password", self.password.as_str()),
        ];

        let login_resp = self
            .client
            .post("https://www.tadpoles.com/auth/login")
            .form(&form)
            .send()
            .await
            .map_err(|err| Error::NetworkError {
                endpoint: Endpoint::Login,
                err: err,
            })?;

        login_resp
            .error_for_status_ref()
            .map_err(|err| Error::ResponseError {
                endpoint: Endpoint::Login,
                err: err,
            })?;

        let enter_resp = self
            .client
            .get("https://www.tadpoles.com/athome/enter")
            .send()
            .await
            .map_err(|err| Error::NetworkError {
                endpoint: Endpoint::Enter,
                err: err,
            })?;

        enter_resp
            .error_for_status_ref()
            .map_err(|err| Error::ResponseError {
                endpoint: Endpoint::Enter,
                err: err,
            })?;

        Ok(())
    }

    pub async fn events<Tz: TimeZone>(
        &self,
        start_time: &DateTime<Tz>,
        end_time: &DateTime<Tz>,
    ) -> Result<EventsResponse, Error> {
        let mut events_url = EVENTS_URL.clone();

        events_url
            .query_pairs_mut()
            .append_pair(
                "earliest_event_time",
                start_time.timestamp().to_string().as_str(),
            )
            .append_pair(
                "latest_event_time",
                end_time.timestamp().to_string().as_str(),
            );

        let response = {
            // Copy the URL here in case we need it still for the second call.
            let url_copy = events_url.clone();

            let first_response =
                self.client
                    .get(url_copy)
                    .send()
                    .await
                    .map_err(|err| Error::NetworkError {
                        endpoint: Endpoint::Events,
                        err: err,
                    })?;

            let status = first_response.status();

            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                self.login().await?;
                self.client
                    .get(events_url)
                    .send()
                    .await
                    .map_err(|err| Error::NetworkError {
                        endpoint: Endpoint::Events,
                        err: err,
                    })?
            } else {
                first_response
            }
        };

        response
            .error_for_status_ref()
            .map_err(|err| Error::ResponseError {
                endpoint: Endpoint::Events,
                err: err,
            })?;

        response
            .json::<EventsResponse>()
            .await
            .map_err(|err| Error::JsonParseError {
                endpoint: Endpoint::Events,
                err: err,
            })
    }
}
