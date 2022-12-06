use crate::tadpoles::{
    BathroomEntry, Client as TadpolesClient, DailyReport, Entry, Error as TadpolesError, Event,
};
use chrono::{DateTime, Duration, Local, Utc};
use std::vec::Vec;

#[cfg_attr(test, faux::create)]
pub struct AlexaHandler {
    client: TadpolesClient,
}

#[cfg_attr(test, faux::methods)]
impl AlexaHandler {
    pub fn new(client: TadpolesClient) -> Self {
        Self {
            client: client,
        }
    }

    pub async fn latest(&self) -> Result<Option<DateTime<Local>>, TadpolesError> {
        let start_time = (Utc::today() - Duration::days(7)).and_hms(0, 0, 0);
        let end_time = (Utc::today()).and_hms(0, 0, 0);

        let response = self.client.events(&start_time, &end_time).await?;

        Ok(find_best_time(response.events))
    }
}

fn to_bathroom(entry: Entry) -> Option<BathroomEntry> {
    match entry {
        Entry::Bathroom(e) => Some(e),
        _ => None,
    }
}

fn has_poop(entry: &BathroomEntry) -> bool {
    return entry.classification.to_lowercase().contains("bm");
}

fn to_daily_report(event: Event) -> Option<DailyReport> {
    match event {
        Event::DailyReport(e) => Some(e),
        _ => None,
    }
}

fn find_best_time(events: Vec<Event>) -> Option<DateTime<Local>> {
    events
        .into_iter()
        .filter_map(|x| to_daily_report(x))
        .map(|x| x.entries)
        .flatten()
        .filter_map(|x| to_bathroom(x))
        .filter(|x| has_poop(x))
        .map(|x| x.start_time)
        .reduce(|accum, item| if item < accum { item } else { accum })
}
